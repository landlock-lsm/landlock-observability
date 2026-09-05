// SPDX-License-Identifier: MIT OR Apache-2.0

//! Collection of Landlock events from the embedded BPF programs.
use libbpf_rs::{Link, MapCore, Object, ObjectBuilder, RingBufferBuilder};
use std::any::Any;
use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use crate::event::Event;
use crate::wire;

mod tracepoint;

#[cfg(not(docsrs_build))]
const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/landlock_observability.bpf.o"));

#[cfg(docsrs_build)]
const BPF_OBJECT: &[u8] = &[];
const DEFAULT_EVENT_CAPACITY: usize = 1024;
const MIN_EVENT_CAPACITY: usize = 1;
const MAX_EVENT_CAPACITY: usize = 65_536;
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The reason a collector configuration could not be built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CollectorConfigErrorKind {
    /// The configured event capacity is outside the supported range.
    InvalidEventCapacity,
}

/// A failure to build a [`CollectorConfig`].
///
/// Configuration failures are reported before any channels, BPF resources, or
/// worker threads are created.  The configured and accepted capacities remain
/// available through the accessors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CollectorConfigError {
    kind: CollectorConfigErrorKind,
    configured: usize,
}

impl CollectorConfigError {
    /// Returns the reason configuration failed.
    pub const fn kind(&self) -> CollectorConfigErrorKind {
        self.kind
    }

    /// Returns the rejected event capacity.
    pub const fn configured(&self) -> usize {
        self.configured
    }

    /// Returns the minimum accepted event capacity.
    pub const fn minimum(&self) -> usize {
        MIN_EVENT_CAPACITY
    }

    /// Returns the maximum accepted event capacity.
    pub const fn maximum(&self) -> usize {
        MAX_EVENT_CAPACITY
    }
}

impl fmt::Display for CollectorConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "collector event capacity {} is outside the supported range {}..={}",
            self.configured, MIN_EVENT_CAPACITY, MAX_EVENT_CAPACITY
        )
    }
}

impl Error for CollectorConfigError {}

/// A builder for an inert [`CollectorConfig`].
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct CollectorConfigBuilder {
    event_capacity: usize,
}

impl CollectorConfigBuilder {
    /// Configures the bounded delivery queue capacity.
    ///
    /// Accepted capacities range from 1 through 65,536 entries.
    pub const fn event_capacity(mut self, event_capacity: usize) -> Self {
        self.event_capacity = event_capacity;
        self
    }

    /// Validates this builder and returns an inert, reusable configuration.
    ///
    /// Building does not open or load BPF, allocate channels, or spawn a
    /// worker thread.
    pub fn build(self) -> Result<CollectorConfig, CollectorConfigError> {
        if !(MIN_EVENT_CAPACITY..=MAX_EVENT_CAPACITY).contains(&self.event_capacity) {
            return Err(CollectorConfigError {
                kind: CollectorConfigErrorKind::InvalidEventCapacity,
                configured: self.event_capacity,
            });
        }
        Ok(CollectorConfig {
            event_capacity: self.event_capacity,
        })
    }
}

impl Default for CollectorConfigBuilder {
    fn default() -> Self {
        Self {
            event_capacity: DEFAULT_EVENT_CAPACITY,
        }
    }
}

/// A validated, inert collector configuration.
///
/// This value owns no BPF resources, channels, or threads. It can be reused to
/// prepare multiple independent collector lifecycles. Each lifecycle loads its
/// own programs and ring buffer and receives its own copy of observed events;
/// multiple lifecycles do not distribute one event stream across a worker pool.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct CollectorConfig {
    event_capacity: usize,
}

impl CollectorConfig {
    /// Returns a builder with a delivery queue capacity of 1024.
    pub fn builder() -> CollectorConfigBuilder {
        CollectorConfigBuilder::default()
    }

    /// Returns the configured delivery queue capacity.
    pub const fn event_capacity(&self) -> usize {
        self.event_capacity
    }

    /// Synchronously prepares an attached collector and its worker.
    ///
    /// Opening, loading, attachment, and ring-buffer setup all complete on the
    /// calling thread. If setup fails, every partially prepared BPF resource is
    /// destroyed before the error is returned.
    ///
    /// The caller must then move the returned [`CollectorWorker`] to a thread,
    /// call [`CollectorWorker::run()`], retain its join handle, and drop the
    /// [`Collector`] before joining.
    #[must_use = "the collector and worker halves must both be used"]
    pub fn prepare(&self) -> Result<(Collector, CollectorWorker), CollectorPrepareError> {
        let (collector, worker) = backend::prepare(self.event_capacity)?;
        Ok((collector, CollectorWorker { backend: worker }))
    }
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            event_capacity: DEFAULT_EVENT_CAPACITY,
        }
    }
}

/// The preparation stage at which a collector failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CollectorPrepareErrorKind {
    /// The target lacks a complete supported Landlock tracing interface.
    ///
    /// This is reported only when a compatibility-shaped BPF load failure is
    /// followed by a conclusive diagnosis from canonical vmlinux BTF.
    UnsupportedKernel,
    /// The embedded BPF object could not be opened.
    Open,
    /// The BPF object could not be loaded into the kernel.
    Load,
    /// The BPF programs could not be attached.
    Attach,
    /// The userspace BPF ring-buffer consumer could not be set up.
    RingSetup,
}

impl CollectorPrepareErrorKind {
    fn description(self) -> &'static str {
        match self {
            Self::UnsupportedKernel => "load a supported Landlock tracing interface",
            Self::Open => "open embedded BPF object",
            Self::Load => "load BPF object",
            Self::Attach => "attach BPF programs",
            Self::RingSetup => "set up BPF ring buffer",
        }
    }
}

/// An opaque failure to prepare a [`Collector`].
///
/// Use [`CollectorPrepareError::kind()`] to identify the preparation stage.
/// Underlying libbpf errors remain available through [`Error::source()`].
/// [`CollectorPrepareErrorKind::UnsupportedKernel`] retains the original BPF load
/// error as its source.
#[derive(Debug)]
#[non_exhaustive]
pub struct CollectorPrepareError {
    kind: CollectorPrepareErrorKind,
    detail: ErrorDetail,
}

impl CollectorPrepareError {
    fn new(kind: CollectorPrepareErrorKind, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            kind,
            detail: ErrorDetail::Source(Box::new(source)),
        }
    }

    /// Returns the preparation stage that failed.
    pub fn kind(&self) -> CollectorPrepareErrorKind {
        self.kind
    }
}

impl fmt::Display for CollectorPrepareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to {}: {}",
            self.kind.description(),
            self.detail
        )
    }
}

impl Error for CollectorPrepareError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.detail.source()
    }
}

/// The reason an event could not be delivered by a running collector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CollectorReceiveErrorKind {
    /// A BPF ring-buffer sample did not match the private wire format.
    MalformedSample,
    /// At least one userspace delivery entry was omitted because the output
    /// queue was full.  This does not account for kernel-side event loss.
    OutputQueueFull,
    /// Polling the BPF ring buffer failed and collection terminated.
    PollFailure,
    /// The collector worker panicked and collection terminated.
    WorkerPanic,
    /// The collector worker has stopped.
    WorkerStop,
}

impl CollectorReceiveErrorKind {
    fn description(self) -> &'static str {
        match self {
            Self::MalformedSample => "decode BPF event sample",
            Self::OutputQueueFull => "deliver entries through the full output queue",
            Self::PollFailure => "poll BPF ring buffer",
            Self::WorkerPanic => "receive from collector worker",
            Self::WorkerStop => "receive from the stopped collector worker",
        }
    }
}

/// An opaque collection failure occupying a position in the delivery stream.
///
/// Use [`CollectorReceiveError::kind()`] to identify the failure.  Detailed
/// decoding and libbpf errors remain available through [`Error::source()`]
/// without making the private wire format part of the public API. A worker
/// panic has a [`CollectorWorkerPanic`] source. Source-less queue and
/// worker-state failures retain a static detail.
#[derive(Debug)]
#[non_exhaustive]
pub struct CollectorReceiveError {
    kind: CollectorReceiveErrorKind,
    detail: ErrorDetail,
}

impl CollectorReceiveError {
    fn new(kind: CollectorReceiveErrorKind, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            kind,
            detail: ErrorDetail::Source(Box::new(source)),
        }
    }

    fn with_static_detail(kind: CollectorReceiveErrorKind, detail: &'static str) -> Self {
        Self {
            kind,
            detail: ErrorDetail::Static(detail),
        }
    }

    /// Returns the reason this delivery failed.
    pub fn kind(&self) -> CollectorReceiveErrorKind {
        self.kind
    }
}

impl fmt::Display for CollectorReceiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to {}: {}",
            self.kind.description(),
            self.detail
        )
    }
}

impl Error for CollectorReceiveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.detail.source()
    }
}

/// Details captured when the collector worker panics.
///
/// A `String` or `&'static str` panic payload is available through
/// [`CollectorWorkerPanic::message()`]. Other payload types remain opaque so
/// worker implementation details do not become part of the public API.
/// This error is the source of the corresponding [`CollectorReceiveError`].
#[derive(Debug)]
#[non_exhaustive]
pub struct CollectorWorkerPanic {
    message: Option<String>,
}

impl CollectorWorkerPanic {
    /// Returns the panic payload text when it was a `String` or `&'static str`.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
    fn from_payload(payload: Box<dyn Any + Send + 'static>) -> Self {
        let payload = match payload.downcast::<String>() {
            Ok(message) => {
                return Self {
                    message: Some(*message),
                };
            }
            Err(payload) => payload,
        };
        match payload.downcast::<&'static str>() {
            Ok(message) => Self {
                message: Some((*message).to_owned()),
            },
            Err(payload) => {
                suppress_panic_payload(payload);
                Self { message: None }
            }
        }
    }
}

impl fmt::Display for CollectorWorkerPanic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message() {
            Some(message) => write!(formatter, "collector worker panicked: {message}"),
            None => formatter.write_str("collector worker panicked with an opaque payload"),
        }
    }
}

impl Error for CollectorWorkerPanic {}

/// An error returned by [`Collector::try_recv()`].
#[derive(Debug)]
#[non_exhaustive]
pub enum TryReceiveError {
    /// The collector is still running but no delivery entry is currently ready.
    Empty,
    /// The next delivery entry is a collector error.
    Collector(CollectorReceiveError),
}

impl fmt::Display for TryReceiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("collector output queue is empty"),
            Self::Collector(error) => error.fmt(formatter),
        }
    }
}

impl Error for TryReceiveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Empty => None,
            Self::Collector(error) => Some(error),
        }
    }
}

/// An error returned by [`Collector::recv_timeout()`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ReceiveTimeoutError {
    /// No delivery entry became ready before the requested timeout elapsed.
    Timeout,
    /// The next delivery entry is a collector error.
    Collector(CollectorReceiveError),
}

impl fmt::Display for ReceiveTimeoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("timed out waiting for collector output"),
            Self::Collector(error) => error.fmt(formatter),
        }
    }
}

impl Error for ReceiveTimeoutError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Timeout => None,
            Self::Collector(error) => Some(error),
        }
    }
}

#[derive(Debug)]
enum ErrorDetail {
    Source(Box<dyn Error + Send + Sync>),
    Static(&'static str),
}

impl ErrorDetail {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source(source) => Some(source.as_ref()),
            Self::Static(_) => None,
        }
    }
}

impl fmt::Display for ErrorDetail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(source) => source.fmt(formatter),
            Self::Static(detail) => formatter.write_str(detail),
        }
    }
}

fn receive_error(kind: CollectorReceiveErrorKind, message: &'static str) -> CollectorReceiveError {
    CollectorReceiveError::with_static_detail(kind, message)
}

fn worker_stop() -> CollectorReceiveError {
    receive_error(
        CollectorReceiveErrorKind::WorkerStop,
        "collector worker is no longer running",
    )
}
fn suppress_panic_payload(payload: Box<dyn Any + Send + 'static>) {
    if let Err(secondary_payload) =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload)))
    {
        // Dropping an arbitrary secondary payload could start another unwind.
        std::mem::forget(secondary_payload);
    }
}
fn worker_receive_panic(payload: Box<dyn Any + Send + 'static>) -> CollectorReceiveError {
    CollectorReceiveError::new(
        CollectorReceiveErrorKind::WorkerPanic,
        CollectorWorkerPanic::from_payload(payload),
    )
}
type PanicPayload = Box<dyn Any + Send + 'static>;
fn catch_callback_panic(
    panic: &Mutex<Option<PanicPayload>>,
    callback: impl FnOnce() -> i32,
) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(callback)) {
        Ok(result) => result,
        Err(payload) => {
            *panic.lock().expect("callback panic state is not poisoned") = Some(payload);
            -1
        }
    }
}
fn callback_panicked(panic: &Mutex<Option<PanicPayload>>) -> bool {
    panic
        .lock()
        .expect("callback panic state is not poisoned")
        .is_some()
}
fn resume_callback_panic(panic: &Mutex<Option<PanicPayload>>) {
    let payload = panic
        .lock()
        .expect("callback panic state is not poisoned")
        .take();
    if let Some(payload) = payload {
        std::panic::resume_unwind(payload);
    }
}

type Delivery = Result<Event, CollectorReceiveError>;

struct DeliveryEntry {
    delivery: Delivery,
    output_full_before: bool,
}

mod backend {
    use super::*;

    pub(super) struct Worker {
        pub(in crate::collector) deliveries: mpsc::SyncSender<DeliveryEntry>,
        pub(in crate::collector) terminal: mpsc::SyncSender<CollectorReceiveError>,
        pub(super) running: Arc<AtomicBool>,
        pub(in crate::collector) resources: Option<PreparedResources>,
    }
    impl Worker {
        pub(in crate::collector) fn run_with<F>(self, worker_main: F)
        where
            F: FnOnce(
                mpsc::SyncSender<DeliveryEntry>,
                mpsc::SyncSender<CollectorReceiveError>,
                Arc<AtomicBool>,
                Option<PreparedResources>,
            ),
        {
            let Self {
                deliveries,
                terminal,
                running,
                resources,
            } = self;
            let terminal_panic = terminal.clone();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                worker_main(deliveries, terminal, running, resources);
            }));
            if let Err(payload) = result {
                let _ = terminal_panic.try_send(worker_receive_panic(payload));
            }
        }
    }

    pub(super) fn prepare(
        event_capacity: usize,
    ) -> Result<(Collector, Worker), CollectorPrepareError> {
        let (delivery_tx, delivery_rx) = mpsc::sync_channel(event_capacity);
        // A queue-full notice, poll failure, and subsequent panic may all need
        // distinct ordered terminal slots.
        let (terminal_tx, terminal_rx) = mpsc::sync_channel(3);
        let running = Arc::new(AtomicBool::new(true));
        let resources = prepare_resources(delivery_tx.clone(), Arc::clone(&running))?;
        Ok((
            Collector {
                deliveries: delivery_rx,
                pending_delivery: None,
                terminal: terminal_rx,
                running: Arc::clone(&running),
            },
            Worker {
                deliveries: delivery_tx,
                terminal: terminal_tx,
                running,
                resources: Some(resources),
            },
        ))
    }
}

/// The blocking worker half of a collector lifecycle.
///
/// This value is `Send` but owns no thread. The caller chooses the thread
/// builder, retains its join handle, and moves this value into that thread.
/// All BPF setup is already complete before this value is returned.
#[must_use = "the worker must be run on a caller-owned thread"]
#[non_exhaustive]
pub struct CollectorWorker {
    backend: backend::Worker,
}

impl CollectorWorker {
    /// Polls the prepared ring buffer until collection stops.
    ///
    /// This consuming call blocks and cannot be run more than once. Panics are
    /// contained and reported through the matching [`Collector`].
    pub fn run(self) {
        self.backend.run_with(run_worker);
    }
}

/// An attached collector yielding semantic events in ring-buffer arrival order.
///
/// A collector has one consumer and a bounded output queue.  Its capacity
/// covers event-bearing and non-terminal-error delivery entries.  The
/// ring-buffer callback never waits for queue space: omitted entries are
/// represented by a coalesced [`CollectorReceiveErrorKind::OutputQueueFull`]
/// notification paired with and returned before the next accepted delivery.
/// The notification does not occupy a separate queue entry.  It accounts only
/// for userspace delivery-queue omissions, not failed BPF ring reservations,
/// events before program attachment, or other kernel-side loss.
///
/// The matching [`CollectorWorker`] owns the libbpf resources prepared before
/// either half is returned. An unexpected worker panic is reported once, after
/// buffered accepted deliveries and any terminal poll error, where ordinary
/// worker termination would otherwise be reported. Later receives report
/// [`CollectorReceiveErrorKind::WorkerStop`].
/// Dropping the collector only requests shutdown; the caller must join the
/// worker it spawned to wait for BPF program detachment. An idle worker checks
/// for shutdown after each poll of at most 100 ms; thread scheduling and
/// resource destruction do not have a real-time bound.
#[non_exhaustive]
pub struct Collector {
    deliveries: mpsc::Receiver<DeliveryEntry>,
    pending_delivery: Option<Delivery>,
    terminal: mpsc::Receiver<CollectorReceiveError>,
    running: Arc<AtomicBool>,
}

struct ReceiveDeadline {
    started: Instant,
    timeout: Duration,
}

impl ReceiveDeadline {
    fn new(timeout: Duration) -> Self {
        Self {
            started: Instant::now(),
            timeout,
        }
    }

    fn remaining(&self) -> Duration {
        self.timeout.saturating_sub(self.started.elapsed())
    }
}

impl Collector {
    /// Returns the next event immediately, without waiting.
    ///
    /// [`TryReceiveError::Empty`] means the running collector has no ready
    /// entry.  Delivery failures and eventual worker termination are returned
    /// as [`TryReceiveError::Collector`].
    pub fn try_recv(&mut self) -> Result<Event, TryReceiveError> {
        if let Some(delivery) = self.pending_delivery.take() {
            return delivery.map_err(TryReceiveError::Collector);
        }
        match self.deliveries.try_recv() {
            Ok(entry) => self.unpair(entry).map_err(TryReceiveError::Collector),
            Err(mpsc::TryRecvError::Empty) => self
                .terminal_now_nonblocking()
                .map_or(Err(TryReceiveError::Empty), |error| {
                    Err(TryReceiveError::Collector(error))
                }),
            Err(mpsc::TryRecvError::Disconnected) => self
                .terminal_or_stop_nonblocking()
                .map_or(Err(TryReceiveError::Empty), |error| {
                    Err(TryReceiveError::Collector(error))
                }),
        }
    }

    /// Waits up to `timeout` for the next event.
    ///
    /// One monotonic budget covers waiting for a delivery, terminal status,
    /// and worker completion. [`ReceiveTimeoutError::Timeout`] is distinct
    /// from collection failures and is returned if worker teardown remains
    /// unfinished when that budget expires. A worker panic then remains
    /// available to a later receive. Buffered delivery entries are returned
    /// before a terminal poll failure; after that failure, a worker panic is
    /// reported before the ordinary stopped state. Thread scheduling means
    /// the timeout is not a hard real-time bound.
    pub fn recv_timeout(&mut self, timeout: Duration) -> Result<Event, ReceiveTimeoutError> {
        if let Some(delivery) = self.pending_delivery.take() {
            return delivery.map_err(ReceiveTimeoutError::Collector);
        }
        let deadline = ReceiveDeadline::new(timeout);
        match self.deliveries.recv_timeout(deadline.remaining()) {
            Ok(entry) => self.unpair(entry).map_err(ReceiveTimeoutError::Collector),
            Err(mpsc::RecvTimeoutError::Timeout) => self
                .terminal_now_nonblocking()
                .map_or(Err(ReceiveTimeoutError::Timeout), |error| {
                    Err(ReceiveTimeoutError::Collector(error))
                }),
            Err(mpsc::RecvTimeoutError::Disconnected) => self
                .terminal_until(&deadline)
                .map_or(Err(ReceiveTimeoutError::Timeout), |error| {
                    Err(ReceiveTimeoutError::Collector(error))
                }),
        }
    }

    fn unpair(&mut self, entry: DeliveryEntry) -> Delivery {
        if entry.output_full_before {
            self.pending_delivery = Some(entry.delivery);
            Err(receive_error(
                CollectorReceiveErrorKind::OutputQueueFull,
                "one or more delivery entries were omitted",
            ))
        } else {
            entry.delivery
        }
    }

    fn terminal_now_nonblocking(&mut self) -> Option<CollectorReceiveError> {
        match self.terminal.try_recv() {
            Ok(error) => Some(error),
            Err(mpsc::TryRecvError::Disconnected) => self.worker_termination_nonblocking(),
            Err(mpsc::TryRecvError::Empty) => None,
        }
    }

    fn terminal_or_stop_nonblocking(&mut self) -> Option<CollectorReceiveError> {
        match self.terminal.try_recv() {
            Ok(error) => Some(error),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => self.worker_termination_nonblocking(),
        }
    }

    fn terminal_until(&mut self, deadline: &ReceiveDeadline) -> Option<CollectorReceiveError> {
        match self.terminal.recv_timeout(deadline.remaining()) {
            Ok(error) => Some(error),
            Err(mpsc::RecvTimeoutError::Timeout) => self.terminal_now_nonblocking(),
            Err(mpsc::RecvTimeoutError::Disconnected) => Some(worker_stop()),
        }
    }

    fn worker_termination_nonblocking(&mut self) -> Option<CollectorReceiveError> {
        Some(worker_stop())
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
    }
}
struct DeliveryQueue {
    sender: mpsc::SyncSender<DeliveryEntry>,
    output_full_pending: Arc<AtomicBool>,
}
impl DeliveryQueue {
    fn deliver(&mut self, running: &AtomicBool, data: &[u8]) -> i32 {
        if !running.load(Ordering::Acquire) {
            return -1;
        }

        let entry = DeliveryEntry {
            delivery: wire::decode(data).map_err(|error| {
                CollectorReceiveError::new(CollectorReceiveErrorKind::MalformedSample, error)
            }),
            output_full_before: self.output_full_pending.load(Ordering::Acquire),
        };
        match self.sender.try_send(entry) {
            Ok(()) => {
                self.output_full_pending.store(false, Ordering::Release);
                0
            }
            Err(mpsc::TrySendError::Full(_)) => {
                self.output_full_pending.store(true, Ordering::Release);
                0
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                running.store(false, Ordering::Release);
                -1
            }
        }
    }
}
struct PreparedResources {
    // Fields are dropped in declaration order: stop polling before detaching
    // links, then close the object after its programs and maps are no longer
    // used. libbpf-rs owns all three resources and marks them as transferable.
    ring: libbpf_rs::RingBuffer<'static>,
    _links: Vec<Link>,
    _object: Object,
    output_full_pending: Arc<AtomicBool>,
    callback_panic: Arc<Mutex<Option<PanicPayload>>>,
}
fn prepare_resources(
    deliveries: mpsc::SyncSender<DeliveryEntry>,
    running: Arc<AtomicBool>,
) -> Result<PreparedResources, CollectorPrepareError> {
    let mut builder = ObjectBuilder::default();
    let open = builder
        .open_memory(BPF_OBJECT)
        .map_err(|error| CollectorPrepareError::new(CollectorPrepareErrorKind::Open, error))?;
    // libbpf resolves every tp_btf target ID while loading the programs, before
    // the later link-attachment stage.
    let object = open.load().map_err(|error| {
        let kind = if tracepoint::generation_1_is_missing(&error) {
            CollectorPrepareErrorKind::UnsupportedKernel
        } else {
            CollectorPrepareErrorKind::Load
        };
        CollectorPrepareError::new(kind, error)
    })?;
    let links = object
        .progs_mut()
        .map(|program| program.attach())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| CollectorPrepareError::new(CollectorPrepareErrorKind::Attach, error))?;

    let callback_running = Arc::clone(&running);
    let output_full_pending = Arc::new(AtomicBool::new(false));
    let mut queue = DeliveryQueue {
        sender: deliveries,
        output_full_pending: Arc::clone(&output_full_pending),
    };
    let callback_panic = Arc::new(Mutex::new(None));
    let callback_panic_capture = Arc::clone(&callback_panic);
    let ring = {
        let events = object
            .maps()
            .find(|map| map.name() == OsStr::new("events"))
            .ok_or_else(|| {
                CollectorPrepareError::new(
                    CollectorPrepareErrorKind::RingSetup,
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "embedded BPF object has no events map",
                    ),
                )
            })?;
        let mut ring_builder = RingBufferBuilder::new();
        ring_builder
            .add(&events, move |data| {
                catch_callback_panic(&callback_panic_capture, || {
                    queue.deliver(&callback_running, data)
                })
            })
            .map_err(|error| {
                CollectorPrepareError::new(CollectorPrepareErrorKind::RingSetup, error)
            })?;
        ring_builder.build().map_err(|error| {
            CollectorPrepareError::new(CollectorPrepareErrorKind::RingSetup, error)
        })?
    };

    Ok(PreparedResources {
        ring,
        _links: links,
        _object: object,
        output_full_pending,
        callback_panic,
    })
}
fn run_worker(
    _deliveries: mpsc::SyncSender<DeliveryEntry>,
    terminal: mpsc::SyncSender<CollectorReceiveError>,
    running: Arc<AtomicBool>,
    resources: Option<PreparedResources>,
) {
    let resources = resources.expect("prepared collector resources are present");
    while running.load(Ordering::Acquire) {
        let result = resources.ring.poll(POLL_INTERVAL);
        // The callback is invoked through an extern-C frame, so resume a caught
        // panic only after control has returned to Rust. Preserve an already
        // pending queue-loss notice before that terminal panic.
        if callback_panicked(&resources.callback_panic)
            && resources.output_full_pending.swap(false, Ordering::AcqRel)
        {
            let _ = terminal.try_send(receive_error(
                CollectorReceiveErrorKind::OutputQueueFull,
                "one or more delivery entries were omitted",
            ));
        }
        resume_callback_panic(&resources.callback_panic);
        if let Err(error) = result {
            if running.load(Ordering::Acquire) {
                if resources.output_full_pending.load(Ordering::Acquire) {
                    let _ = terminal.try_send(receive_error(
                        CollectorReceiveErrorKind::OutputQueueFull,
                        "one or more delivery entries were omitted",
                    ));
                }
                let _ = terminal.try_send(CollectorReceiveError::new(
                    CollectorReceiveErrorKind::PollFailure,
                    error,
                ));
            }
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, FreeRulesetEvent, KernelTimestamp, RulesetId, MIN_LANDLOCK_ID};
    use std::thread::{self, JoinHandle};
    use std::time::Instant;

    #[cfg(target_endian = "little")]
    const RULESET_FREE_FIXTURE: &[u8; 344] =
        include_bytes!("../tests/fixtures/wire/11-ruleset-free-little-endian.bin");

    #[cfg(target_endian = "big")]
    const RULESET_FREE_FIXTURE: &[u8; 344] =
        include_bytes!("../tests/fixtures/wire/11-ruleset-free-big-endian.bin");

    fn event(id_offset: u64) -> Event {
        Event::FreeRuleset(
            FreeRulesetEvent::builder()
                .timestamp(KernelTimestamp::from_nanoseconds(id_offset))
                .ruleset_id(RulesetId::new(MIN_LANDLOCK_ID + id_offset).unwrap())
                .ruleset_version(id_offset as u32)
                .build(),
        )
    }

    fn sample(timestamp: u64) -> [u8; 344] {
        let mut data = *RULESET_FREE_FIXTURE;
        data[..size_of::<u64>()].copy_from_slice(&timestamp.to_ne_bytes());
        data
    }

    fn fake_collector(
        capacity: usize,
    ) -> (
        Collector,
        mpsc::SyncSender<DeliveryEntry>,
        mpsc::SyncSender<CollectorReceiveError>,
    ) {
        let (delivery_tx, delivery_rx) = mpsc::sync_channel(capacity);
        let (terminal_tx, terminal_rx) = mpsc::sync_channel(1);
        let running = Arc::new(AtomicBool::new(true));
        (
            Collector {
                deliveries: delivery_rx,
                pending_delivery: None,
                terminal: terminal_rx,
                running,
            },
            delivery_tx,
            terminal_tx,
        )
    }

    fn start_with_worker<F>(config: CollectorConfig, worker_main: F) -> (Collector, JoinHandle<()>)
    where
        F: FnOnce(
                mpsc::SyncSender<DeliveryEntry>,
                mpsc::SyncSender<CollectorReceiveError>,
                Arc<AtomicBool>,
                Option<PreparedResources>,
            ) + Send
            + 'static,
    {
        let (delivery_tx, delivery_rx) = mpsc::sync_channel(config.event_capacity());
        let (terminal_tx, terminal_rx) = mpsc::sync_channel(3);
        let running = Arc::new(AtomicBool::new(true));
        let collector = Collector {
            deliveries: delivery_rx,
            pending_delivery: None,
            terminal: terminal_rx,
            running: Arc::clone(&running),
        };
        let worker = backend::Worker {
            deliveries: delivery_tx,
            terminal: terminal_tx,
            running,
            resources: None,
        };
        let handle = thread::spawn(move || worker.run_with(worker_main));
        (collector, handle)
    }

    struct DelayedTeardown {
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    }

    impl Drop for DelayedTeardown {
        fn drop(&mut self) {
            self.entered.send(()).unwrap();
            self.release.recv().unwrap();
        }
    }

    fn delayed_teardown_collector() -> (Collector, JoinHandle<()>, mpsc::SyncSender<()>) {
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let config = CollectorConfig::default();
        let (collector, worker) = start_with_worker(config, move |deliveries, terminal, _, _| {
            let _teardown = DelayedTeardown {
                entered: entered_tx,
                release: release_rx,
            };
            drop(deliveries);
            drop(terminal);
            panic!("panic before delayed teardown");
        });
        entered_rx.recv().unwrap();
        (collector, worker, release_tx)
    }

    #[test]
    fn capacities_are_validated_without_preparation() {
        for capacity in [0, MAX_EVENT_CAPACITY + 1, usize::MAX] {
            let error = CollectorConfig::builder()
                .event_capacity(capacity)
                .build()
                .unwrap_err();
            assert_eq!(error.kind(), CollectorConfigErrorKind::InvalidEventCapacity);
            assert_eq!(error.configured(), capacity);
            assert_eq!(error.minimum(), 1);
            assert_eq!(error.maximum(), 65_536);
            assert!(error.source().is_none());
        }

        for capacity in [1, MAX_EVENT_CAPACITY] {
            let config = CollectorConfig::builder()
                .event_capacity(capacity)
                .build()
                .unwrap();
            assert_eq!(config.event_capacity(), capacity);
        }

        let config = CollectorConfig::default();
        assert_eq!(config.event_capacity(), 1024);
    }

    #[test]
    fn empty_and_timeout_are_distinct() {
        let (mut collector, _deliveries, _terminal) = fake_collector(1);
        assert!(matches!(collector.try_recv(), Err(TryReceiveError::Empty)));
        assert!(matches!(
            collector.recv_timeout(Duration::from_millis(1)),
            Err(ReceiveTimeoutError::Timeout)
        ));
    }

    #[test]
    fn capacity_n_preserves_accepted_delivery_order() {
        let (sender, receiver) = mpsc::sync_channel(3);
        let running = AtomicBool::new(true);
        let mut queue = DeliveryQueue {
            sender,
            output_full_pending: Arc::new(AtomicBool::new(false)),
        };
        for timestamp in 1..=3 {
            assert_eq!(queue.deliver(&running, &sample(timestamp)), 0);
        }
        assert_eq!(queue.deliver(&running, &sample(4)), 0);

        for timestamp in 1..=3 {
            let entry = receiver.try_recv().unwrap();
            assert!(!entry.output_full_before);
            assert_eq!(
                entry.delivery.unwrap(),
                wire::decode(&sample(timestamp)).unwrap()
            );
        }
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        assert!(queue.output_full_pending.load(Ordering::Acquire));
    }

    #[test]
    fn capacity_one_pairs_notice_with_next_accepted_delivery() {
        let (mut collector, sender, _terminal) = fake_collector(1);
        let running = AtomicBool::new(true);
        let pending = Arc::new(AtomicBool::new(false));
        let mut queue = DeliveryQueue {
            sender,
            output_full_pending: Arc::clone(&pending),
        };

        assert_eq!(queue.deliver(&running, &sample(1)), 0);
        assert_eq!(queue.deliver(&running, &sample(2)), 0);
        assert_eq!(queue.deliver(&running, &sample(3)), 0);
        assert_eq!(
            collector.try_recv().unwrap(),
            wire::decode(&sample(1)).unwrap()
        );

        assert_eq!(queue.deliver(&running, &sample(4)), 0);
        assert!(!pending.load(Ordering::Acquire));
        let TryReceiveError::Collector(notice) = collector.try_recv().unwrap_err() else {
            panic!()
        };
        assert_eq!(notice.kind(), CollectorReceiveErrorKind::OutputQueueFull);
        assert!(notice.source().is_none());
        assert_eq!(
            collector.try_recv().unwrap(),
            wire::decode(&sample(4)).unwrap()
        );
        assert!(matches!(collector.try_recv(), Err(TryReceiveError::Empty)));
    }

    #[test]
    fn malformed_sample_preserves_private_source() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let running = AtomicBool::new(true);
        let mut queue = DeliveryQueue {
            sender,
            output_full_pending: Arc::new(AtomicBool::new(false)),
        };
        assert_eq!(queue.deliver(&running, &[0]), 0);
        let error = receiver.try_recv().unwrap().delivery.unwrap_err();
        assert_eq!(error.kind(), CollectorReceiveErrorKind::MalformedSample);
        assert!(error.source().is_some());
    }

    #[test]
    fn paired_malformed_delivery_precedes_terminal_error() {
        let (mut collector, sender, terminal) = fake_collector(1);
        let running = AtomicBool::new(true);
        let mut queue = DeliveryQueue {
            sender,
            output_full_pending: Arc::new(AtomicBool::new(false)),
        };
        assert_eq!(queue.deliver(&running, &sample(1)), 0);
        assert_eq!(queue.deliver(&running, &sample(2)), 0);
        assert!(collector.try_recv().is_ok());
        assert_eq!(queue.deliver(&running, &[0]), 0);
        terminal
            .try_send(CollectorReceiveError::new(
                CollectorReceiveErrorKind::PollFailure,
                std::io::Error::other("fake poll failure"),
            ))
            .unwrap();
        drop(queue);
        drop(terminal);

        let TryReceiveError::Collector(error) = collector.try_recv().unwrap_err() else {
            panic!()
        };
        assert_eq!(error.kind(), CollectorReceiveErrorKind::OutputQueueFull);
        let TryReceiveError::Collector(error) = collector.try_recv().unwrap_err() else {
            panic!()
        };
        assert_eq!(error.kind(), CollectorReceiveErrorKind::MalformedSample);
        assert!(error.source().is_some());
        let TryReceiveError::Collector(error) = collector.try_recv().unwrap_err() else {
            panic!()
        };
        assert_eq!(error.kind(), CollectorReceiveErrorKind::PollFailure);
    }

    #[test]
    fn buffered_item_precedes_terminal_poll_error_and_stop() {
        let (mut collector, deliveries, terminal) = fake_collector(1);
        deliveries
            .try_send(DeliveryEntry {
                delivery: Ok(event(1)),
                output_full_before: false,
            })
            .unwrap();
        terminal
            .try_send(CollectorReceiveError::new(
                CollectorReceiveErrorKind::PollFailure,
                std::io::Error::other("fake poll failure"),
            ))
            .unwrap();
        drop(deliveries);
        drop(terminal);
        assert_eq!(collector.try_recv().unwrap(), event(1));
        let TryReceiveError::Collector(error) = collector.try_recv().unwrap_err() else {
            panic!()
        };
        assert_eq!(error.kind(), CollectorReceiveErrorKind::PollFailure);
        assert!(error.source().is_some());
        let TryReceiveError::Collector(error) = collector.try_recv().unwrap_err() else {
            panic!()
        };
        assert_eq!(error.kind(), CollectorReceiveErrorKind::WorkerStop);
        assert!(error.source().is_none());
    }

    #[test]
    fn callback_panic_resumes_only_after_the_callback_returns() {
        let panic = Mutex::new(None);
        let result = catch_callback_panic(&panic, || panic!("callback panic"));
        assert_eq!(result, -1);
        assert!(callback_panicked(&panic));

        let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            resume_callback_panic(&panic);
        }))
        .unwrap_err();
        assert_eq!(
            CollectorWorkerPanic::from_payload(payload).message(),
            Some("callback panic")
        );
        assert!(panic.lock().unwrap().is_none());
    }

    #[test]
    fn unsupported_kernel_retains_the_load_error() {
        let error = CollectorPrepareError::new(
            CollectorPrepareErrorKind::UnsupportedKernel,
            std::io::Error::other("fake BPF load failure"),
        );
        assert_eq!(error.kind(), CollectorPrepareErrorKind::UnsupportedKernel);
        assert_eq!(error.source().unwrap().to_string(), "fake BPF load failure");
    }

    #[test]
    fn worker_panic_follows_buffered_deliveries() {
        let config = CollectorConfig::builder()
            .event_capacity(2)
            .build()
            .unwrap();
        let (collector, worker) = start_with_worker(config, |deliveries, _, _, _| {
            for id_offset in 1..=2 {
                deliveries
                    .send(DeliveryEntry {
                        delivery: Ok(event(id_offset)),
                        output_full_before: false,
                    })
                    .unwrap();
            }
            std::panic::panic_any(String::from("panic after deliveries"));
        });
        let mut collector = collector;

        assert_eq!(
            collector.recv_timeout(Duration::from_secs(1)).unwrap(),
            event(1)
        );
        assert_eq!(
            collector.recv_timeout(Duration::from_secs(1)).unwrap(),
            event(2)
        );
        let ReceiveTimeoutError::Collector(error) =
            collector.recv_timeout(Duration::from_secs(1)).unwrap_err()
        else {
            panic!()
        };
        assert_eq!(error.kind(), CollectorReceiveErrorKind::WorkerPanic);
        let source = error
            .source()
            .unwrap()
            .downcast_ref::<CollectorWorkerPanic>()
            .unwrap();
        assert_eq!(source.message(), Some("panic after deliveries"));
        worker.join().unwrap();
        let TryReceiveError::Collector(error) = collector.try_recv().unwrap_err() else {
            panic!()
        };
        assert_eq!(error.kind(), CollectorReceiveErrorKind::WorkerStop);
    }

    #[test]
    fn terminal_poll_error_precedes_worker_panic() {
        let config = CollectorConfig::default();
        let (collector, worker) = start_with_worker(config, |_, terminal, _, _| {
            terminal
                .send(CollectorReceiveError::new(
                    CollectorReceiveErrorKind::PollFailure,
                    std::io::Error::other("fake poll failure"),
                ))
                .unwrap();
            panic!("panic after terminal error");
        });
        let mut collector = collector;

        let ReceiveTimeoutError::Collector(error) =
            collector.recv_timeout(Duration::from_secs(1)).unwrap_err()
        else {
            panic!()
        };
        assert_eq!(error.kind(), CollectorReceiveErrorKind::PollFailure);
        let ReceiveTimeoutError::Collector(error) =
            collector.recv_timeout(Duration::from_secs(1)).unwrap_err()
        else {
            panic!()
        };
        assert_eq!(error.kind(), CollectorReceiveErrorKind::WorkerPanic);
        drop(collector);
        worker.join().unwrap();
    }

    #[test]
    fn disconnected_try_recv_does_not_join_unwinding_worker() {
        let (mut collector, worker, release_tx) = delayed_teardown_collector();
        let (try_finished_tx, try_finished_rx) = mpsc::sync_channel(0);
        let watchdog = thread::spawn(move || {
            let _ = try_finished_rx.recv_timeout(Duration::from_secs(1));
            release_tx.send(()).unwrap();
        });
        let start = Instant::now();
        assert!(matches!(collector.try_recv(), Err(TryReceiveError::Empty)));
        let elapsed = start.elapsed();
        try_finished_tx.send(()).unwrap();
        watchdog.join().unwrap();
        assert!(elapsed < Duration::from_millis(500));

        let deadline = Instant::now() + Duration::from_secs(1);
        let panic_error = loop {
            match collector.try_recv() {
                Err(TryReceiveError::Empty) => {
                    assert!(Instant::now() < deadline);
                    thread::yield_now();
                }
                Err(TryReceiveError::Collector(error)) => break error,
                Ok(_) => panic!(),
            }
        };
        assert_eq!(panic_error.kind(), CollectorReceiveErrorKind::WorkerPanic);
        let TryReceiveError::Collector(error) = collector.try_recv().unwrap_err() else {
            panic!()
        };
        assert_eq!(error.kind(), CollectorReceiveErrorKind::WorkerStop);
        drop(collector);
        worker.join().unwrap();
    }

    #[test]
    fn recv_timeout_budget_includes_unfinished_worker_teardown() {
        let (mut collector, worker, release_tx) = delayed_teardown_collector();
        let (receive_finished_tx, receive_finished_rx) = mpsc::sync_channel(1);
        let watchdog = thread::spawn(move || {
            let _ = receive_finished_rx.recv_timeout(Duration::from_secs(1));
            release_tx.send(()).unwrap();
        });

        let start = Instant::now();
        assert!(matches!(
            collector.recv_timeout(Duration::from_millis(20)),
            Err(ReceiveTimeoutError::Timeout)
        ));
        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_millis(500));
        assert!(matches!(
            collector.recv_timeout(Duration::ZERO),
            Err(ReceiveTimeoutError::Timeout)
        ));

        let _ = receive_finished_tx.try_send(());
        watchdog.join().unwrap();
        let ReceiveTimeoutError::Collector(error) =
            collector.recv_timeout(Duration::from_secs(1)).unwrap_err()
        else {
            panic!()
        };
        assert_eq!(error.kind(), CollectorReceiveErrorKind::WorkerPanic);
        let source = error
            .source()
            .unwrap()
            .downcast_ref::<CollectorWorkerPanic>()
            .unwrap();
        assert_eq!(source.message(), Some("panic before delayed teardown"));
        let ReceiveTimeoutError::Collector(error) =
            collector.recv_timeout(Duration::from_secs(1)).unwrap_err()
        else {
            panic!()
        };
        assert_eq!(error.kind(), CollectorReceiveErrorKind::WorkerStop);
        drop(collector);
        worker.join().unwrap();
    }

    #[test]
    fn queued_delivery_accepts_maximum_timeout() {
        let (mut collector, deliveries, _terminal) = fake_collector(1);
        deliveries
            .try_send(DeliveryEntry {
                delivery: Ok(event(1)),
                output_full_before: false,
            })
            .unwrap();
        assert_eq!(collector.recv_timeout(Duration::MAX).unwrap(), event(1));
    }

    #[test]
    fn opaque_panic_payload_is_dropped() {
        struct DropTracker(Arc<AtomicBool>);

        impl Drop for DropTracker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let payload_dropped = Arc::clone(&dropped);
        let config = CollectorConfig::default();
        let (collector, worker) = start_with_worker(config, |_, _, _, _| {
            std::panic::panic_any(DropTracker(payload_dropped));
        });
        let mut collector = collector;

        let ReceiveTimeoutError::Collector(error) =
            collector.recv_timeout(Duration::from_secs(1)).unwrap_err()
        else {
            panic!()
        };
        assert_eq!(error.kind(), CollectorReceiveErrorKind::WorkerPanic);
        let source = error
            .source()
            .unwrap()
            .downcast_ref::<CollectorWorkerPanic>()
            .unwrap();
        assert_eq!(source.message(), None);
        assert_eq!(
            source.to_string(),
            "collector worker panicked with an opaque payload"
        );
        assert!(dropped.load(Ordering::Acquire));
        drop(collector);
        worker.join().unwrap();
    }

    #[test]
    fn hostile_panic_payload_does_not_escape_receive_or_drop() {
        struct PanicOnDrop;

        impl Drop for PanicOnDrop {
            fn drop(&mut self) {
                panic!("panic payload dropped");
            }
        }

        let config = CollectorConfig::default();
        let (collector, worker) = start_with_worker(config, |_, _, _, _| {
            std::panic::panic_any(PanicOnDrop);
        });
        let mut collector = collector;
        let receive = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            collector.recv_timeout(Duration::from_secs(1))
        }));
        let ReceiveTimeoutError::Collector(error) = receive.unwrap().unwrap_err() else {
            panic!()
        };
        assert_eq!(error.kind(), CollectorReceiveErrorKind::WorkerPanic);
        drop(collector);
        worker.join().unwrap();

        let (collector, worker) = start_with_worker(config, |_, _, running, _| {
            while running.load(Ordering::Acquire) {
                thread::yield_now();
            }
            std::panic::panic_any(PanicOnDrop);
        });
        let collector = collector;
        let start = Instant::now();
        let dropped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(collector)));
        assert!(dropped.is_ok());
        worker.join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn callback_stops_during_shutdown_and_disconnection_under_traffic() {
        let (sender, receiver) = mpsc::sync_channel(8);
        let running = AtomicBool::new(true);
        let mut queue = DeliveryQueue {
            sender,
            output_full_pending: Arc::new(AtomicBool::new(false)),
        };
        for _ in 0..100 {
            assert_eq!(queue.deliver(&running, RULESET_FREE_FIXTURE), 0);
        }
        running.store(false, Ordering::Release);
        assert_eq!(queue.deliver(&running, RULESET_FREE_FIXTURE), -1);
        running.store(true, Ordering::Release);
        drop(receiver);
        assert_eq!(queue.deliver(&running, RULESET_FREE_FIXTURE), -1);
        assert!(!running.load(Ordering::Acquire));
    }
}
