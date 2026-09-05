// SPDX-License-Identifier: MIT OR Apache-2.0

//! Collection of Landlock events from the embedded BPF programs.

use std::cell::Cell;
use std::error::Error;
use std::fmt;
use std::mem::MaybeUninit;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::RingBufferBuilder;

use crate::event::Event;
use crate::wire;

mod bpf {
    include!(concat!(env!("OUT_DIR"), "/landlock_observability.skel.rs"));
}

use bpf::LandlockObservabilitySkelBuilder;

const DEFAULT_EVENT_CAPACITY: usize = 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The startup stage at which a collector failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CollectorStartErrorKind {
    /// The requested event capacity was zero.
    InvalidCapacity,
    /// The private worker thread could not be spawned.
    Spawn,
    /// The embedded BPF object could not be opened.
    Open,
    /// The BPF object could not be loaded into the kernel.
    Load,
    /// The BPF programs could not be attached.
    Attach,
    /// The userspace BPF ring-buffer consumer could not be set up.
    RingSetup,
    /// The worker stopped before reporting successful startup.
    EarlyWorkerStop,
}

impl CollectorStartErrorKind {
    fn description(self) -> &'static str {
        match self {
            Self::InvalidCapacity => "validate collector event capacity",
            Self::Spawn => "spawn collector worker",
            Self::Open => "open embedded BPF object",
            Self::Load => "load BPF object",
            Self::Attach => "attach BPF programs",
            Self::RingSetup => "set up BPF ring buffer",
            Self::EarlyWorkerStop => "complete collector startup",
        }
    }
}

/// An opaque failure to create a [`Collector`].
///
/// Use [`CollectorStartError::kind()`] to identify the startup stage.
/// Underlying spawning and libbpf errors remain available through
/// [`Error::source()`]; source-less validation failures retain a static detail.
#[derive(Debug)]
#[non_exhaustive]
pub struct CollectorStartError {
    kind: CollectorStartErrorKind,
    detail: ErrorDetail,
}

impl CollectorStartError {
    fn new(kind: CollectorStartErrorKind, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            kind,
            detail: ErrorDetail::Source(Box::new(source)),
        }
    }

    fn with_static_detail(kind: CollectorStartErrorKind, detail: &'static str) -> Self {
        Self {
            kind,
            detail: ErrorDetail::Static(detail),
        }
    }

    /// Returns the startup stage that failed.
    pub fn kind(&self) -> CollectorStartErrorKind {
        self.kind
    }
}

impl fmt::Display for CollectorStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to {}: {}",
            self.kind.description(),
            self.detail
        )
    }
}

impl Error for CollectorStartError {
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
    /// The private collector worker has stopped.
    WorkerStop,
}

impl CollectorReceiveErrorKind {
    fn description(self) -> &'static str {
        match self {
            Self::MalformedSample => "decode BPF event sample",
            Self::OutputQueueFull => "deliver entries through the full output queue",
            Self::PollFailure => "poll BPF ring buffer",
            Self::WorkerStop => "receive from the stopped collector worker",
        }
    }
}

/// An opaque collection failure occupying a position in the delivery stream.
///
/// Use [`CollectorReceiveError::kind()`] to identify the failure.  Detailed
/// decoding and libbpf errors remain available through [`Error::source()`]
/// without making the private wire format part of the public API.  Source-less
/// queue and worker-state failures retain a static detail.
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

type Delivery = Result<Event, CollectorReceiveError>;

struct DeliveryEntry {
    delivery: Delivery,
    output_full_before: bool,
}

type StartupResult = Result<(), CollectorStartError>;

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
/// All libbpf resources live on a private worker thread. Dropping the collector
/// requests shutdown and joins the worker, thereby detaching every BPF program.
/// An idle worker checks for shutdown after each poll of at most 100 ms; thread
/// scheduling and resource destruction do not have a real-time bound.
#[non_exhaustive]
pub struct Collector {
    deliveries: mpsc::Receiver<DeliveryEntry>,
    pending_delivery: Option<Delivery>,
    terminal: mpsc::Receiver<CollectorReceiveError>,
    running: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Collector {
    /// Creates a collector with a bounded capacity of 1024 delivery entries.
    ///
    /// This returns only after the BPF object is opened and loaded, all twelve
    /// programs are attached, and the ring-buffer consumer is ready.
    pub fn new() -> Result<Self, CollectorStartError> {
        Self::with_event_capacity(DEFAULT_EVENT_CAPACITY)
    }

    /// Creates a collector with the specified bounded delivery capacity.
    ///
    /// `event_capacity` bounds event-bearing and non-terminal-error delivery
    /// queue entries.  A coalesced output-full notification is control metadata
    /// paired with the next accepted delivery and does not occupy a separate
    /// queue entry.  Zero is rejected synchronously before attempting to spawn
    /// the worker.  Startup returns only after open, load, attach, and
    /// ring-buffer setup complete.
    pub fn with_event_capacity(event_capacity: usize) -> Result<Self, CollectorStartError> {
        if event_capacity == 0 {
            return Err(CollectorStartError::with_static_detail(
                CollectorStartErrorKind::InvalidCapacity,
                "event capacity must be greater than zero",
            ));
        }

        let (delivery_tx, delivery_rx) = mpsc::sync_channel(event_capacity);
        let (terminal_tx, terminal_rx) = mpsc::sync_channel(2);
        let (startup_tx, startup_rx) = mpsc::sync_channel(1);
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let worker = thread::Builder::new()
            .name("ll-observe".to_owned())
            .spawn(move || run_worker(delivery_tx, terminal_tx, worker_running, startup_tx))
            .map_err(|error| CollectorStartError::new(CollectorStartErrorKind::Spawn, error))?;

        match startup_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                deliveries: delivery_rx,
                pending_delivery: None,
                terminal: terminal_rx,
                running,
                worker: Some(worker),
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(error) => {
                let _ = worker.join();
                Err(CollectorStartError::new(
                    CollectorStartErrorKind::EarlyWorkerStop,
                    error,
                ))
            }
        }
    }

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
                .terminal_now()
                .map_or(Err(TryReceiveError::Empty), |error| {
                    Err(TryReceiveError::Collector(error))
                }),
            Err(mpsc::TryRecvError::Disconnected) => {
                Err(TryReceiveError::Collector(self.terminal_or_stop()))
            }
        }
    }

    /// Waits up to `timeout` for the next event.
    ///
    /// [`ReceiveTimeoutError::Timeout`] is distinct from collection failures.
    /// Buffered delivery entries are returned before a terminal poll failure;
    /// after that failure, subsequent calls report worker termination.
    pub fn recv_timeout(&mut self, timeout: Duration) -> Result<Event, ReceiveTimeoutError> {
        if let Some(delivery) = self.pending_delivery.take() {
            return delivery.map_err(ReceiveTimeoutError::Collector);
        }
        match self.deliveries.recv_timeout(timeout) {
            Ok(entry) => self.unpair(entry).map_err(ReceiveTimeoutError::Collector),
            Err(mpsc::RecvTimeoutError::Timeout) => self
                .terminal_now()
                .map_or(Err(ReceiveTimeoutError::Timeout), |error| {
                    Err(ReceiveTimeoutError::Collector(error))
                }),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(ReceiveTimeoutError::Collector(self.terminal_or_stop()))
            }
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

    fn terminal_now(&mut self) -> Option<CollectorReceiveError> {
        match self.terminal.try_recv() {
            Ok(error) => Some(error),
            Err(mpsc::TryRecvError::Disconnected) => Some(worker_stop()),
            Err(mpsc::TryRecvError::Empty) => None,
        }
    }

    fn terminal_or_stop(&mut self) -> CollectorReceiveError {
        self.terminal_now().unwrap_or_else(worker_stop)
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct DeliveryQueue {
    sender: mpsc::SyncSender<DeliveryEntry>,
    output_full_pending: Rc<Cell<bool>>,
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
            output_full_before: self.output_full_pending.get(),
        };
        match self.sender.try_send(entry) {
            Ok(()) => {
                self.output_full_pending.set(false);
                0
            }
            Err(mpsc::TrySendError::Full(_)) => {
                self.output_full_pending.set(true);
                0
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                running.store(false, Ordering::Release);
                -1
            }
        }
    }
}

fn startup_failure(
    startup: &mpsc::SyncSender<StartupResult>,
    kind: CollectorStartErrorKind,
    source: impl Error + Send + Sync + 'static,
) {
    let _ = startup.send(Err(CollectorStartError::new(kind, source)));
}

fn run_worker(
    deliveries: mpsc::SyncSender<DeliveryEntry>,
    terminal: mpsc::SyncSender<CollectorReceiveError>,
    running: Arc<AtomicBool>,
    startup: mpsc::SyncSender<StartupResult>,
) {
    let builder = LandlockObservabilitySkelBuilder::default();
    let mut object = MaybeUninit::uninit();
    let open = match builder.open(&mut object) {
        Ok(open) => open,
        Err(error) => {
            startup_failure(&startup, CollectorStartErrorKind::Open, error);
            return;
        }
    };
    let mut skeleton = match open.load() {
        Ok(skeleton) => skeleton,
        Err(error) => {
            startup_failure(&startup, CollectorStartErrorKind::Load, error);
            return;
        }
    };
    if let Err(error) = skeleton.attach() {
        startup_failure(&startup, CollectorStartErrorKind::Attach, error);
        return;
    }

    // A nonzero callback return stops libbpf's greedy poll; the resulting poll
    // error during shutdown is ignored below because `running` is already false.
    let callback_running = Arc::clone(&running);
    let output_full_pending = Rc::new(Cell::new(false));
    let mut queue = DeliveryQueue {
        sender: deliveries.clone(),
        output_full_pending: Rc::clone(&output_full_pending),
    };
    let mut ring_builder = RingBufferBuilder::new();
    if let Err(error) = ring_builder.add(&skeleton.maps.events, move |data| {
        queue.deliver(&callback_running, data)
    }) {
        startup_failure(&startup, CollectorStartErrorKind::RingSetup, error);
        return;
    }
    let ring = match ring_builder.build() {
        Ok(ring) => ring,
        Err(error) => {
            startup_failure(&startup, CollectorStartErrorKind::RingSetup, error);
            return;
        }
    };
    if startup.send(Ok(())).is_err() {
        return;
    }

    while running.load(Ordering::Acquire) {
        if let Err(error) = ring.poll(POLL_INTERVAL) {
            if running.load(Ordering::Acquire) {
                if output_full_pending.get() {
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
    use std::time::Instant;

    #[cfg(target_endian = "little")]
    const RULESET_FREE_FIXTURE: &[u8; 344] =
        include_bytes!("../tests/fixtures/wire/11-ruleset-free-little-endian.bin");
    #[cfg(target_endian = "big")]
    const RULESET_FREE_FIXTURE: &[u8; 344] =
        include_bytes!("../tests/fixtures/wire/11-ruleset-free-big-endian.bin");

    fn event(id_offset: u64) -> Event {
        Event::FreeRuleset(FreeRulesetEvent::new(
            KernelTimestamp::from_nanoseconds(id_offset),
            RulesetId::new(MIN_LANDLOCK_ID + id_offset).unwrap(),
            id_offset as u32,
        ))
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
        let worker_running = Arc::clone(&running);
        let worker = thread::spawn(move || {
            while worker_running.load(Ordering::Acquire) {
                thread::yield_now();
            }
        });
        (
            Collector {
                deliveries: delivery_rx,
                pending_delivery: None,
                terminal: terminal_rx,
                running,
                worker: Some(worker),
            },
            delivery_tx,
            terminal_tx,
        )
    }

    #[test]
    fn zero_capacity_is_rejected_before_spawn() {
        let Err(error) = Collector::with_event_capacity(0) else {
            panic!()
        };
        assert_eq!(error.kind(), CollectorStartErrorKind::InvalidCapacity);
        assert!(error.source().is_none());

        let spawn = CollectorStartError::new(
            CollectorStartErrorKind::Spawn,
            std::io::Error::other("fake spawn failure"),
        );
        assert!(spawn.source().is_some());
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
            output_full_pending: Rc::new(Cell::new(false)),
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
        assert!(queue.output_full_pending.get());
    }

    #[test]
    fn capacity_one_pairs_notice_with_next_accepted_delivery() {
        let (mut collector, sender, _terminal) = fake_collector(1);
        let running = AtomicBool::new(true);
        let pending = Rc::new(Cell::new(false));
        let mut queue = DeliveryQueue {
            sender,
            output_full_pending: Rc::clone(&pending),
        };

        assert_eq!(queue.deliver(&running, &sample(1)), 0);
        assert_eq!(queue.deliver(&running, &sample(2)), 0);
        assert_eq!(queue.deliver(&running, &sample(3)), 0);
        assert_eq!(
            collector.try_recv().unwrap(),
            wire::decode(&sample(1)).unwrap()
        );

        assert_eq!(queue.deliver(&running, &sample(4)), 0);
        assert!(!pending.get());
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
            output_full_pending: Rc::new(Cell::new(false)),
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
            output_full_pending: Rc::new(Cell::new(false)),
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
    fn drop_requests_and_joins_fake_worker() {
        let (collector, _deliveries, _terminal) = fake_collector(1);
        let start = Instant::now();
        drop(collector);
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn callback_stops_during_shutdown_and_disconnection_under_traffic() {
        let (sender, receiver) = mpsc::sync_channel(8);
        let running = AtomicBool::new(true);
        let mut queue = DeliveryQueue {
            sender,
            output_full_pending: Rc::new(Cell::new(false)),
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
