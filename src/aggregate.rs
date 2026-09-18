// SPDX-License-Identifier: MIT OR Apache-2.0

//! Optional bounded aggregation of Landlock denial events.

use crate::event::{
    CapturedAbstractUnixSocketName, CapturedCommand, Denial, DomainId, DomainMembership, Event,
    FilesystemAccess, KernelTimestamp, NetworkAccess, Observation, ProcessId,
};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

const DEFAULT_CAPACITY: usize = 1000;

/// A filesystem denial aggregation key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct FilesystemDenialKey {
    domain_id: DomainId,
    blockers_access: FilesystemAccess,
    device: u32,
    inode: u64,
}

impl FilesystemDenialKey {
    /// Creates a filesystem denial key.
    pub const fn new(
        domain_id: DomainId,
        blockers_access: FilesystemAccess,
        device: u32,
        inode: u64,
    ) -> Self {
        Self {
            domain_id,
            blockers_access,
            device,
            inode,
        }
    }

    /// Returns the denying domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    /// Returns the access rights that blocked the operation.
    pub const fn blockers_access(&self) -> FilesystemAccess {
        self.blockers_access
    }

    /// Returns the captured filesystem device number.
    pub const fn device(&self) -> u32 {
        self.device
    }

    /// Returns the captured filesystem inode number.
    pub const fn inode(&self) -> u64 {
        self.inode
    }
}

/// A network denial aggregation key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct NetworkDenialKey {
    domain_id: DomainId,
    blockers_access: NetworkAccess,
    source_port: u64,
    destination_port: u64,
}

impl NetworkDenialKey {
    /// Creates a network denial key.
    pub const fn new(
        domain_id: DomainId,
        blockers_access: NetworkAccess,
        source_port: u64,
        destination_port: u64,
    ) -> Self {
        Self {
            domain_id,
            blockers_access,
            source_port,
            destination_port,
        }
    }

    /// Returns the denying domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    /// Returns the access rights that blocked the operation.
    pub const fn blockers_access(&self) -> NetworkAccess {
        self.blockers_access
    }

    /// Returns the checked port projected for a known bind access, or zero otherwise.
    pub const fn source_port(&self) -> u64 {
        self.source_port
    }

    /// Returns the checked port projected for a known connect or send access, or zero otherwise.
    pub const fn destination_port(&self) -> u64 {
        self.destination_port
    }
}

/// A ptrace denial aggregation key. The captured tracee command is part of the identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct PtraceDenialKey {
    domain_id: DomainId,
    tracee_domain: DomainMembership,
    tracee_pid: ProcessId,
    tracee_comm: CapturedCommand,
}

impl PtraceDenialKey {
    /// Creates a ptrace denial key.
    pub fn new(
        domain_id: DomainId,
        tracee_domain: DomainMembership,
        tracee_pid: ProcessId,
        tracee_comm: CapturedCommand,
    ) -> Self {
        Self {
            domain_id,
            tracee_domain,
            tracee_pid,
            tracee_comm,
        }
    }

    /// Returns the denying domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    /// Returns whether the tracee was unsandboxed or in a domain.
    pub const fn tracee_domain(&self) -> DomainMembership {
        self.tracee_domain
    }

    /// Returns the process ID of the tracee task.
    pub const fn tracee_pid(&self) -> ProcessId {
        self.tracee_pid
    }

    /// Returns the captured command name of the tracee task.
    pub const fn tracee_comm(&self) -> &CapturedCommand {
        &self.tracee_comm
    }
}

/// A signal denial aggregation key. The captured target command is part of the identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct SignalDenialKey {
    domain_id: DomainId,
    target_domain: DomainMembership,
    target_pid: ProcessId,
    target_comm: CapturedCommand,
}

impl SignalDenialKey {
    /// Creates a signal denial key.
    pub fn new(
        domain_id: DomainId,
        target_domain: DomainMembership,
        target_pid: ProcessId,
        target_comm: CapturedCommand,
    ) -> Self {
        Self {
            domain_id,
            target_domain,
            target_pid,
            target_comm,
        }
    }

    /// Returns the denying domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    /// Returns whether the target was unsandboxed or in a domain.
    pub const fn target_domain(&self) -> DomainMembership {
        self.target_domain
    }

    /// Returns the process ID of the target task.
    pub const fn target_pid(&self) -> ProcessId {
        self.target_pid
    }

    /// Returns the captured command name of the target task.
    pub const fn target_comm(&self) -> &CapturedCommand {
        &self.target_comm
    }
}

/// An abstract UNIX socket denial aggregation key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct AbstractUnixSocketDenialKey {
    domain_id: DomainId,
    peer_domain: DomainMembership,
    abstract_name: CapturedAbstractUnixSocketName,
}

impl AbstractUnixSocketDenialKey {
    /// Creates an abstract UNIX socket denial key.
    pub fn new(
        domain_id: DomainId,
        peer_domain: DomainMembership,
        abstract_name: CapturedAbstractUnixSocketName,
    ) -> Self {
        Self {
            domain_id,
            peer_domain,
            abstract_name,
        }
    }

    /// Returns the denying domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    /// Returns whether the peer was unsandboxed or in a domain.
    pub const fn peer_domain(&self) -> DomainMembership {
        self.peer_domain
    }

    /// Returns the peer socket's captured abstract name.
    pub const fn abstract_name(&self) -> &CapturedAbstractUnixSocketName {
        &self.abstract_name
    }
}

/// A type-safe denial aggregation key.
///
/// Each variant contains only the blocker and target categories carried by its
/// denial family. Filesystem paths are descriptive event data and are not part
/// of filesystem target identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum DenialKey {
    /// A filesystem denial key.
    Filesystem(FilesystemDenialKey),
    /// A network denial key.
    Network(NetworkDenialKey),
    /// A ptrace denial key.
    Ptrace(PtraceDenialKey),
    /// A signal denial key.
    Signal(SignalDenialKey),
    /// An abstract UNIX socket denial key.
    AbstractUnixSocket(AbstractUnixSocketDenialKey),
}

impl DenialKey {
    /// Returns the identity of the domain that denied the operation.
    pub const fn domain_id(&self) -> DomainId {
        match self {
            Self::Filesystem(key) => key.domain_id(),
            Self::Network(key) => key.domain_id(),
            Self::Ptrace(key) => key.domain_id(),
            Self::Signal(key) => key.domain_id(),
            Self::AbstractUnixSocket(key) => key.domain_id(),
        }
    }
}

/// The reason a denial aggregator could not be built.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DenialAggregatorBuildErrorKind {
    /// The configured capacity was zero.
    InvalidCapacity,
    /// Storage for the configured capacity could not be reserved.
    Reservation,
}

/// A failure to build a [`DenialAggregator`].
#[derive(Debug)]
#[non_exhaustive]
pub struct DenialAggregatorBuildError {
    kind: DenialAggregatorBuildErrorKind,
    configured: usize,
    source: Option<std::collections::TryReserveError>,
}

impl DenialAggregatorBuildError {
    /// Returns the reason construction failed.
    pub const fn kind(&self) -> DenialAggregatorBuildErrorKind {
        self.kind
    }

    /// Returns the configured capacity that could not be built.
    pub const fn configured(&self) -> usize {
        self.configured
    }
}

impl fmt::Display for DenialAggregatorBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(source) => write!(
                formatter,
                "failed to reserve denial aggregation capacity {}: {source}",
                self.configured
            ),
            None => formatter.write_str("denial aggregation capacity must be nonzero"),
        }
    }
}

impl Error for DenialAggregatorBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

/// A builder for a [`DenialAggregator`].
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct DenialAggregatorBuilder {
    capacity: usize,
}

impl DenialAggregatorBuilder {
    /// Configures the exact maximum number of retained denial keys.
    pub const fn capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    /// Validates the capacity and reserves its map storage.
    pub fn build(self) -> Result<DenialAggregator, DenialAggregatorBuildError> {
        if self.capacity == 0 {
            return Err(DenialAggregatorBuildError {
                kind: DenialAggregatorBuildErrorKind::InvalidCapacity,
                configured: self.capacity,
                source: None,
            });
        }

        let mut entries = HashMap::new();
        entries
            .try_reserve(self.capacity)
            .map_err(|source| DenialAggregatorBuildError {
                kind: DenialAggregatorBuildErrorKind::Reservation,
                configured: self.capacity,
                source: Some(source),
            })?;
        Ok(DenialAggregator {
            capacity: self.capacity,
            entries,
            ingestion_sequence: 0,
        })
    }
}

impl Default for DenialAggregatorBuilder {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_CAPACITY,
        }
    }
}

/// A locally aggregated denial and its latest observed event.
#[derive(Debug)]
#[non_exhaustive]
pub struct AggregatedDenial {
    key: DenialKey,
    occurrence_count: u64,
    first_timestamp: KernelTimestamp,
    latest_timestamp: KernelTimestamp,
    same_exec: bool,
    logged: bool,
    latest_event: Event,
    last_observed_sequence: u128,
}

impl AggregatedDenial {
    /// Returns the semantic aggregation key.
    pub const fn key(&self) -> &DenialKey {
        &self.key
    }

    /// Returns the number of matching events observed by this aggregator.
    ///
    /// This local count is independent of the kernel's cumulative denial count
    /// and saturates at [`u64::MAX`].
    pub const fn occurrence_count(&self) -> u64 {
        self.occurrence_count
    }

    /// Returns the timestamp carried by the first matching event ingested.
    pub const fn first_timestamp(&self) -> KernelTimestamp {
        self.first_timestamp
    }

    /// Returns the timestamp carried by the latest matching event ingested.
    ///
    /// Ingestion order is used even when kernel timestamps are equal or decrease.
    pub const fn latest_timestamp(&self) -> KernelTimestamp {
        self.latest_timestamp
    }

    /// Returns `same_exec` from the latest matching denial event ingested.
    pub const fn same_exec(&self) -> bool {
        self.same_exec
    }

    /// Returns `logged` from the latest matching denial event ingested.
    pub const fn logged(&self) -> bool {
        self.logged
    }

    /// Returns the latest matching event ingested.
    ///
    /// The returned value is guaranteed to be one of the denial variants of
    /// [`Event`].
    pub const fn latest_event(&self) -> &Event {
        &self.latest_event
    }
}

/// An optional bounded least-recently-observed denial aggregator.
///
/// Raw [`Event`] values remain independently usable; aggregation occurs only
/// when callers explicitly pass events to [`DenialAggregator::observe()`].
#[derive(Debug)]
#[non_exhaustive]
pub struct DenialAggregator {
    capacity: usize,
    entries: HashMap<DenialKey, AggregatedDenial>,
    ingestion_sequence: u128,
}

impl DenialAggregator {
    /// Creates an empty aggregator with capacity 1000.
    ///
    /// This infallible default does not allocate storage.  Use
    /// [`DenialAggregator::builder()`] to reserve storage during construction.
    pub fn new() -> Self {
        Self {
            capacity: DEFAULT_CAPACITY,
            entries: HashMap::new(),
            ingestion_sequence: 0,
        }
    }

    /// Returns a builder configured with capacity 1000.
    pub fn builder() -> DenialAggregatorBuilder {
        DenialAggregatorBuilder::default()
    }

    /// Observes an event, aggregating it when it is a concrete denial.
    ///
    /// Non-denial events are ignored. Every matching hit refreshes the
    /// least-recently-observed recency. Inserting a new key while full evicts
    /// the key whose matching event was ingested least recently.
    pub fn observe(&mut self, event: &Event) {
        let _ = self.observe_entry(event);
    }

    /// Observes an event and returns the affected retained entry for a denial.
    ///
    /// Non-denial events return `None`. The returned entry already contains
    /// the current observation.
    pub fn observe_entry(&mut self, event: &Event) -> Option<&AggregatedDenial> {
        let (key, same_exec, logged) = denial_facts(event)?;
        let sequence = self.next_ingestion_sequence();

        if self.entries.contains_key(&key) {
            let entry = self.entries.get_mut(&key)?;
            entry.occurrence_count = entry.occurrence_count.saturating_add(1);
            entry.latest_timestamp = event.timestamp();
            entry.same_exec = same_exec;
            entry.logged = logged;
            entry.latest_event = event.clone();
            entry.last_observed_sequence = sequence;
            return Some(entry);
        }

        if self.entries.len() >= self.capacity {
            let least_recent_key = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_observed_sequence)
                .map(|(key, _)| key.clone())?;
            self.entries.remove(&least_recent_key);
        }

        Some(self.entries.entry(key.clone()).or_insert(AggregatedDenial {
            key,
            occurrence_count: 1,
            first_timestamp: event.timestamp(),
            latest_timestamp: event.timestamp(),
            same_exec,
            logged,
            latest_event: event.clone(),
            last_observed_sequence: sequence,
        }))
    }

    fn next_ingestion_sequence(&mut self) -> u128 {
        // Compact stored sequence numbers in their existing recency order.  The
        // current observation then receives a number greater than every entry.
        if self.ingestion_sequence == u128::MAX {
            let mut recency = self.entries.values_mut().collect::<Vec<_>>();
            recency.sort_unstable_by_key(|entry| entry.last_observed_sequence);
            let mut sequence = 0_u128;
            for entry in recency {
                sequence = sequence.saturating_add(1);
                entry.last_observed_sequence = sequence;
            }
            self.ingestion_sequence = sequence;
        }
        self.ingestion_sequence = self.ingestion_sequence.saturating_add(1);
        self.ingestion_sequence
    }

    /// Iterates over retained entries in an unspecified order.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = &AggregatedDenial> {
        self.entries.values()
    }

    /// Returns the retained entry for `key`, if present.
    pub fn get(&self, key: &DenialKey) -> Option<&AggregatedDenial> {
        self.entries.get(key)
    }

    /// Returns the number of retained unique denial keys.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no denial keys are retained.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the exact maximum number of retained denial keys.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }
}

impl Default for DenialAggregator {
    fn default() -> Self {
        Self::new()
    }
}

fn denial_facts(event: &Event) -> Option<(DenialKey, bool, bool)> {
    let (key, context) = match event {
        Event::DenyAccessFs(denial) => (
            DenialKey::Filesystem(FilesystemDenialKey::new(
                denial.context().hierarchy().domain_id(),
                denial.blockers_access(),
                denial.device(),
                denial.inode(),
            )),
            denial.context(),
        ),
        Event::DenyAccessNet(denial) => (
            DenialKey::Network(NetworkDenialKey::new(
                denial.context().hierarchy().domain_id(),
                denial.blockers_access(),
                denial.source_port(),
                denial.destination_port(),
            )),
            denial.context(),
        ),
        Event::DenyPtrace(denial) => (
            DenialKey::Ptrace(PtraceDenialKey::new(
                denial.context().hierarchy().domain_id(),
                denial.tracee_domain(),
                denial.tracee_pid(),
                denial.tracee_comm().clone(),
            )),
            denial.context(),
        ),
        Event::DenyScopeSignal(denial) => (
            DenialKey::Signal(SignalDenialKey::new(
                denial.context().hierarchy().domain_id(),
                denial.target_domain(),
                denial.target_pid(),
                denial.target_comm().clone(),
            )),
            denial.context(),
        ),
        Event::DenyScopeAbstractUnixSocket(denial) => (
            DenialKey::AbstractUnixSocket(AbstractUnixSocketDenialKey::new(
                denial.context().hierarchy().domain_id(),
                denial.peer_domain(),
                denial.abstract_name().clone(),
            )),
            denial.context(),
        ),
        _ => return None,
    };
    Some((key, context.same_exec(), context.logged()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{CapturedBytes, CapturedBytesOrigin};
    use crate::event::{
        DenialContext, DenyAccessFsEvent, DenyAccessNetEvent, DenyPtraceEvent,
        DenyScopeAbstractUnixSocketEvent, DenyScopeSignalEvent, FreeDomainEvent, HierarchySnapshot,
        MIN_LANDLOCK_ID,
    };

    fn string<K: CapturedBytesOrigin>(value: &[u8]) -> CapturedBytes<K> {
        CapturedBytes::new(value.to_vec(), false).unwrap()
    }

    fn pid(value: u32) -> ProcessId {
        ProcessId::new(value).unwrap()
    }

    fn context(
        domain_offset: u64,
        cumulative: u64,
        same_exec: bool,
        logged: bool,
    ) -> DenialContext {
        DenialContext::builder()
            .hierarchy(
                HierarchySnapshot::builder()
                    .domain_id(DomainId::new(MIN_LANDLOCK_ID + domain_offset).unwrap())
                    .parent_id(None)
                    .creator_tgid(pid(10))
                    .creator_comm(string(b"creator"))
                    .build(),
            )
            .cumulative_denial_count(cumulative)
            .same_exec(same_exec)
            .logged(logged)
            .build()
    }

    fn fs(
        timestamp: u64,
        domain_offset: u64,
        cumulative: u64,
        blockers_access: u64,
        target: (u32, u64, &[u8]),
        flags: (bool, bool),
    ) -> Event {
        Event::DenyAccessFs(
            DenyAccessFsEvent::builder()
                .timestamp(KernelTimestamp::from_nanoseconds(timestamp))
                .context(context(domain_offset, cumulative, flags.0, flags.1))
                .blockers_access(FilesystemAccess::from_bits(blockers_access))
                .device(target.0)
                .inode(target.1)
                .pathname(string(target.2))
                .build(),
        )
    }

    fn network(
        timestamp: u64,
        domain_offset: u64,
        blockers_access: u64,
        ports: (u64, u64),
    ) -> Event {
        Event::DenyAccessNet(
            DenyAccessNetEvent::builder()
                .timestamp(KernelTimestamp::from_nanoseconds(timestamp))
                .context(context(domain_offset, 1, false, true))
                .blockers_access(NetworkAccess::from_bits(blockers_access))
                .source_port(ports.0)
                .destination_port(ports.1)
                .build(),
        )
    }

    #[test]
    fn keys_cover_all_denial_families_and_fields() {
        let ptrace = Event::DenyPtrace(
            DenyPtraceEvent::builder()
                .timestamp(KernelTimestamp::from_nanoseconds(3))
                .context(context(12, 1, false, false))
                .tracee_domain(DomainMembership::Sandboxed(
                    DomainId::new(MIN_LANDLOCK_ID + 20).unwrap(),
                ))
                .tracee_pid(pid(30))
                .tracee_comm(string(b"tracee"))
                .build(),
        );
        let signal = Event::DenyScopeSignal(
            DenyScopeSignalEvent::builder()
                .timestamp(KernelTimestamp::from_nanoseconds(4))
                .context(context(13, 1, false, false))
                .target_domain(DomainMembership::Unsandboxed)
                .target_pid(pid(31))
                .target_comm(string(b"target"))
                .build(),
        );
        let unix = Event::DenyScopeAbstractUnixSocket(
            DenyScopeAbstractUnixSocketEvent::builder()
                .timestamp(KernelTimestamp::from_nanoseconds(5))
                .context(context(14, 1, false, false))
                .peer_domain(DomainMembership::Sandboxed(
                    DomainId::new(MIN_LANDLOCK_ID + 21).unwrap(),
                ))
                .peer_pid(Some(pid(32)))
                .abstract_name(string(b"service\0v1"))
                .build(),
        );
        let mut aggregator = DenialAggregator::new();
        aggregator.observe(&fs(
            1,
            10,
            1,
            0x8000_0000_0000_0001,
            (2, 3, b"/a"),
            (false, false),
        ));
        aggregator.observe(&network(2, 11, 0x8000_0000_0000_0002, (100, 200)));
        aggregator.observe(&ptrace);
        aggregator.observe(&signal);
        aggregator.observe(&unix);

        assert_eq!(aggregator.len(), 5);
        let fs_key = DenialKey::Filesystem(FilesystemDenialKey::new(
            DomainId::new(MIN_LANDLOCK_ID + 10).unwrap(),
            FilesystemAccess::from_bits(0x8000_0000_0000_0001),
            2,
            3,
        ));
        let network_key = DenialKey::Network(NetworkDenialKey::new(
            DomainId::new(MIN_LANDLOCK_ID + 11).unwrap(),
            NetworkAccess::from_bits(0x8000_0000_0000_0002),
            100,
            200,
        ));
        let ptrace_key = DenialKey::Ptrace(PtraceDenialKey::new(
            DomainId::new(MIN_LANDLOCK_ID + 12).unwrap(),
            DomainMembership::Sandboxed(DomainId::new(MIN_LANDLOCK_ID + 20).unwrap()),
            pid(30),
            string(b"tracee"),
        ));
        let signal_key = DenialKey::Signal(SignalDenialKey::new(
            DomainId::new(MIN_LANDLOCK_ID + 13).unwrap(),
            DomainMembership::Unsandboxed,
            pid(31),
            string(b"target"),
        ));
        let unix_key = DenialKey::AbstractUnixSocket(AbstractUnixSocketDenialKey::new(
            DomainId::new(MIN_LANDLOCK_ID + 14).unwrap(),
            DomainMembership::Sandboxed(DomainId::new(MIN_LANDLOCK_ID + 21).unwrap()),
            string(b"service\0v1"),
        ));
        assert!(aggregator.get(&fs_key).is_some());
        assert!(aggregator.get(&network_key).is_some());
        assert!(aggregator.get(&ptrace_key).is_some());
        assert!(aggregator.get(&signal_key).is_some());
        assert!(aggregator.get(&unix_key).is_some());
        assert_eq!(
            fs_key.domain_id(),
            DomainId::new(MIN_LANDLOCK_ID + 10).unwrap()
        );

        let DenialKey::Filesystem(key) = fs_key else {
            panic!("filesystem key changed variant");
        };
        assert_eq!(key.blockers_access().bits(), 0x8000_0000_0000_0001);
        assert_eq!((key.device(), key.inode()), (2, 3));
        let DenialKey::Network(key) = network_key else {
            panic!("network key changed variant");
        };
        assert_eq!(key.blockers_access().bits(), 0x8000_0000_0000_0002);
        assert_eq!((key.source_port(), key.destination_port()), (100, 200));
        let DenialKey::Ptrace(key) = ptrace_key else {
            panic!("ptrace key changed variant");
        };
        assert_eq!(
            key.tracee_domain(),
            DomainMembership::Sandboxed(DomainId::new(MIN_LANDLOCK_ID + 20).unwrap())
        );
        assert_eq!(key.tracee_pid(), pid(30));
        assert_eq!(key.tracee_comm().as_bytes(), b"tracee");
        let DenialKey::Signal(key) = signal_key else {
            panic!("signal key changed variant");
        };
        assert_eq!(key.target_domain(), DomainMembership::Unsandboxed);
        assert_eq!(key.target_pid(), pid(31));
        assert_eq!(key.target_comm().as_bytes(), b"target");
        let DenialKey::AbstractUnixSocket(key) = unix_key else {
            panic!("abstract UNIX key changed variant");
        };
        assert_eq!(
            key.peer_domain(),
            DomainMembership::Sandboxed(DomainId::new(MIN_LANDLOCK_ID + 21).unwrap())
        );
        assert_eq!(key.abstract_name().as_bytes(), b"service\0v1");
    }

    #[test]
    fn matching_filesystem_events_keep_ingestion_order_and_latest_path() {
        let first = fs(50, 7, 900, 1, (2, 3, b"/old"), (false, true));
        let latest = fs(40, 7, 4, 1, (2, 3, b"/new"), (true, false));
        let equal = fs(40, 7, 1000, 1, (2, 3, b"/equal"), (false, true));
        let mut aggregator = DenialAggregator::new();
        aggregator.observe(&first);
        aggregator.observe(&latest);
        let entry = aggregator.observe_entry(&equal).unwrap();
        assert_eq!(entry.occurrence_count(), 3);
        assert_eq!(entry.first_timestamp().as_nanoseconds(), 50);
        assert_eq!(entry.latest_timestamp().as_nanoseconds(), 40);
        assert!(!entry.same_exec());
        assert!(entry.logged());
        let Event::DenyAccessFs(latest) = entry.latest_event() else {
            panic!("latest event is not a filesystem denial");
        };
        assert_eq!(latest.timestamp().as_nanoseconds(), 40);
        assert_eq!(latest.pathname().as_bytes(), b"/equal");
        assert_eq!(latest.context().cumulative_denial_count(), 1000);
    }

    #[test]
    fn identity_dimensions_remain_distinct() {
        let task_denial = |signal, domain_membership, task_pid, task_comm: &[u8]| {
            let timestamp = KernelTimestamp::from_nanoseconds(1);
            let context = context(1, 1, false, false);
            if signal {
                Event::DenyScopeSignal(
                    DenyScopeSignalEvent::builder()
                        .timestamp(timestamp)
                        .context(context)
                        .target_domain(domain_membership)
                        .target_pid(task_pid)
                        .target_comm(string(task_comm))
                        .build(),
                )
            } else {
                Event::DenyPtrace(
                    DenyPtraceEvent::builder()
                        .timestamp(timestamp)
                        .context(context)
                        .tracee_domain(domain_membership)
                        .tracee_pid(task_pid)
                        .tracee_comm(string(task_comm))
                        .build(),
                )
            }
        };
        let unix_denial = |peer_domain, peer_pid, abstract_name: &[u8]| {
            Event::DenyScopeAbstractUnixSocket(
                DenyScopeAbstractUnixSocketEvent::builder()
                    .timestamp(KernelTimestamp::from_nanoseconds(1))
                    .context(context(1, 1, false, false))
                    .peer_domain(peer_domain)
                    .peer_pid(peer_pid)
                    .abstract_name(string(abstract_name))
                    .build(),
            )
        };
        let events = [
            fs(1, 1, 1, 1, (1, 1, b"/a"), (false, false)),
            fs(1, 2, 1, 1, (1, 1, b"/a"), (false, false)),
            fs(1, 1, 1, 2, (1, 1, b"/a"), (false, false)),
            fs(1, 1, 1, 1, (2, 1, b"/a"), (false, false)),
            fs(1, 1, 1, 1, (1, 2, b"/a"), (false, false)),
            network(1, 1, 1, (1, 1)),
            network(1, 1, 1, (2, 1)),
            network(1, 1, 1, (1, 2)),
            task_denial(false, DomainMembership::Unsandboxed, pid(1), b"task"),
            task_denial(true, DomainMembership::Unsandboxed, pid(1), b"task"),
            task_denial(
                false,
                DomainMembership::Sandboxed(DomainId::new(MIN_LANDLOCK_ID + 2).unwrap()),
                pid(1),
                b"task",
            ),
            task_denial(false, DomainMembership::Unsandboxed, pid(2), b"task"),
            task_denial(false, DomainMembership::Unsandboxed, pid(1), b"other"),
            unix_denial(DomainMembership::Unsandboxed, Some(pid(1)), b"service\0one"),
            unix_denial(
                DomainMembership::Sandboxed(DomainId::new(MIN_LANDLOCK_ID + 2).unwrap()),
                Some(pid(1)),
                b"service\0one",
            ),
            unix_denial(DomainMembership::Unsandboxed, Some(pid(1)), b"service\0two"),
        ];
        let mut aggregator = DenialAggregator::new();
        for event in &events {
            aggregator.observe(event);
        }
        assert_eq!(aggregator.len(), events.len());
    }

    #[test]
    fn abstract_name_is_identity_while_peer_pid_is_descriptive() {
        let denial = |timestamp, peer_pid, abstract_name: &[u8]| {
            Event::DenyScopeAbstractUnixSocket(
                DenyScopeAbstractUnixSocketEvent::builder()
                    .timestamp(KernelTimestamp::from_nanoseconds(timestamp))
                    .context(context(1, 1, false, false))
                    .peer_domain(DomainMembership::Unsandboxed)
                    .peer_pid(peer_pid)
                    .abstract_name(string(abstract_name))
                    .build(),
            )
        };
        let mut aggregator = DenialAggregator::new();
        aggregator.observe(&denial(1, Some(pid(10)), b"service\0one"));
        let merged = aggregator
            .observe_entry(&denial(2, Some(pid(20)), b"service\0one"))
            .unwrap();
        assert_eq!(merged.occurrence_count(), 2);
        let Event::DenyScopeAbstractUnixSocket(latest) = merged.latest_event() else {
            panic!("latest event changed denial family");
        };
        assert_eq!(latest.peer_pid(), Some(pid(20)));

        aggregator.observe(&denial(3, Some(pid(20)), b"service\0two"));
        assert_eq!(aggregator.len(), 2);
    }

    #[test]
    fn unknown_bits_and_domain_membership_are_identity() {
        let signal = |target_domain| {
            Event::DenyScopeSignal(
                DenyScopeSignalEvent::builder()
                    .timestamp(KernelTimestamp::from_nanoseconds(1))
                    .context(context(1, 1, false, false))
                    .target_domain(target_domain)
                    .target_pid(pid(2))
                    .target_comm(string(b"target"))
                    .build(),
            )
        };
        let mut aggregator = DenialAggregator::new();
        aggregator.observe(&fs(1, 1, 1, 1, (1, 1, b"/a"), (false, false)));
        aggregator.observe(&fs(
            1,
            1,
            1,
            0x8000_0000_0000_0001,
            (1, 1, b"/a"),
            (false, false),
        ));
        aggregator.observe(&signal(DomainMembership::Unsandboxed));
        aggregator.observe(&signal(DomainMembership::Sandboxed(
            DomainId::new(MIN_LANDLOCK_ID + 2).unwrap(),
        )));
        assert_eq!(aggregator.len(), 4);
    }

    #[test]
    fn non_denials_are_ignored() {
        let mut aggregator = DenialAggregator::new();
        aggregator.observe(&Event::FreeDomain(
            FreeDomainEvent::builder()
                .timestamp(KernelTimestamp::from_nanoseconds(1))
                .domain_id(DomainId::new(MIN_LANDLOCK_ID + 1).unwrap())
                .denial_count(2)
                .build(),
        ));
        assert!(aggregator.is_empty());
        assert_eq!(aggregator.len(), 0);
        assert_eq!(aggregator.capacity(), 1000);
    }

    #[test]
    fn capacity_is_checked_and_exact() {
        let invalid = DenialAggregator::builder().capacity(0).build().unwrap_err();
        assert_eq!(
            invalid.kind(),
            DenialAggregatorBuildErrorKind::InvalidCapacity
        );
        assert_eq!(invalid.configured(), 0);
        assert_eq!(
            invalid.to_string(),
            "denial aggregation capacity must be nonzero"
        );
        assert!(invalid.source().is_none());
        assert_eq!(
            DenialAggregator::builder().build().unwrap().capacity(),
            1000
        );

        let mut aggregator = DenialAggregator::builder().capacity(1).build().unwrap();
        assert_eq!(aggregator.capacity(), 1);
        aggregator.observe(&fs(1, 1, 1, 1, (1, 1, b"/a"), (false, false)));
        aggregator.observe(&fs(1, 2, 1, 1, (1, 1, b"/b"), (false, false)));
        assert_eq!(aggregator.len(), 1);
        assert_eq!(
            aggregator.entries().next().unwrap().key().domain_id(),
            DomainId::new(MIN_LANDLOCK_ID + 2).unwrap()
        );
    }

    #[test]
    fn reservation_failure_is_structured_and_retains_its_source() {
        let error = DenialAggregator::builder()
            .capacity(usize::MAX)
            .build()
            .unwrap_err();
        assert_eq!(error.kind(), DenialAggregatorBuildErrorKind::Reservation);
        assert_eq!(error.configured(), usize::MAX);
        assert!(error.source().is_some());
    }

    #[test]
    fn counters_do_not_panic_at_their_numeric_limits() {
        let first = fs(1, 1, 1, 1, (1, 1, b"/first"), (false, false));
        let second = fs(1, 2, 1, 1, (1, 1, b"/second"), (false, false));
        let third = fs(1, 3, 1, 1, (1, 1, b"/third"), (false, false));
        let first_key = DenialKey::Filesystem(FilesystemDenialKey::new(
            DomainId::new(MIN_LANDLOCK_ID + 1).unwrap(),
            FilesystemAccess::from_bits(1),
            1,
            1,
        ));
        let second_key = DenialKey::Filesystem(FilesystemDenialKey::new(
            DomainId::new(MIN_LANDLOCK_ID + 2).unwrap(),
            FilesystemAccess::from_bits(1),
            1,
            1,
        ));
        let mut aggregator = DenialAggregator::builder().capacity(2).build().unwrap();
        aggregator.observe(&first);
        aggregator.observe(&second);
        aggregator
            .entries
            .get_mut(&first_key)
            .unwrap()
            .occurrence_count = u64::MAX;
        aggregator.observe(&first);
        aggregator.ingestion_sequence = u128::MAX;

        aggregator.observe(&third);

        assert_eq!(
            aggregator.get(&first_key).unwrap().occurrence_count(),
            u64::MAX
        );
        assert!(aggregator.get(&second_key).is_none());
    }

    #[test]
    fn lru_hits_refresh_recency_independently_of_timestamps() {
        let first = fs(7, 1, 1, 1, (1, 1, b"/first"), (false, false));
        let second = fs(7, 2, 1, 1, (1, 1, b"/second"), (false, false));
        let third = fs(7, 3, 1, 1, (1, 1, b"/third"), (false, false));
        let first_key = DenialKey::Filesystem(FilesystemDenialKey::new(
            DomainId::new(MIN_LANDLOCK_ID + 1).unwrap(),
            FilesystemAccess::from_bits(1),
            1,
            1,
        ));
        let second_key = DenialKey::Filesystem(FilesystemDenialKey::new(
            DomainId::new(MIN_LANDLOCK_ID + 2).unwrap(),
            FilesystemAccess::from_bits(1),
            1,
            1,
        ));
        let third_key = DenialKey::Filesystem(FilesystemDenialKey::new(
            DomainId::new(MIN_LANDLOCK_ID + 3).unwrap(),
            FilesystemAccess::from_bits(1),
            1,
            1,
        ));
        let mut aggregator = DenialAggregator::builder().capacity(2).build().unwrap();
        aggregator.observe(&first);
        aggregator.observe(&second);
        aggregator.observe(&first);
        aggregator.observe(&third);

        assert_eq!(aggregator.len(), 2);
        assert!(aggregator.get(&first_key).is_some());
        assert!(aggregator.get(&second_key).is_none());
        assert!(aggregator.get(&third_key).is_some());
        assert_eq!(aggregator.get(&first_key).unwrap().occurrence_count(), 2);
    }
}
