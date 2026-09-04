// SPDX-License-Identifier: MIT OR Apache-2.0

//! Optional bounded aggregation of Landlock denial events.

use crate::event::{
    CapturedString, DomainId, DomainMembership, Event, FilesystemAccess, KernelTimestamp,
    NetworkAccess,
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
    blockers: FilesystemAccess,
    device: u32,
    inode: u64,
}

impl FilesystemDenialKey {
    /// Creates a filesystem denial key.
    pub const fn new(
        domain_id: DomainId,
        blockers: FilesystemAccess,
        device: u32,
        inode: u64,
    ) -> Self {
        Self {
            domain_id,
            blockers,
            device,
            inode,
        }
    }

    /// Returns the denying domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    /// Returns the access rights that blocked the operation.
    pub const fn blockers(&self) -> FilesystemAccess {
        self.blockers
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
    blockers: NetworkAccess,
    source_port: u64,
    destination_port: u64,
}

impl NetworkDenialKey {
    /// Creates a network denial key.
    pub const fn new(
        domain_id: DomainId,
        blockers: NetworkAccess,
        source_port: u64,
        destination_port: u64,
    ) -> Self {
        Self {
            domain_id,
            blockers,
            source_port,
            destination_port,
        }
    }

    /// Returns the denying domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    /// Returns the access rights that blocked the operation.
    pub const fn blockers(&self) -> NetworkAccess {
        self.blockers
    }

    /// Returns the bind-side source port captured by the tracepoint.
    pub const fn source_port(&self) -> u64 {
        self.source_port
    }

    /// Returns the connect or send-side destination port captured by the tracepoint.
    pub const fn destination_port(&self) -> u64 {
        self.destination_port
    }
}

macro_rules! task_denial_key {
    (
        $type:ident,
        $description:literal,
        $domain:ident,
        $pid:ident,
        $comm:ident,
        $party:literal
    ) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        #[non_exhaustive]
        pub struct $type {
            domain_id: DomainId,
            $domain: DomainMembership,
            $pid: u32,
            $comm: CapturedString,
        }

        impl $type {
            /// Creates a task denial key.
            pub fn new(
                domain_id: DomainId,
                $domain: DomainMembership,
                $pid: u32,
                $comm: CapturedString,
            ) -> Self {
                Self {
                    domain_id,
                    $domain,
                    $pid,
                    $comm,
                }
            }

            /// Returns the denying domain identity.
            pub const fn domain_id(&self) -> DomainId {
                self.domain_id
            }

            #[doc = concat!("Returns whether the ", $party, " was unsandboxed or in a domain.")]
            pub const fn $domain(&self) -> DomainMembership {
                self.$domain
            }

            #[doc = concat!("Returns the thread-group ID of the ", $party, " task.")]
            pub const fn $pid(&self) -> u32 {
                self.$pid
            }

            #[doc = concat!("Returns the captured command name of the ", $party, " task.")]
            pub const fn $comm(&self) -> &CapturedString {
                &self.$comm
            }
        }
    };
}

task_denial_key!(
    PtraceDenialKey,
    "A ptrace denial aggregation key. The captured tracee command is part of the identity.",
    tracee_domain,
    tracee_pid,
    tracee_comm,
    "tracee"
);
task_denial_key!(
    SignalDenialKey,
    "A signal denial aggregation key. The captured target command is part of the identity.",
    target_domain,
    target_pid,
    target_comm,
    "target"
);

/// An abstract UNIX socket denial aggregation key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct AbstractUnixSocketDenialKey {
    domain_id: DomainId,
    peer_domain: DomainMembership,
    peer_pid: u32,
}

impl AbstractUnixSocketDenialKey {
    /// Creates an abstract UNIX socket denial key.
    pub const fn new(domain_id: DomainId, peer_domain: DomainMembership, peer_pid: u32) -> Self {
        Self {
            domain_id,
            peer_domain,
            peer_pid,
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

    /// Returns the socket peer PID captured by the kernel.
    pub const fn peer_pid(&self) -> u32 {
        self.peer_pid
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

/// The error returned when an aggregation capacity is zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InvalidCapacityError;

impl fmt::Display for InvalidCapacityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("denial aggregation capacity must be nonzero")
    }
}

impl Error for InvalidCapacityError {}

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
    pub fn new() -> Self {
        Self {
            capacity: DEFAULT_CAPACITY,
            entries: HashMap::new(),
            ingestion_sequence: 0,
        }
    }

    /// Creates an empty aggregator with the exact nonzero `capacity`.
    pub fn with_capacity(capacity: usize) -> Result<Self, InvalidCapacityError> {
        if capacity == 0 {
            return Err(InvalidCapacityError);
        }
        Ok(Self {
            capacity,
            entries: HashMap::with_capacity(capacity),
            ingestion_sequence: 0,
        })
    }

    /// Observes an event, aggregating it when it is a concrete denial.
    ///
    /// Non-denial events and [`Event::Unknown`] are ignored. Every matching hit
    /// refreshes least-recently-observed recency. Inserting a new key while full
    /// evicts the key whose matching event was ingested least recently.
    pub fn observe(&mut self, event: &Event) {
        let _ = self.observe_entry(event);
    }

    /// Observes an event and returns the affected retained entry for a denial.
    ///
    /// Non-denial events and [`Event::Unknown`] return `None`. The returned
    /// entry already contains the current observation.
    pub fn observe_entry(&mut self, event: &Event) -> Option<&AggregatedDenial> {
        let (key, same_exec, logged) = denial_facts(event)?;
        let sequence = self.next_ingestion_sequence();

        if self.entries.contains_key(&key) {
            let entry = self
                .entries
                .get_mut(&key)
                .expect("a checked aggregation entry remains present");
            entry.occurrence_count = entry.occurrence_count.saturating_add(1);
            entry.latest_timestamp = event.timestamp();
            entry.same_exec = same_exec;
            entry.logged = logged;
            entry.latest_event = event.clone();
            entry.last_observed_sequence = sequence;
            return Some(entry);
        }

        if self.entries.len() == self.capacity {
            let least_recent_key = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_observed_sequence)
                .map(|(key, _)| key.clone())
                .expect("a full denial aggregator contains an entry");
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
            let mut recency = self
                .entries
                .iter()
                .map(|(key, entry)| (key.clone(), entry.last_observed_sequence))
                .collect::<Vec<_>>();
            recency.sort_unstable_by_key(|(_, sequence)| *sequence);
            for (index, (key, _)) in recency.iter().enumerate() {
                self.entries
                    .get_mut(key)
                    .expect("recency keys come from the aggregation map")
                    .last_observed_sequence = index as u128 + 1;
            }
            self.ingestion_sequence = recency.len() as u128;
        }
        self.ingestion_sequence += 1;
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
                denial.blockers(),
                denial.device(),
                denial.inode(),
            )),
            denial.context(),
        ),
        Event::DenyAccessNet(denial) => (
            DenialKey::Network(NetworkDenialKey::new(
                denial.context().hierarchy().domain_id(),
                denial.blockers(),
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
                denial.peer_pid(),
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
    use crate::event::{
        DenialContext, DenyAccessFsEvent, DenyAccessNetEvent, DenyPtraceEvent,
        DenyScopeAbstractUnixSocketEvent, DenyScopeSignalEvent, FreeDomainEvent, HierarchySnapshot,
        UnknownEvent,
    };

    fn string(value: &[u8]) -> CapturedString {
        CapturedString::new(value.to_vec(), false).unwrap()
    }

    fn context(domain: u64, cumulative: u64, same_exec: bool, logged: bool) -> DenialContext {
        DenialContext::new(
            HierarchySnapshot::new(DomainId::new(domain), None, 10, string(b"creator")),
            cumulative,
            same_exec,
            logged,
        )
    }

    fn fs(
        timestamp: u64,
        domain: u64,
        cumulative: u64,
        blockers: u32,
        target: (u32, u64, &[u8]),
        flags: (bool, bool),
    ) -> Event {
        Event::DenyAccessFs(DenyAccessFsEvent::new(
            KernelTimestamp::from_nanoseconds(timestamp),
            context(domain, cumulative, flags.0, flags.1),
            FilesystemAccess::from_bits(blockers),
            target.0,
            target.1,
            string(target.2),
        ))
    }

    fn network(timestamp: u64, domain: u64, blockers: u32, ports: (u64, u64)) -> Event {
        Event::DenyAccessNet(DenyAccessNetEvent::new(
            KernelTimestamp::from_nanoseconds(timestamp),
            context(domain, 1, false, true),
            NetworkAccess::from_bits(blockers),
            ports.0,
            ports.1,
        ))
    }

    #[test]
    fn keys_cover_all_denial_families_and_fields() {
        let ptrace = Event::DenyPtrace(DenyPtraceEvent::new(
            KernelTimestamp::from_nanoseconds(3),
            context(12, 1, false, false),
            DomainMembership::Sandboxed(DomainId::new(20)),
            30,
            string(b"tracee"),
        ));
        let signal = Event::DenyScopeSignal(DenyScopeSignalEvent::new(
            KernelTimestamp::from_nanoseconds(4),
            context(13, 1, false, false),
            DomainMembership::Unsandboxed,
            31,
            string(b"target"),
        ));
        let unix = Event::DenyScopeAbstractUnixSocket(DenyScopeAbstractUnixSocketEvent::new(
            KernelTimestamp::from_nanoseconds(5),
            context(14, 1, false, false),
            DomainMembership::Sandboxed(DomainId::new(21)),
            32,
        ));
        let mut aggregator = DenialAggregator::new();
        aggregator.observe(&fs(1, 10, 1, 0x8000_0001, (2, 3, b"/a"), (false, false)));
        aggregator.observe(&network(2, 11, 0x8000_0002, (100, 200)));
        aggregator.observe(&ptrace);
        aggregator.observe(&signal);
        aggregator.observe(&unix);

        assert_eq!(aggregator.len(), 5);
        let fs_key = DenialKey::Filesystem(FilesystemDenialKey::new(
            DomainId::new(10),
            FilesystemAccess::from_bits(0x8000_0001),
            2,
            3,
        ));
        let network_key = DenialKey::Network(NetworkDenialKey::new(
            DomainId::new(11),
            NetworkAccess::from_bits(0x8000_0002),
            100,
            200,
        ));
        let ptrace_key = DenialKey::Ptrace(PtraceDenialKey::new(
            DomainId::new(12),
            DomainMembership::Sandboxed(DomainId::new(20)),
            30,
            string(b"tracee"),
        ));
        let signal_key = DenialKey::Signal(SignalDenialKey::new(
            DomainId::new(13),
            DomainMembership::Unsandboxed,
            31,
            string(b"target"),
        ));
        let unix_key = DenialKey::AbstractUnixSocket(AbstractUnixSocketDenialKey::new(
            DomainId::new(14),
            DomainMembership::Sandboxed(DomainId::new(21)),
            32,
        ));
        assert!(aggregator.get(&fs_key).is_some());
        assert!(aggregator.get(&network_key).is_some());
        assert!(aggregator.get(&ptrace_key).is_some());
        assert!(aggregator.get(&signal_key).is_some());
        assert!(aggregator.get(&unix_key).is_some());
        assert_eq!(fs_key.domain_id(), DomainId::new(10));

        let DenialKey::Filesystem(key) = fs_key else {
            panic!("filesystem key changed variant");
        };
        assert_eq!(key.blockers().bits(), 0x8000_0001);
        assert_eq!((key.device(), key.inode()), (2, 3));
        let DenialKey::Network(key) = network_key else {
            panic!("network key changed variant");
        };
        assert_eq!(key.blockers().bits(), 0x8000_0002);
        assert_eq!((key.source_port(), key.destination_port()), (100, 200));
        let DenialKey::Ptrace(key) = ptrace_key else {
            panic!("ptrace key changed variant");
        };
        assert_eq!(
            key.tracee_domain(),
            DomainMembership::Sandboxed(DomainId::new(20))
        );
        assert_eq!(key.tracee_pid(), 30);
        assert_eq!(key.tracee_comm().as_bytes(), b"tracee");
        let DenialKey::Signal(key) = signal_key else {
            panic!("signal key changed variant");
        };
        assert_eq!(key.target_domain(), DomainMembership::Unsandboxed);
        assert_eq!(key.target_pid(), 31);
        assert_eq!(key.target_comm().as_bytes(), b"target");
        let DenialKey::AbstractUnixSocket(key) = unix_key else {
            panic!("abstract UNIX key changed variant");
        };
        assert_eq!(
            key.peer_domain(),
            DomainMembership::Sandboxed(DomainId::new(21))
        );
        assert_eq!(key.peer_pid(), 32);
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
                Event::DenyScopeSignal(DenyScopeSignalEvent::new(
                    timestamp,
                    context,
                    domain_membership,
                    task_pid,
                    string(task_comm),
                ))
            } else {
                Event::DenyPtrace(DenyPtraceEvent::new(
                    timestamp,
                    context,
                    domain_membership,
                    task_pid,
                    string(task_comm),
                ))
            }
        };
        let unix_denial = |peer_domain, peer_pid| {
            Event::DenyScopeAbstractUnixSocket(DenyScopeAbstractUnixSocketEvent::new(
                KernelTimestamp::from_nanoseconds(1),
                context(1, 1, false, false),
                peer_domain,
                peer_pid,
            ))
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
            task_denial(false, DomainMembership::Unsandboxed, 1, b"task"),
            task_denial(true, DomainMembership::Unsandboxed, 1, b"task"),
            task_denial(
                false,
                DomainMembership::Sandboxed(DomainId::new(2)),
                1,
                b"task",
            ),
            task_denial(false, DomainMembership::Unsandboxed, 2, b"task"),
            task_denial(false, DomainMembership::Unsandboxed, 1, b"other"),
            unix_denial(DomainMembership::Unsandboxed, 1),
            unix_denial(DomainMembership::Sandboxed(DomainId::new(2)), 1),
            unix_denial(DomainMembership::Unsandboxed, 2),
        ];
        let mut aggregator = DenialAggregator::new();
        for event in &events {
            aggregator.observe(event);
        }
        assert_eq!(aggregator.len(), events.len());
    }

    #[test]
    fn unknown_bits_and_domain_membership_are_identity() {
        let signal = |target_domain| {
            Event::DenyScopeSignal(DenyScopeSignalEvent::new(
                KernelTimestamp::from_nanoseconds(1),
                context(1, 1, false, false),
                target_domain,
                2,
                string(b"target"),
            ))
        };
        let mut aggregator = DenialAggregator::new();
        aggregator.observe(&fs(1, 1, 1, 1, (1, 1, b"/a"), (false, false)));
        aggregator.observe(&fs(1, 1, 1, 0x8000_0001, (1, 1, b"/a"), (false, false)));
        aggregator.observe(&signal(DomainMembership::Unsandboxed));
        aggregator.observe(&signal(DomainMembership::Sandboxed(DomainId::new(2))));
        assert_eq!(aggregator.len(), 4);
    }

    #[test]
    fn non_denials_and_unknown_events_are_ignored() {
        let mut aggregator = DenialAggregator::new();
        aggregator.observe(&Event::FreeDomain(FreeDomainEvent::new(
            KernelTimestamp::from_nanoseconds(1),
            DomainId::new(1),
            2,
        )));
        aggregator.observe(&Event::Unknown(UnknownEvent::new(
            KernelTimestamp::from_nanoseconds(2),
            99,
            344,
        )));
        assert!(aggregator.is_empty());
        assert_eq!(aggregator.len(), 0);
        assert_eq!(aggregator.capacity(), 1000);
    }

    #[test]
    fn capacity_is_checked_and_exact() {
        assert_eq!(
            DenialAggregator::with_capacity(0).unwrap_err(),
            InvalidCapacityError
        );
        assert_eq!(
            InvalidCapacityError.to_string(),
            "denial aggregation capacity must be nonzero"
        );

        let mut aggregator = DenialAggregator::with_capacity(1).unwrap();
        assert_eq!(aggregator.capacity(), 1);
        aggregator.observe(&fs(1, 1, 1, 1, (1, 1, b"/a"), (false, false)));
        aggregator.observe(&fs(1, 2, 1, 1, (1, 1, b"/b"), (false, false)));
        assert_eq!(aggregator.len(), 1);
        assert_eq!(
            aggregator.entries().next().unwrap().key().domain_id(),
            DomainId::new(2)
        );
    }

    #[test]
    fn counters_do_not_panic_at_their_numeric_limits() {
        let first = fs(1, 1, 1, 1, (1, 1, b"/first"), (false, false));
        let second = fs(1, 2, 1, 1, (1, 1, b"/second"), (false, false));
        let third = fs(1, 3, 1, 1, (1, 1, b"/third"), (false, false));
        let first_key = DenialKey::Filesystem(FilesystemDenialKey::new(
            DomainId::new(1),
            FilesystemAccess::from_bits(1),
            1,
            1,
        ));
        let second_key = DenialKey::Filesystem(FilesystemDenialKey::new(
            DomainId::new(2),
            FilesystemAccess::from_bits(1),
            1,
            1,
        ));
        let mut aggregator = DenialAggregator::with_capacity(2).unwrap();
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
            DomainId::new(1),
            FilesystemAccess::from_bits(1),
            1,
            1,
        ));
        let second_key = DenialKey::Filesystem(FilesystemDenialKey::new(
            DomainId::new(2),
            FilesystemAccess::from_bits(1),
            1,
            1,
        ));
        let third_key = DenialKey::Filesystem(FilesystemDenialKey::new(
            DomainId::new(3),
            FilesystemAccess::from_bits(1),
            1,
            1,
        ));
        let mut aggregator = DenialAggregator::with_capacity(2).unwrap();
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
