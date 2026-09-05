// SPDX-License-Identifier: MIT OR Apache-2.0

//! Semantic Landlock events and values.

mod access_names;
mod string;

pub use string::{CapturedString, CapturedStringError};

use access_names::{FILESYSTEM_ACCESS_NAMES, NETWORK_ACCESS_NAMES, SCOPE_NAMES};
use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::num::NonZeroU64;

/// The inclusive minimum ID assigned by the kernel to a Landlock ruleset or domain.
pub const MIN_LANDLOCK_ID: u64 = 0x1_0000_0000;

mod sealed {
    pub trait Sealed {}
}

/// A supported kind of kernel-assigned Landlock ID.
///
/// This trait is sealed and cannot be implemented outside this crate.
pub trait LandlockIdKind: sealed::Sealed {
    /// The kind-specific type name used to format an ID for debugging.
    const DEBUG_NAME: &'static str;
}

/// The marker kind for a Landlock domain ID.
#[derive(Debug)]
#[non_exhaustive]
pub struct Domain;

impl sealed::Sealed for Domain {}
impl LandlockIdKind for Domain {
    const DEBUG_NAME: &'static str = "DomainId";
}

/// The marker kind for a Landlock ruleset ID.
#[derive(Debug)]
#[non_exhaustive]
pub struct Ruleset;

impl sealed::Sealed for Ruleset {}
impl LandlockIdKind for Ruleset {
    const DEBUG_NAME: &'static str = "RulesetId";
}

/// An invalid kernel-assigned Landlock ID.
///
/// Linux allocates ruleset and domain IDs from a shared counter whose minimum
/// possible value is [`MIN_LANDLOCK_ID`]. Every smaller value is invalid;
/// notably, zero is reserved for an absent or unsandboxed domain relationship.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InvalidLandlockIdError {
    value: u64,
}

impl InvalidLandlockIdError {
    /// Returns the rejected value.
    pub const fn value(self) -> u64 {
        self.value
    }

    /// Returns the inclusive minimum valid value.
    pub const fn minimum(self) -> u64 {
        MIN_LANDLOCK_ID
    }
}

impl fmt::Display for InvalidLandlockIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid Landlock ID {}, expected at least {}",
            self.value, MIN_LANDLOCK_ID
        )
    }
}

impl Error for InvalidLandlockIdError {}

/// An ID assigned by the kernel to a Landlock ruleset or domain.
///
/// `K` distinguishes the two supported ID kinds at compile time. Values are at
/// least [`MIN_LANDLOCK_ID`].
#[non_exhaustive]
pub struct LandlockId<K: LandlockIdKind> {
    value: NonZeroU64,
    kind: PhantomData<fn() -> K>,
}

impl<K: LandlockIdKind> LandlockId<K> {
    /// Creates an ID from a kernel-assigned value.
    pub const fn new(value: u64) -> Result<Self, InvalidLandlockIdError> {
        if value < MIN_LANDLOCK_ID {
            return Err(InvalidLandlockIdError { value });
        }
        let value = NonZeroU64::new(value).expect("a valid Landlock ID must be nonzero");
        Ok(Self {
            value,
            kind: PhantomData,
        })
    }

    /// Returns the kernel-assigned ID.
    pub const fn get(self) -> u64 {
        self.value.get()
    }
}

impl<K: LandlockIdKind> TryFrom<u64> for LandlockId<K> {
    type Error = InvalidLandlockIdError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<K: LandlockIdKind> From<LandlockId<K>> for u64 {
    fn from(value: LandlockId<K>) -> Self {
        value.get()
    }
}

impl<K: LandlockIdKind> Clone for LandlockId<K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: LandlockIdKind> Copy for LandlockId<K> {}

impl fmt::Display for LandlockId<Domain> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:x}", self.get())
    }
}

impl<K: LandlockIdKind> fmt::Debug for LandlockId<K> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple(K::DEBUG_NAME)
            .field(&self.get())
            .finish()
    }
}

impl<K: LandlockIdKind> PartialEq for LandlockId<K> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<K: LandlockIdKind> Eq for LandlockId<K> {}

impl<K: LandlockIdKind> PartialOrd for LandlockId<K> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K: LandlockIdKind> Ord for LandlockId<K> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}

impl<K: LandlockIdKind> Hash for LandlockId<K> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

/// An ID assigned by the kernel to a Landlock domain.
///
/// [`Display`](fmt::Display) follows the kernel's lowercase hexadecimal
/// representation without `0x` or padding. Formatting flags are ignored to
/// keep this representation canonical.
pub type DomainId = LandlockId<Domain>;

/// An ID assigned by the kernel to a Landlock ruleset.
///
/// A bare ruleset ID intentionally does not implement [`Display`](fmt::Display)
/// because a complete ruleset reference also requires its version. Use
/// [`RulesetVersion`](crate::state::RulesetVersion) for display.
///
/// ```compile_fail
/// use landlock_observability::event::{RulesetId, MIN_LANDLOCK_ID};
///
/// let id = RulesetId::new(MIN_LANDLOCK_ID).unwrap();
/// let _ = format!("{id}");
/// ```
pub type RulesetId = LandlockId<Ruleset>;

/// A monotonic timestamp captured by the kernel, in nanoseconds.
///
/// This is a boot-relative clock reading, not wall-clock or UNIX time. Compare
/// it only with other observations from the same boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct KernelTimestamp(u64);

impl KernelTimestamp {
    /// Creates a timestamp from a monotonic nanosecond value.
    pub const fn from_nanoseconds(value: u64) -> Self {
        Self(value)
    }

    /// Returns the monotonic nanosecond value.
    pub const fn as_nanoseconds(self) -> u64 {
        self.0
    }
}

macro_rules! access_type {
    ($mask:ident, $name:ident, $table:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        #[non_exhaustive]
        pub struct $mask(u32);

        impl $mask {
            /// Creates a mask while preserving every bit.
            pub const fn from_bits(bits: u32) -> Self {
                Self(bits)
            }

            /// Returns every bit, including bits unknown to this library.
            pub const fn bits(self) -> u32 {
                self.0
            }

            /// Returns the set bits known to this library.
            pub fn known_bits(self) -> u32 {
                self.0 & $table.iter().fold(0, |bits, (bit, _)| bits | bit)
            }

            /// Returns the set bits unknown to this library.
            pub fn unknown_bits(self) -> u32 {
                self.0 & !$table.iter().fold(0, |bits, (bit, _)| bits | bit)
            }

            /// Iterates over known names whose bits are set.
            pub fn known_names(self) -> impl Iterator<Item = $name> {
                $table
                    .iter()
                    .filter(move |(bit, _)| self.0 & bit != 0)
                    .map(|(bit, name)| $name { bit: *bit, name })
            }

            /// Iterates over every known name in bit order.
            pub fn all_known_names() -> impl ExactSizeIterator<Item = $name> {
                $table.iter().map(|(bit, name)| $name { bit: *bit, name })
            }
        }

        #[doc = concat!("A known name in a ", $description)]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        #[non_exhaustive]
        pub struct $name {
            bit: u32,
            name: &'static str,
        }

        impl $name {
            /// Returns the single bit represented by this name.
            pub const fn bit(self) -> u32 {
                self.bit
            }

            /// Returns the unprefixed kernel name.
            pub const fn as_str(self) -> &'static str {
                self.name
            }
        }
    };
}

access_type!(
    FilesystemAccess,
    FilesystemAccessName,
    FILESYSTEM_ACCESS_NAMES,
    "filesystem access mask."
);
access_type!(
    NetworkAccess,
    NetworkAccessName,
    NETWORK_ACCESS_NAMES,
    "network access mask."
);
access_type!(ScopeAccess, ScopeAccessName, SCOPE_NAMES, "scope mask.");

/// Whether the other party was unsandboxed or belonged to a Landlock domain.
///
/// A complete event field is either the kernel's zero sentinel or one nonzero
/// domain ID, so these variants exhaust the possible membership states. This
/// type intentionally does not implement [`Display`](fmt::Display) because
/// consumers represent the unsandboxed state differently.
///
/// ```compile_fail
/// use landlock_observability::event::DomainMembership;
///
/// let membership = DomainMembership::Unsandboxed;
/// let _ = format!("{membership}");
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DomainMembership {
    /// The other party was unsandboxed at the decision point.
    Unsandboxed,
    /// The other party belonged to the contained nonzero Landlock domain.
    Sandboxed(DomainId),
}

impl DomainMembership {
    /// Returns the sandboxed identity, or `None` for an unsandboxed party.
    pub const fn domain_id(self) -> Option<DomainId> {
        match self {
            Self::Unsandboxed => None,
            Self::Sandboxed(id) => Some(id),
        }
    }
}

impl From<Option<DomainId>> for DomainMembership {
    fn from(value: Option<DomainId>) -> Self {
        match value {
            Some(id) => Self::Sandboxed(id),
            None => Self::Unsandboxed,
        }
    }
}

impl From<DomainMembership> for Option<DomainId> {
    fn from(value: DomainMembership) -> Self {
        value.domain_id()
    }
}

/// A captured domain hierarchy snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct HierarchySnapshot {
    domain_id: DomainId,
    parent_id: Option<DomainId>,
    creator_tgid: u32,
    creator_comm: CapturedString,
}

impl HierarchySnapshot {
    /// Creates a hierarchy snapshot.
    ///
    /// A present `parent_id` is expected to be nonzero; use `None` for a
    /// domain without a parent.
    pub fn new(
        domain_id: DomainId,
        parent_id: Option<DomainId>,
        creator_tgid: u32,
        creator_comm: CapturedString,
    ) -> Self {
        Self {
            domain_id,
            parent_id,
            creator_tgid,
            creator_comm,
        }
    }

    /// Returns the denying domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }
    /// Returns the parent, or `None` when the snapshot records no parent.
    pub const fn parent_id(&self) -> Option<DomainId> {
        self.parent_id
    }
    /// Returns the thread-group ID that created the domain.
    pub const fn creator_tgid(&self) -> u32 {
        self.creator_tgid
    }
    /// Returns the captured creator command.
    pub const fn creator_comm(&self) -> &CapturedString {
        &self.creator_comm
    }
}

/// Facts shared by all denial events.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DenialContext {
    hierarchy: HierarchySnapshot,
    cumulative_denial_count: u64,
    same_exec: bool,
    logged: bool,
}

impl DenialContext {
    /// Creates shared denial facts.
    pub fn new(
        hierarchy: HierarchySnapshot,
        cumulative_denial_count: u64,
        same_exec: bool,
        logged: bool,
    ) -> Self {
        Self {
            hierarchy,
            cumulative_denial_count,
            same_exec,
            logged,
        }
    }

    /// Returns the hierarchy snapshot.
    pub const fn hierarchy(&self) -> &HierarchySnapshot {
        &self.hierarchy
    }
    /// Returns the kernel's cumulative denial count.
    pub const fn cumulative_denial_count(&self) -> u64 {
        self.cumulative_denial_count
    }
    /// Returns whether the denial occurred in the creator's executable image.
    pub const fn same_exec(&self) -> bool {
        self.same_exec
    }
    /// Returns whether the kernel selected the denial for audit logging.
    pub const fn logged(&self) -> bool {
        self.logged
    }
}

macro_rules! common_event {
    ($type:ident) => {
        impl $type {
            /// Returns the event timestamp.
            pub const fn timestamp(&self) -> KernelTimestamp {
                self.timestamp
            }
        }
    };
}

/// A ruleset creation event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CreateRulesetEvent {
    timestamp: KernelTimestamp,
    ruleset_id: RulesetId,
    ruleset_version: u32,
    handled_fs: FilesystemAccess,
    handled_net: NetworkAccess,
    scoped: ScopeAccess,
}
impl CreateRulesetEvent {
    /// Creates an event.
    pub fn new(
        timestamp: KernelTimestamp,
        ruleset_id: RulesetId,
        ruleset_version: u32,
        handled_fs: FilesystemAccess,
        handled_net: NetworkAccess,
        scoped: ScopeAccess,
    ) -> Self {
        Self {
            timestamp,
            ruleset_id,
            ruleset_version,
            handled_fs,
            handled_net,
            scoped,
        }
    }
    /// Returns the kernel-assigned ruleset identity.
    pub const fn ruleset_id(&self) -> RulesetId {
        self.ruleset_id
    }
    /// Returns the ruleset version captured for this event.
    pub const fn ruleset_version(&self) -> u32 {
        self.ruleset_version
    }
    /// Returns the filesystem access rights handled by the ruleset.
    pub const fn handled_fs(&self) -> FilesystemAccess {
        self.handled_fs
    }
    /// Returns the network access rights handled by the ruleset.
    pub const fn handled_net(&self) -> NetworkAccess {
        self.handled_net
    }
    /// Returns the access rights scoped by the ruleset.
    pub const fn scoped(&self) -> ScopeAccess {
        self.scoped
    }
}
common_event!(CreateRulesetEvent);

/// A filesystem rule addition event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AddRuleFsEvent {
    timestamp: KernelTimestamp,
    ruleset_id: RulesetId,
    ruleset_version: u32,
    access_rights: FilesystemAccess,
    device: u32,
    inode: u64,
    pathname: CapturedString,
}
impl AddRuleFsEvent {
    /// Creates this semantic value from its captured fields.
    pub fn new(
        timestamp: KernelTimestamp,
        ruleset_id: RulesetId,
        ruleset_version: u32,
        access_rights: FilesystemAccess,
        device: u32,
        inode: u64,
        pathname: CapturedString,
    ) -> Self {
        Self {
            timestamp,
            ruleset_id,
            ruleset_version,
            access_rights,
            device,
            inode,
            pathname,
        }
    }
    /// Returns the kernel-assigned ruleset identity.
    pub const fn ruleset_id(&self) -> RulesetId {
        self.ruleset_id
    }
    /// Returns the ruleset version captured for this event.
    pub const fn ruleset_version(&self) -> u32 {
        self.ruleset_version
    }
    /// Returns the access rights allowed by the added rule.
    pub const fn access_rights(&self) -> FilesystemAccess {
        self.access_rights
    }
    /// Returns the captured filesystem device number.
    pub const fn device(&self) -> u32 {
        self.device
    }
    /// Returns the captured filesystem inode number.
    pub const fn inode(&self) -> u64 {
        self.inode
    }
    /// Returns the captured filesystem pathname.
    pub const fn pathname(&self) -> &CapturedString {
        &self.pathname
    }
}
common_event!(AddRuleFsEvent);

/// A network rule addition event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AddRuleNetEvent {
    timestamp: KernelTimestamp,
    ruleset_id: RulesetId,
    ruleset_version: u32,
    access_rights: NetworkAccess,
    port: u64,
}
impl AddRuleNetEvent {
    /// Creates this semantic value from its captured fields.
    pub const fn new(
        timestamp: KernelTimestamp,
        ruleset_id: RulesetId,
        ruleset_version: u32,
        access_rights: NetworkAccess,
        port: u64,
    ) -> Self {
        Self {
            timestamp,
            ruleset_id,
            ruleset_version,
            access_rights,
            port,
        }
    }
    /// Returns the kernel-assigned ruleset identity.
    pub const fn ruleset_id(&self) -> RulesetId {
        self.ruleset_id
    }
    /// Returns the ruleset version captured for this event.
    pub const fn ruleset_version(&self) -> u32 {
        self.ruleset_version
    }
    /// Returns the access rights allowed by the added rule.
    pub const fn access_rights(&self) -> NetworkAccess {
        self.access_rights
    }
    /// Returns the network-rule port supplied by the tracepoint.
    pub const fn port(&self) -> u64 {
        self.port
    }
}
common_event!(AddRuleNetEvent);

/// A domain creation event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CreateDomainEvent {
    timestamp: KernelTimestamp,
    ruleset_id: RulesetId,
    ruleset_version: u32,
    domain_id: DomainId,
    parent_id: Option<DomainId>,
    creator_tgid: u32,
    creator_comm: CapturedString,
}
impl CreateDomainEvent {
    /// Creates this semantic value from its captured fields.
    ///
    /// A present `parent_id` is expected to be nonzero; use `None` for a
    /// domain without a parent.
    pub fn new(
        timestamp: KernelTimestamp,
        ruleset_id: RulesetId,
        ruleset_version: u32,
        domain_id: DomainId,
        parent_id: Option<DomainId>,
        creator_tgid: u32,
        creator_comm: CapturedString,
    ) -> Self {
        Self {
            timestamp,
            ruleset_id,
            ruleset_version,
            domain_id,
            parent_id,
            creator_tgid,
            creator_comm,
        }
    }
    /// Returns the kernel-assigned ruleset identity.
    pub const fn ruleset_id(&self) -> RulesetId {
        self.ruleset_id
    }
    /// Returns the ruleset version frozen into the new domain.
    pub const fn ruleset_version(&self) -> u32 {
        self.ruleset_version
    }
    /// Returns the kernel-assigned domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }
    /// Returns the parent domain identity, or `None` for no parent.
    pub const fn parent_id(&self) -> Option<DomainId> {
        self.parent_id
    }
    /// Returns the thread-group ID of the task that created the domain.
    pub const fn creator_tgid(&self) -> u32 {
        self.creator_tgid
    }
    /// Returns the command name of the task that created the domain.
    pub const fn creator_comm(&self) -> &CapturedString {
        &self.creator_comm
    }
}
common_event!(CreateDomainEvent);

macro_rules! denial_common {
    ($type:ident) => {
        impl $type {
            /// Returns the monotonic kernel timestamp captured for this event.
            pub const fn timestamp(&self) -> KernelTimestamp {
                self.timestamp
            }
            /// Returns the hierarchy and kernel denial facts shared by denial events.
            pub const fn context(&self) -> &DenialContext {
                &self.context
            }
        }
    };
}

/// A filesystem access denial.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DenyAccessFsEvent {
    timestamp: KernelTimestamp,
    context: DenialContext,
    blockers: FilesystemAccess,
    device: u32,
    inode: u64,
    pathname: CapturedString,
}
impl DenyAccessFsEvent {
    /// Creates this semantic value from its captured fields.
    pub fn new(
        timestamp: KernelTimestamp,
        context: DenialContext,
        blockers: FilesystemAccess,
        device: u32,
        inode: u64,
        pathname: CapturedString,
    ) -> Self {
        Self {
            timestamp,
            context,
            blockers,
            device,
            inode,
            pathname,
        }
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
    /// Returns the captured filesystem pathname.
    pub const fn pathname(&self) -> &CapturedString {
        &self.pathname
    }
}
denial_common!(DenyAccessFsEvent);

/// A network access denial.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DenyAccessNetEvent {
    timestamp: KernelTimestamp,
    context: DenialContext,
    blockers: NetworkAccess,
    source_port: u64,
    destination_port: u64,
}
impl DenyAccessNetEvent {
    /// Creates this semantic value from its captured fields.
    pub const fn new(
        timestamp: KernelTimestamp,
        context: DenialContext,
        blockers: NetworkAccess,
        source_port: u64,
        destination_port: u64,
    ) -> Self {
        Self {
            timestamp,
            context,
            blockers,
            source_port,
            destination_port,
        }
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
denial_common!(DenyAccessNetEvent);

macro_rules! task_denial {
    (
        $type:ident,
        $description:literal,
        $domain:ident,
        $pid:ident,
        $comm:ident,
        $party:literal
    ) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, PartialEq)]
        #[non_exhaustive]
        pub struct $type {
            timestamp: KernelTimestamp,
            context: DenialContext,
            $domain: DomainMembership,
            $pid: u32,
            $comm: CapturedString,
        }
        impl $type {
            /// Creates this semantic value from its captured fields.
            pub fn new(
                timestamp: KernelTimestamp,
                context: DenialContext,
                $domain: DomainMembership,
                $pid: u32,
                $comm: CapturedString,
            ) -> Self {
                Self {
                    timestamp,
                    context,
                    $domain,
                    $pid,
                    $comm,
                }
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
        denial_common!($type);
    };
}
task_denial!(
    DenyPtraceEvent,
    "A ptrace denial.",
    tracee_domain,
    tracee_pid,
    tracee_comm,
    "tracee"
);
task_denial!(
    DenyScopeSignalEvent,
    "A signal denial.",
    target_domain,
    target_pid,
    target_comm,
    "target"
);

/// An abstract UNIX socket denial.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DenyScopeAbstractUnixSocketEvent {
    timestamp: KernelTimestamp,
    context: DenialContext,
    peer_domain: DomainMembership,
    peer_pid: u32,
}
impl DenyScopeAbstractUnixSocketEvent {
    /// Creates this semantic value from its captured fields.
    pub const fn new(
        timestamp: KernelTimestamp,
        context: DenialContext,
        peer_domain: DomainMembership,
        peer_pid: u32,
    ) -> Self {
        Self {
            timestamp,
            context,
            peer_domain,
            peer_pid,
        }
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
denial_common!(DenyScopeAbstractUnixSocketEvent);

/// A domain destruction event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct FreeDomainEvent {
    timestamp: KernelTimestamp,
    domain_id: DomainId,
    denial_count: u64,
}
impl FreeDomainEvent {
    /// Creates this semantic value from its captured fields.
    pub const fn new(timestamp: KernelTimestamp, domain_id: DomainId, denial_count: u64) -> Self {
        Self {
            timestamp,
            domain_id,
            denial_count,
        }
    }
    /// Returns the kernel-assigned domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }
    /// Returns the domain's final cumulative kernel denial count.
    pub const fn denial_count(&self) -> u64 {
        self.denial_count
    }
}
common_event!(FreeDomainEvent);

/// A ruleset destruction event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct FreeRulesetEvent {
    timestamp: KernelTimestamp,
    ruleset_id: RulesetId,
    ruleset_version: u32,
}
impl FreeRulesetEvent {
    /// Creates this semantic value from its captured fields.
    pub const fn new(
        timestamp: KernelTimestamp,
        ruleset_id: RulesetId,
        ruleset_version: u32,
    ) -> Self {
        Self {
            timestamp,
            ruleset_id,
            ruleset_version,
        }
    }
    /// Returns the kernel-assigned ruleset identity.
    pub const fn ruleset_id(&self) -> RulesetId {
        self.ruleset_id
    }
    /// Returns the ruleset's final version.
    pub const fn ruleset_version(&self) -> u32 {
        self.ruleset_version
    }
}
common_event!(FreeRulesetEvent);

/// A domain enforcement outcome event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct EnforceDomainEvent {
    timestamp: KernelTimestamp,
    domain_id: DomainId,
    enforcing_tid: u32,
    complete: bool,
    process_wide: bool,
    no_new_privs: bool,
}
impl EnforceDomainEvent {
    /// Creates this semantic value from its captured fields.
    pub const fn new(
        timestamp: KernelTimestamp,
        domain_id: DomainId,
        enforcing_tid: u32,
        complete: bool,
        process_wide: bool,
        no_new_privs: bool,
    ) -> Self {
        Self {
            timestamp,
            domain_id,
            enforcing_tid,
            complete,
            process_wide,
            no_new_privs,
        }
    }
    /// Returns the kernel-assigned domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }
    /// Returns the thread ID on which this enforcement outcome occurred.
    pub const fn enforcing_tid(&self) -> u32 {
        self.enforcing_tid
    }
    /// Returns whether this was the caller's concluding enforcement event.
    ///
    /// This does not claim that reconstructed domain state is complete.
    pub const fn complete(&self) -> bool {
        self.complete
    }
    /// Returns whether eligible sibling threads were covered or none existed.
    pub const fn process_wide(&self) -> bool {
        self.process_wide
    }
    /// Returns whether the enforcing thread had `no_new_privs` set.
    pub const fn no_new_privs(&self) -> bool {
        self.no_new_privs
    }
}
common_event!(EnforceDomainEvent);

/// An event kind not understood by this library.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct UnknownEvent {
    timestamp: KernelTimestamp,
    numeric_kind: u8,
    record_length: usize,
}
impl UnknownEvent {
    /// Creates an event for an unrecognized producer kind.
    ///
    /// An unknown event retains its numeric kind so a newer producer
    /// observation is not discarded.
    pub const fn new(timestamp: KernelTimestamp, numeric_kind: u8, record_length: usize) -> Self {
        Self {
            timestamp,
            numeric_kind,
            record_length,
        }
    }
    /// Returns the monotonic kernel timestamp captured for this event.
    pub const fn timestamp(&self) -> KernelTimestamp {
        self.timestamp
    }
    /// Returns the producer's unrecognized numeric event kind.
    pub const fn numeric_kind(&self) -> u8 {
        self.numeric_kind
    }
    /// Returns the captured record length carrying the unknown kind.
    pub const fn record_length(&self) -> usize {
        self.record_length
    }
}

/// A semantic Landlock observation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Event {
    /// A ruleset was created.
    CreateRuleset(CreateRulesetEvent),
    /// A filesystem rule was added.
    AddRuleFs(AddRuleFsEvent),
    /// A network rule was added.
    AddRuleNet(AddRuleNetEvent),
    /// A domain was created.
    CreateDomain(CreateDomainEvent),
    /// Filesystem access was denied.
    DenyAccessFs(DenyAccessFsEvent),
    /// Network access was denied.
    DenyAccessNet(DenyAccessNetEvent),
    /// Ptrace access was denied.
    DenyPtrace(DenyPtraceEvent),
    /// Signal delivery was denied.
    DenyScopeSignal(DenyScopeSignalEvent),
    /// Abstract UNIX socket communication was denied.
    DenyScopeAbstractUnixSocket(DenyScopeAbstractUnixSocketEvent),
    /// A domain was freed.
    FreeDomain(FreeDomainEvent),
    /// A ruleset was freed.
    FreeRuleset(FreeRulesetEvent),
    /// A domain was enforced on a thread.
    EnforceDomain(EnforceDomainEvent),
    /// The producer supplied an event kind unknown to this library.
    Unknown(UnknownEvent),
}

impl Event {
    /// Returns the monotonic kernel timestamp captured for this event.
    pub const fn timestamp(&self) -> KernelTimestamp {
        match self {
            Self::CreateRuleset(event) => event.timestamp(),
            Self::AddRuleFs(event) => event.timestamp(),
            Self::AddRuleNet(event) => event.timestamp(),
            Self::CreateDomain(event) => event.timestamp(),
            Self::DenyAccessFs(event) => event.timestamp(),
            Self::DenyAccessNet(event) => event.timestamp(),
            Self::DenyPtrace(event) => event.timestamp(),
            Self::DenyScopeSignal(event) => event.timestamp(),
            Self::DenyScopeAbstractUnixSocket(event) => event.timestamp(),
            Self::FreeDomain(event) => event.timestamp(),
            Self::FreeRuleset(event) => event.timestamp(),
            Self::EnforceDomain(event) => event.timestamp(),
            Self::Unknown(event) => event.timestamp(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_names_and_unknown_bits() {
        let fs = FilesystemAccess::from_bits(u32::MAX);
        let network = NetworkAccess::from_bits((1 << 31) | 0b0101);
        let scope = ScopeAccess::from_bits((1 << 31) | 0b10);

        assert_eq!(FilesystemAccess::all_known_names().count(), 17);
        assert_eq!(NetworkAccess::all_known_names().count(), 4);
        assert_eq!(ScopeAccess::all_known_names().count(), 2);
        assert_eq!(fs.known_names().count(), 17);
        assert_eq!(fs.known_bits(), 0x1ffff);
        assert_eq!(fs.unknown_bits(), 0xfffe0000);
        assert_eq!(network.bits(), 0x80000005);
        assert_eq!(network.known_bits(), 5);
        assert_eq!(network.unknown_bits(), 1 << 31);
        assert_eq!(scope.known_bits(), 2);
        assert_eq!(scope.unknown_bits(), 1 << 31);
        assert_eq!(
            network
                .known_names()
                .map(|name| (name.bit(), name.as_str()))
                .collect::<Vec<_>>(),
            vec![(1, "bind_tcp"), (4, "bind_udp")]
        );
    }

    #[test]
    fn landlock_id_boundaries_and_conversions() {
        for value in [0, 1, u32::MAX as u64] {
            let error = DomainId::new(value).unwrap_err();
            assert_eq!(error.value(), value);
            assert_eq!(error.minimum(), MIN_LANDLOCK_ID);
            assert_eq!(DomainId::try_from(value), Err(error));
        }

        let minimum = DomainId::new(MIN_LANDLOCK_ID).unwrap();
        let maximum = DomainId::try_from(u64::MAX).unwrap();
        assert_eq!(minimum.get(), MIN_LANDLOCK_ID);
        assert_eq!(u64::from(maximum), u64::MAX);
        assert!(minimum < maximum);
        assert_eq!(minimum.to_string(), "100000000");
        assert_eq!(maximum.to_string(), "ffffffffffffffff");
        assert_eq!(format!("{minimum:#020}"), "100000000");
        assert_eq!(format!("{minimum:*>20}"), "100000000");
        assert_eq!(format!("{minimum:?}"), "DomainId(4294967296)");
        assert_eq!(
            DomainId::new(u32::MAX as u64).unwrap_err().to_string(),
            "invalid Landlock ID 4294967295, expected at least 4294967296"
        );

        let ruleset = RulesetId::new(MIN_LANDLOCK_ID).unwrap();
        assert_eq!(ruleset.get(), minimum.get());
        assert_eq!(format!("{ruleset:?}"), "RulesetId(4294967296)");
    }

    #[test]
    fn domain_membership_option_conversions_are_total() {
        let id = DomainId::new(MIN_LANDLOCK_ID).unwrap();
        assert_eq!(DomainMembership::from(None), DomainMembership::Unsandboxed);
        assert_eq!(DomainMembership::from(Some(id)).domain_id(), Some(id));
        assert_eq!(
            Option::<DomainId>::from(DomainMembership::Unsandboxed),
            None
        );
        assert_eq!(
            Option::<DomainId>::from(DomainMembership::Sandboxed(id)),
            Some(id)
        );
        assert_eq!(KernelTimestamp::from_nanoseconds(11).as_nanoseconds(), 11);
    }
}
