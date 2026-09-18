// SPDX-License-Identifier: MIT OR Apache-2.0

//! Semantic Landlock events and values.

mod access_names;
mod string;

pub use string::{
    AbstractUnixSocketNameOrigin, CapturedAbstractUnixSocketName, CapturedBytes,
    CapturedBytesError, CapturedBytesOrigin, CapturedCommand, CapturedPath, CommandOrigin,
    PathnameOrigin,
};

use access_names::{FILESYSTEM_ACCESS_NAMES, NETWORK_ACCESS_NAMES, SCOPE_NAMES};
use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::num::{NonZeroU32, NonZeroU64};

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
        match NonZeroU64::new(value) {
            Some(value) if value.get() >= MIN_LANDLOCK_ID => Ok(Self {
                value,
                kind: PhantomData,
            }),
            _ => Err(InvalidLandlockIdError { value }),
        }
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

/// An invalid Linux process or thread ID.
///
/// Zero is not a valid process or thread identity.  Optional kernel fields use
/// an outer [`Option`] instead of constructing a zero ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct InvalidTaskIdError {
    value: u32,
}

impl InvalidTaskIdError {
    /// Returns the rejected zero value.
    pub const fn value(self) -> u32 {
        self.value
    }
}

impl fmt::Display for InvalidTaskIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid Linux task ID {}, expected a nonzero value",
            self.value
        )
    }
}

impl Error for InvalidTaskIdError {}

macro_rules! task_id_type {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        ///
        /// Values are nonzero IDs from Linux's initial PID namespace.  The
        /// nonzero storage is private and no stable memory representation is
        /// promised.
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[non_exhaustive]
        pub struct $name {
            value: NonZeroU32,
        }

        impl $name {
            /// Creates an ID from a nonzero kernel-assigned value.
            pub const fn new(value: u32) -> Result<Self, InvalidTaskIdError> {
                match NonZeroU32::new(value) {
                    Some(value) => Ok(Self { value }),
                    None => Err(InvalidTaskIdError { value }),
                }
            }

            /// Returns the kernel-assigned ID.
            pub const fn get(self) -> u32 {
                self.value.get()
            }
        }

        impl TryFrom<u32> for $name {
            type Error = InvalidTaskIdError;

            fn try_from(value: u32) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for u32 {
            fn from(value: $name) -> Self {
                value.get()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.get())
                    .finish()
            }
        }
    };
}

task_id_type!(ProcessId, "A Linux process (thread-group) identity.");
task_id_type!(ThreadId, "A Linux thread identity.");

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
    creator_tgid: ProcessId,
    creator_comm: CapturedCommand,
}

impl HierarchySnapshot {
    /// Returns the denying domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }
    /// Returns the parent, or `None` when the snapshot records no parent.
    pub const fn parent_id(&self) -> Option<DomainId> {
        self.parent_id
    }
    /// Returns the process ID that created the domain.
    pub const fn creator_tgid(&self) -> ProcessId {
        self.creator_tgid
    }
    /// Returns the captured creator command.
    pub const fn creator_comm(&self) -> &CapturedCommand {
        &self.creator_comm
    }
}

/// Facts shared by all denial events.
///
/// # Compile-time field checks
///
/// Missing required fields prevent building:
///
/// ```compile_fail
/// use landlock_observability::event::DenialContext;
///
/// DenialContext::builder().same_exec(false).logged(true).build();
/// ```
///
/// A field cannot be supplied twice:
///
/// ```compile_fail
/// use landlock_observability::event::DenialContext;
///
/// DenialContext::builder().same_exec(false).same_exec(true);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DenialContext {
    hierarchy: HierarchySnapshot,
    cumulative_denial_count: u64,
    same_exec: bool,
    logged: bool,
}

impl DenialContext {
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

/// A timestamped semantic observation.
///
/// This trait is sealed and cannot be implemented outside this crate.
pub trait Observation: sealed::Sealed {
    /// Returns the monotonic kernel timestamp captured for this observation.
    fn timestamp(&self) -> KernelTimestamp;
}

/// A semantic denial observation.
///
/// This trait is sealed and cannot be implemented outside this crate.
pub trait Denial: Observation {
    /// Returns the hierarchy and kernel denial facts shared by denial events.
    fn context(&self) -> &DenialContext;
}

/// A field that has not yet been supplied to a typestate builder.
///
/// Builders use this public typestate marker to make missing required fields a
/// compile-time error. It cannot be constructed outside this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Missing;

/// A field that has been supplied to a typestate builder.
///
/// Builders use this public typestate marker to prevent a required field from
/// being supplied more than once. Its value is intentionally private.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Present<T>(T);

impl<T> Present<T> {
    fn into_inner(self) -> T {
        self.0
    }
}

macro_rules! typestate_builder_setters {
    (
        $builder:ident;
        [];
        $field:ident : $state:ident => $value:ty, $setter_doc:literal;
        $($after_field:ident : $after_state:ident => $after_value:ty, $after_doc:literal;)*
    ) => {
        typestate_builder_setters!(
            $builder;
            [];
            $field : $state => $value, $setter_doc;
            [$($after_field : $after_state => $after_value, $after_doc;)*]
        );
    };
    (
        $builder:ident;
        [$($before_field:ident : $before_state:ident),*];
        $field:ident : $state:ident => $value:ty, $setter_doc:literal;
        [$($after_field:ident : $after_state:ident => $after_value:ty, $after_doc:literal;)*]
    ) => {
        impl<$($before_state,)* $($after_state,)*>
            $builder<$($before_state,)* Missing, $($after_state,)*>
        {
            #[doc = $setter_doc]
            pub fn $field(
                self,
                value: $value,
            ) -> $builder<$($before_state,)* Present<$value>, $($after_state,)*> {
                let Self {
                    $($before_field,)*
                    $field: _,
                    $($after_field,)*
                } = self;
                $builder {
                    $($before_field,)*
                    $field: Present(value),
                    $($after_field,)*
                }
            }
        }

        typestate_builder_setters!(
            @next $builder;
            [$($before_field : $before_state,)* $field : $state];
            [$($after_field : $after_state => $after_value, $after_doc;)*]
        );
    };
    (
        @next $builder:ident;
        [$($before:tt)*];
        [$field:ident : $state:ident => $value:ty, $setter_doc:literal;
         $($after:tt)*]
    ) => {
        typestate_builder_setters!(
            $builder;
            [$($before)*];
            $field : $state => $value, $setter_doc;
            [$($after)*]
        );
    };
    (@next $builder:ident; [$($before:tt)*]; []) => {};
}

macro_rules! typestate_builder {
    (
        $target:ident, $builder:ident, $builder_doc:literal;
        $($field:ident : $state:ident => $value:ty, $setter_doc:literal;)+
    ) => {
        #[doc = $builder_doc]
        ///
        /// Each required field has a named setter. Setters may be called in
        /// any order, and [`build()`](Self::build) is available only after
        /// every field has been supplied.
        #[derive(Clone, Debug, Eq, PartialEq)]
        #[non_exhaustive]
        pub struct $builder<$($state = Missing),+> {
            $($field: $state),+
        }

        impl $target {
            /// Returns an argument-free builder for this value.
            pub fn builder() -> $builder {
                $builder {
                    $($field: Missing),+
                }
            }
        }

        typestate_builder_setters!(
            $builder;
            [];
            $($field : $state => $value, $setter_doc;)+
        );

        impl $builder<$(Present<$value>),+> {
            /// Builds the value after every required field has been supplied.
            pub fn build(self) -> $target {
                $target {
                    $($field: self.$field.into_inner()),+
                }
            }
        }
    };
}

typestate_builder!(
    HierarchySnapshot, HierarchySnapshotBuilder, "A typestate builder for [`HierarchySnapshot`].";
    domain_id: DomainIdState => DomainId, "Sets the denying domain identity.";
    parent_id: ParentId => Option<DomainId>, "Sets the parent domain identity, or `None` for no parent.";
    creator_tgid: CreatorTgid => ProcessId, "Sets the process ID that created the domain.";
    creator_comm: CreatorComm => CapturedCommand, "Sets the captured creator command.";
);
typestate_builder!(
    DenialContext, DenialContextBuilder, "A typestate builder for [`DenialContext`].";
    hierarchy: Hierarchy => HierarchySnapshot, "Sets the hierarchy snapshot.";
    cumulative_denial_count: CumulativeDenialCount => u64, "Sets the kernel's cumulative denial count.";
    same_exec: SameExec => bool, "Sets whether the denial occurred in the creator's executable image.";
    logged: Logged => bool, "Sets whether the kernel selected the denial for audit logging.";
);

/// A ruleset creation event.
///
/// # Compile-time field checks
///
/// Missing required fields prevent building:
///
/// ```compile_fail
/// use landlock_observability::event::{CreateRulesetEvent, KernelTimestamp};
///
/// CreateRulesetEvent::builder()
///     .timestamp(KernelTimestamp::from_nanoseconds(1))
///     .build();
/// ```
///
/// A field cannot be supplied twice:
///
/// ```compile_fail
/// use landlock_observability::event::{CreateRulesetEvent, KernelTimestamp};
///
/// CreateRulesetEvent::builder()
///     .timestamp(KernelTimestamp::from_nanoseconds(1))
///     .timestamp(KernelTimestamp::from_nanoseconds(2));
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CreateRulesetEvent {
    timestamp: KernelTimestamp,
    ruleset_id: RulesetId,
    ruleset_version: u64,
    handled_fs: FilesystemAccess,
    handled_net: NetworkAccess,
    scoped: ScopeAccess,
}
typestate_builder!(
    CreateRulesetEvent, CreateRulesetEventBuilder, "A typestate builder for [`CreateRulesetEvent`].";
    timestamp: Timestamp => KernelTimestamp, "Sets the monotonic kernel timestamp.";
    ruleset_id: RulesetIdState => RulesetId, "Sets the kernel-assigned ruleset identity.";
    ruleset_version: RulesetVersion => u64, "Sets the captured ruleset version.";
    handled_fs: HandledFs => FilesystemAccess, "Sets the handled filesystem access rights.";
    handled_net: HandledNet => NetworkAccess, "Sets the handled network access rights.";
    scoped: Scoped => ScopeAccess, "Sets the scoped access rights.";
);
impl CreateRulesetEvent {
    /// Returns the kernel-assigned ruleset identity.
    pub const fn ruleset_id(&self) -> RulesetId {
        self.ruleset_id
    }
    /// Returns the ruleset version captured for this event.
    pub const fn ruleset_version(&self) -> u64 {
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
impl sealed::Sealed for CreateRulesetEvent {}
impl Observation for CreateRulesetEvent {
    fn timestamp(&self) -> KernelTimestamp {
        self.timestamp
    }
}

/// A filesystem rule addition event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AddRulePathBeneathEvent {
    timestamp: KernelTimestamp,
    ruleset_id: RulesetId,
    ruleset_version: u64,
    access_rights: FilesystemAccess,
    device: u32,
    inode: u64,
    pathname: CapturedPath,
}
typestate_builder!(
    AddRulePathBeneathEvent, AddRulePathBeneathEventBuilder, "A typestate builder for [`AddRulePathBeneathEvent`].";
    timestamp: Timestamp => KernelTimestamp, "Sets the monotonic kernel timestamp.";
    ruleset_id: RulesetIdState => RulesetId, "Sets the kernel-assigned ruleset identity.";
    ruleset_version: RulesetVersion => u64, "Sets the captured ruleset version.";
    access_rights: AccessRights => FilesystemAccess, "Sets the filesystem access rights allowed by the rule.";
    device: Device => u32, "Sets the captured filesystem device number.";
    inode: Inode => u64, "Sets the captured filesystem inode number.";
    pathname: Pathname => CapturedPath, "Sets the captured filesystem pathname.";
);
impl AddRulePathBeneathEvent {
    /// Returns the kernel-assigned ruleset identity.
    pub const fn ruleset_id(&self) -> RulesetId {
        self.ruleset_id
    }
    /// Returns the ruleset version captured for this event.
    pub const fn ruleset_version(&self) -> u64 {
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
    pub const fn pathname(&self) -> &CapturedPath {
        &self.pathname
    }
}
impl sealed::Sealed for AddRulePathBeneathEvent {}
impl Observation for AddRulePathBeneathEvent {
    fn timestamp(&self) -> KernelTimestamp {
        self.timestamp
    }
}

/// A network rule addition event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AddRuleNetPortEvent {
    timestamp: KernelTimestamp,
    ruleset_id: RulesetId,
    ruleset_version: u64,
    access_rights: NetworkAccess,
    port: u64,
}
typestate_builder!(
    AddRuleNetPortEvent, AddRuleNetPortEventBuilder, "A typestate builder for [`AddRuleNetPortEvent`].";
    timestamp: Timestamp => KernelTimestamp, "Sets the monotonic kernel timestamp.";
    ruleset_id: RulesetIdState => RulesetId, "Sets the kernel-assigned ruleset identity.";
    ruleset_version: RulesetVersion => u64, "Sets the captured ruleset version.";
    access_rights: AccessRights => NetworkAccess, "Sets the network access rights allowed by the rule.";
    port: Port => u64, "Sets the captured network-rule port.";
);
impl AddRuleNetPortEvent {
    /// Returns the kernel-assigned ruleset identity.
    pub const fn ruleset_id(&self) -> RulesetId {
        self.ruleset_id
    }
    /// Returns the ruleset version captured for this event.
    pub const fn ruleset_version(&self) -> u64 {
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
impl sealed::Sealed for AddRuleNetPortEvent {}
impl Observation for AddRuleNetPortEvent {
    fn timestamp(&self) -> KernelTimestamp {
        self.timestamp
    }
}

/// A domain creation event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CreateDomainEvent {
    timestamp: KernelTimestamp,
    ruleset_id: RulesetId,
    ruleset_version: u64,
    domain_id: DomainId,
    parent_id: Option<DomainId>,
    creator_tgid: ProcessId,
    creator_comm: CapturedCommand,
}
typestate_builder!(
    CreateDomainEvent, CreateDomainEventBuilder, "A typestate builder for [`CreateDomainEvent`].";
    timestamp: Timestamp => KernelTimestamp, "Sets the monotonic kernel timestamp.";
    ruleset_id: RulesetIdState => RulesetId, "Sets the kernel-assigned ruleset identity.";
    ruleset_version: RulesetVersion => u64, "Sets the ruleset version frozen into the domain.";
    domain_id: DomainIdState => DomainId, "Sets the kernel-assigned domain identity.";
    parent_id: ParentId => Option<DomainId>, "Sets the parent domain identity, or `None` for no parent.";
    creator_tgid: CreatorTgid => ProcessId, "Sets the process ID of the domain creator.";
    creator_comm: CreatorComm => CapturedCommand, "Sets the captured command of the domain creator.";
);
impl CreateDomainEvent {
    /// Returns the kernel-assigned ruleset identity.
    pub const fn ruleset_id(&self) -> RulesetId {
        self.ruleset_id
    }
    /// Returns the ruleset version frozen into the new domain.
    pub const fn ruleset_version(&self) -> u64 {
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
    /// Returns the process ID of the task that created the domain.
    pub const fn creator_tgid(&self) -> ProcessId {
        self.creator_tgid
    }
    /// Returns the command name of the task that created the domain.
    pub const fn creator_comm(&self) -> &CapturedCommand {
        &self.creator_comm
    }
}
impl sealed::Sealed for CreateDomainEvent {}
impl Observation for CreateDomainEvent {
    fn timestamp(&self) -> KernelTimestamp {
        self.timestamp
    }
}

/// A filesystem access denial.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DenyAccessFsEvent {
    timestamp: KernelTimestamp,
    context: DenialContext,
    blockers_access: FilesystemAccess,
    device: u32,
    inode: u64,
    pathname: CapturedPath,
}
typestate_builder!(
    DenyAccessFsEvent, DenyAccessFsEventBuilder, "A typestate builder for [`DenyAccessFsEvent`].";
    timestamp: Timestamp => KernelTimestamp, "Sets the monotonic kernel timestamp.";
    context: Context => DenialContext, "Sets the facts shared by denial events.";
    blockers_access: Blockers => FilesystemAccess, "Sets the filesystem access rights that blocked the operation.";
    device: Device => u32, "Sets the captured filesystem device number.";
    inode: Inode => u64, "Sets the captured filesystem inode number.";
    pathname: Pathname => CapturedPath, "Sets the captured filesystem pathname.";
);
impl DenyAccessFsEvent {
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
    /// Returns the captured filesystem pathname.
    pub const fn pathname(&self) -> &CapturedPath {
        &self.pathname
    }
}
impl sealed::Sealed for DenyAccessFsEvent {}
impl Observation for DenyAccessFsEvent {
    fn timestamp(&self) -> KernelTimestamp {
        self.timestamp
    }
}
impl Denial for DenyAccessFsEvent {
    fn context(&self) -> &DenialContext {
        &self.context
    }
}

/// A network access denial.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DenyAccessNetEvent {
    timestamp: KernelTimestamp,
    context: DenialContext,
    blockers_access: NetworkAccess,
    source_port: u64,
    destination_port: u64,
}
typestate_builder!(
    DenyAccessNetEvent, DenyAccessNetEventBuilder, "A typestate builder for [`DenyAccessNetEvent`].";
    timestamp: Timestamp => KernelTimestamp, "Sets the monotonic kernel timestamp.";
    context: Context => DenialContext, "Sets the facts shared by denial events.";
    blockers_access: Blockers => NetworkAccess, "Sets the network access rights that blocked the operation.";
    source_port: SourcePort => u64, "Sets the checked port projected for a known bind access, or zero otherwise.";
    destination_port: DestinationPort => u64, "Sets the checked port projected for a known connect or send access, or zero otherwise.";
);
impl DenyAccessNetEvent {
    /// Returns the access rights that blocked the operation.
    pub const fn blockers_access(&self) -> NetworkAccess {
        self.blockers_access
    }
    /// Returns the checked port for a known bind access, or zero otherwise.
    pub const fn source_port(&self) -> u64 {
        self.source_port
    }
    /// Returns the checked port for a known connect or send access, or zero otherwise.
    pub const fn destination_port(&self) -> u64 {
        self.destination_port
    }
}
impl sealed::Sealed for DenyAccessNetEvent {}
impl Observation for DenyAccessNetEvent {
    fn timestamp(&self) -> KernelTimestamp {
        self.timestamp
    }
}
impl Denial for DenyAccessNetEvent {
    fn context(&self) -> &DenialContext {
        &self.context
    }
}

/// A ptrace denial.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DenyPtraceEvent {
    timestamp: KernelTimestamp,
    context: DenialContext,
    tracee_domain: DomainMembership,
    tracee_pid: ProcessId,
    tracee_comm: CapturedCommand,
}
typestate_builder!(
    DenyPtraceEvent, DenyPtraceEventBuilder, "A typestate builder for [`DenyPtraceEvent`].";
    timestamp: Timestamp => KernelTimestamp, "Sets the monotonic kernel timestamp.";
    context: Context => DenialContext, "Sets the facts shared by denial events.";
    tracee_domain: TraceeDomain => DomainMembership, "Sets the tracee domain membership.";
    tracee_pid: TraceePid => ProcessId, "Sets the process ID of the tracee.";
    tracee_comm: TraceeComm => CapturedCommand, "Sets the captured command of the tracee.";
);
impl DenyPtraceEvent {
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
impl sealed::Sealed for DenyPtraceEvent {}
impl Observation for DenyPtraceEvent {
    fn timestamp(&self) -> KernelTimestamp {
        self.timestamp
    }
}
impl Denial for DenyPtraceEvent {
    fn context(&self) -> &DenialContext {
        &self.context
    }
}

/// A signal denial.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DenyScopeSignalEvent {
    timestamp: KernelTimestamp,
    context: DenialContext,
    target_domain: DomainMembership,
    target_pid: ProcessId,
    target_comm: CapturedCommand,
}
typestate_builder!(
    DenyScopeSignalEvent, DenyScopeSignalEventBuilder, "A typestate builder for [`DenyScopeSignalEvent`].";
    timestamp: Timestamp => KernelTimestamp, "Sets the monotonic kernel timestamp.";
    context: Context => DenialContext, "Sets the facts shared by denial events.";
    target_domain: TargetDomain => DomainMembership, "Sets the target domain membership.";
    target_pid: TargetPid => ProcessId, "Sets the process ID of the target.";
    target_comm: TargetComm => CapturedCommand, "Sets the captured command of the target.";
);
impl DenyScopeSignalEvent {
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
impl sealed::Sealed for DenyScopeSignalEvent {}
impl Observation for DenyScopeSignalEvent {
    fn timestamp(&self) -> KernelTimestamp {
        self.timestamp
    }
}
impl Denial for DenyScopeSignalEvent {
    fn context(&self) -> &DenialContext {
        &self.context
    }
}

/// An abstract UNIX socket denial.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DenyScopeAbstractUnixSocketEvent {
    timestamp: KernelTimestamp,
    context: DenialContext,
    peer_domain: DomainMembership,
    peer_pid: Option<ProcessId>,
    abstract_name: CapturedAbstractUnixSocketName,
}
typestate_builder!(
    DenyScopeAbstractUnixSocketEvent, DenyScopeAbstractUnixSocketEventBuilder, "A typestate builder for [`DenyScopeAbstractUnixSocketEvent`].";
    timestamp: Timestamp => KernelTimestamp, "Sets the monotonic kernel timestamp.";
    context: Context => DenialContext, "Sets the facts shared by denial events.";
    peer_domain: PeerDomain => DomainMembership, "Sets the socket peer domain membership.";
    peer_pid: PeerPid => Option<ProcessId>, "Sets the best-effort socket peer process ID, or `None` when unavailable.";
    abstract_name: AbstractName => CapturedAbstractUnixSocketName, "Sets the peer socket's captured abstract name.";
);
impl DenyScopeAbstractUnixSocketEvent {
    /// Returns whether the peer was unsandboxed or in a domain.
    pub const fn peer_domain(&self) -> DomainMembership {
        self.peer_domain
    }
    /// Returns the best-effort socket peer process ID captured by the kernel.
    ///
    /// `None` means peer credentials were unavailable.  A returned ID is
    /// descriptive and is not a stable socket identity.
    pub const fn peer_pid(&self) -> Option<ProcessId> {
        self.peer_pid
    }
    /// Returns the peer socket's exact abstract name.
    pub const fn abstract_name(&self) -> &CapturedAbstractUnixSocketName {
        &self.abstract_name
    }
}
impl sealed::Sealed for DenyScopeAbstractUnixSocketEvent {}
impl Observation for DenyScopeAbstractUnixSocketEvent {
    fn timestamp(&self) -> KernelTimestamp {
        self.timestamp
    }
}
impl Denial for DenyScopeAbstractUnixSocketEvent {
    fn context(&self) -> &DenialContext {
        &self.context
    }
}

/// A domain destruction event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct FreeDomainEvent {
    timestamp: KernelTimestamp,
    domain_id: DomainId,
    denial_count: u64,
}
typestate_builder!(
    FreeDomainEvent, FreeDomainEventBuilder, "A typestate builder for [`FreeDomainEvent`].";
    timestamp: Timestamp => KernelTimestamp, "Sets the monotonic kernel timestamp.";
    domain_id: DomainIdState => DomainId, "Sets the kernel-assigned domain identity.";
    denial_count: DenialCount => u64, "Sets the final cumulative kernel denial count.";
);
impl FreeDomainEvent {
    /// Returns the kernel-assigned domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }
    /// Returns the domain's final cumulative kernel denial count.
    pub const fn denial_count(&self) -> u64 {
        self.denial_count
    }
}
impl sealed::Sealed for FreeDomainEvent {}
impl Observation for FreeDomainEvent {
    fn timestamp(&self) -> KernelTimestamp {
        self.timestamp
    }
}

/// A ruleset destruction event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct FreeRulesetEvent {
    timestamp: KernelTimestamp,
    ruleset_id: RulesetId,
    ruleset_version: u64,
}
typestate_builder!(
    FreeRulesetEvent, FreeRulesetEventBuilder, "A typestate builder for [`FreeRulesetEvent`].";
    timestamp: Timestamp => KernelTimestamp, "Sets the monotonic kernel timestamp.";
    ruleset_id: RulesetIdState => RulesetId, "Sets the kernel-assigned ruleset identity.";
    ruleset_version: RulesetVersion => u64, "Sets the final ruleset version.";
);
impl FreeRulesetEvent {
    /// Returns the kernel-assigned ruleset identity.
    pub const fn ruleset_id(&self) -> RulesetId {
        self.ruleset_id
    }
    /// Returns the ruleset's final version.
    pub const fn ruleset_version(&self) -> u64 {
        self.ruleset_version
    }
}
impl sealed::Sealed for FreeRulesetEvent {}
impl Observation for FreeRulesetEvent {
    fn timestamp(&self) -> KernelTimestamp {
        self.timestamp
    }
}

/// A domain enforcement outcome event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct EnforceDomainEvent {
    timestamp: KernelTimestamp,
    domain_id: DomainId,
    enforcing_tid: ThreadId,
    complete: bool,
    process_wide: bool,
    no_new_privs: bool,
}
typestate_builder!(
    EnforceDomainEvent, EnforceDomainEventBuilder, "A typestate builder for [`EnforceDomainEvent`].";
    timestamp: Timestamp => KernelTimestamp, "Sets the monotonic kernel timestamp.";
    domain_id: DomainIdState => DomainId, "Sets the kernel-assigned domain identity.";
    enforcing_tid: EnforcingTid => ThreadId, "Sets the thread ID reporting the enforcement outcome.";
    complete: Complete => bool, "Sets whether this is the concluding enforcement event.";
    process_wide: ProcessWide => bool, "Sets whether eligible sibling threads were covered or none existed.";
    no_new_privs: NoNewPrivs => bool, "Sets whether the enforcing thread had `no_new_privs` set.";
);
impl EnforceDomainEvent {
    /// Returns the kernel-assigned domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }
    /// Returns the thread ID on which this enforcement outcome occurred.
    pub const fn enforcing_tid(&self) -> ThreadId {
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
impl sealed::Sealed for EnforceDomainEvent {}
impl Observation for EnforceDomainEvent {
    fn timestamp(&self) -> KernelTimestamp {
        self.timestamp
    }
}

/// A semantic Landlock observation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Event {
    /// A ruleset was created.
    CreateRuleset(CreateRulesetEvent),
    /// A filesystem rule was added.
    AddRulePathBeneath(AddRulePathBeneathEvent),
    /// A network rule was added.
    AddRuleNetPort(AddRuleNetPortEvent),
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
}

impl sealed::Sealed for Event {}
impl Observation for Event {
    fn timestamp(&self) -> KernelTimestamp {
        match self {
            Self::CreateRuleset(event) => event.timestamp(),
            Self::AddRulePathBeneath(event) => event.timestamp(),
            Self::AddRuleNetPort(event) => event.timestamp(),
            Self::CreateDomain(event) => event.timestamp(),
            Self::DenyAccessFs(event) => event.timestamp(),
            Self::DenyAccessNet(event) => event.timestamp(),
            Self::DenyPtrace(event) => event.timestamp(),
            Self::DenyScopeSignal(event) => event.timestamp(),
            Self::DenyScopeAbstractUnixSocket(event) => event.timestamp(),
            Self::FreeDomain(event) => event.timestamp(),
            Self::FreeRuleset(event) => event.timestamp(),
            Self::EnforceDomain(event) => event.timestamp(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_builders_accept_all_fields_in_any_order() {
        let timestamp = KernelTimestamp::from_nanoseconds(7);
        let ruleset_id = RulesetId::new(MIN_LANDLOCK_ID).unwrap();
        let event = CreateRulesetEvent::builder()
            .scoped(ScopeAccess::from_bits(6))
            .handled_net(NetworkAccess::from_bits(5))
            .handled_fs(FilesystemAccess::from_bits(4))
            .ruleset_version(3)
            .ruleset_id(ruleset_id)
            .timestamp(timestamp)
            .build();

        assert_eq!(event.timestamp(), timestamp);
        assert_eq!(event.ruleset_id(), ruleset_id);
        assert_eq!(event.ruleset_version(), 3);
        assert_eq!(event.handled_fs().bits(), 4);
        assert_eq!(event.handled_net().bits(), 5);
        assert_eq!(event.scoped().bits(), 6);

        let domain_id = DomainId::new(MIN_LANDLOCK_ID + 1).unwrap();
        let parent_id = DomainId::new(MIN_LANDLOCK_ID + 2).unwrap();
        let creator_comm = CapturedCommand::new(b"creator".to_vec(), false).unwrap();
        let hierarchy = HierarchySnapshot::builder()
            .creator_comm(creator_comm.clone())
            .domain_id(domain_id)
            .creator_tgid(ProcessId::new(8).unwrap())
            .parent_id(Some(parent_id))
            .build();
        assert_eq!(hierarchy.domain_id(), domain_id);
        assert_eq!(hierarchy.parent_id(), Some(parent_id));
        assert_eq!(hierarchy.creator_tgid().get(), 8);
        assert_eq!(hierarchy.creator_comm(), &creator_comm);

        let context = DenialContext::builder()
            .logged(true)
            .hierarchy(hierarchy.clone())
            .same_exec(false)
            .cumulative_denial_count(9)
            .build();
        assert_eq!(context.hierarchy(), &hierarchy);
        assert_eq!(context.cumulative_denial_count(), 9);
        assert!(!context.same_exec());
        assert!(context.logged());
    }

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
    fn task_id_boundaries_and_conversions() {
        for error in [
            ProcessId::new(0).unwrap_err(),
            ThreadId::new(0).unwrap_err(),
        ] {
            assert_eq!(error.value(), 0);
            assert_eq!(
                error.to_string(),
                "invalid Linux task ID 0, expected a nonzero value"
            );
        }

        assert!(ProcessId::try_from(0).is_err());
        assert!(ThreadId::try_from(0).is_err());

        let process = ProcessId::new(1).unwrap();
        let thread = ThreadId::try_from(u32::MAX).unwrap();
        assert_eq!(process.get(), 1);
        assert_eq!(u32::from(process), 1);
        assert_eq!(thread.get(), u32::MAX);
        assert_eq!(format!("{process:?}"), "ProcessId(1)");
        assert_eq!(format!("{thread:?}"), "ThreadId(4294967295)");
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
