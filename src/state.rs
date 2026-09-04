// SPDX-License-Identifier: MIT OR Apache-2.0

//! Partial state reconstructed from semantic observations.
//!
//! # Memory use
//!
//! [`State`] currently has no capacity or eviction policy. It retains
//! reconstructed rulesets, domains, and rules, plus one enforcement event per
//! observed TID in each domain, until it is dropped. Memory can therefore grow
//! without a configured bound in a long-running process. Configurable retention
//! limits and eviction are planned but are not implemented yet; the bounded
//! collector queue and [`crate::aggregate::DenialAggregator`] do not bound
//! `State`.

use std::collections::HashMap;

use crate::event::{
    CapturedString, DenialContext, DomainId, DomainMembership, EnforceDomainEvent, Event,
    FilesystemAccess, KernelTimestamp, NetworkAccess, RulesetId, ScopeAccess,
};

/// The observed lifecycle of an object.
///
/// Unknown, allocated, and deallocated exhaust the possible reconstructed
/// allocation statuses. Population and enforcement are separate facts.
/// Lifecycle facts are monotonic: once an object is known to have been
/// deallocated, later observations can add facts but cannot change that fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleState {
    /// No allocation, use, or deallocation event has established a lifecycle.
    Unknown,
    /// The object is known to have been allocated historically.
    ///
    /// This fact may be inferred from an observed use; it is not proof that the
    /// object is currently live.
    Allocated,
    /// Deallocation of the object has been observed.
    Deallocated,
}

/// The known parent of a reconstructed domain.
///
/// Known parentage is either a null parent or one domain ID. Unknown parentage
/// is represented by `None` from [`DomainState::parent()`], not by a variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainParent {
    /// The domain is known to have no parent.
    Root,
    /// The domain has the contained parent identity.
    Domain(DomainId),
}

/// A ruleset identity paired with a particular version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RulesetVersion {
    ruleset_id: RulesetId,
    ruleset_version: u32,
}

impl RulesetVersion {
    /// Creates a versioned ruleset reference.
    pub const fn new(ruleset_id: RulesetId, ruleset_version: u32) -> Self {
        Self {
            ruleset_id,
            ruleset_version,
        }
    }

    /// Returns the ruleset identity.
    pub const fn ruleset_id(self) -> RulesetId {
        self.ruleset_id
    }

    /// Returns the ruleset version.
    pub const fn ruleset_version(self) -> u32 {
        self.ruleset_version
    }
}

/// Reconstructed state for one filesystem rule target.
#[derive(Debug)]
#[non_exhaustive]
pub struct FilesystemRuleState {
    device: u32,
    inode: u64,
    access_rights: FilesystemAccess,
    pathname: CapturedString,
    pathname_timestamp: KernelTimestamp,
}

impl FilesystemRuleState {
    /// Returns the captured filesystem device number identifying the target.
    pub const fn device(&self) -> u32 {
        self.device
    }

    /// Returns the captured filesystem inode number identifying the target.
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Returns the union of all observed allowed-access masks for this target.
    pub const fn access_rights(&self) -> FilesystemAccess {
        self.access_rights
    }

    /// Returns the path from the latest timestamped observation of this target.
    ///
    /// The path is descriptive and is not part of the rule identity.
    pub const fn pathname(&self) -> &CapturedString {
        &self.pathname
    }
}

/// Reconstructed state for one network rule target.
#[derive(Debug)]
#[non_exhaustive]
pub struct NetworkRuleState {
    port: u64,
    access_rights: NetworkAccess,
}

impl NetworkRuleState {
    /// Returns the port identifying this rule target.
    pub const fn port(&self) -> u64 {
        self.port
    }

    /// Returns the union of all observed allowed-access masks for this target.
    pub const fn access_rights(&self) -> NetworkAccess {
        self.access_rights
    }
}

/// Reconstructed facts about a ruleset.
#[derive(Debug)]
#[non_exhaustive]
pub struct RulesetState {
    id: RulesetId,
    lifecycle: LifecycleState,
    creation_timestamp: Option<KernelTimestamp>,
    handled_fs: Option<FilesystemAccess>,
    handled_net: Option<NetworkAccess>,
    scoped: Option<ScopeAccess>,
    max_observed_version: Option<u32>,
    final_version: Option<u32>,
    free_timestamp: Option<KernelTimestamp>,
    filesystem_rules: HashMap<(u32, u64), FilesystemRuleState>,
    network_rules: HashMap<u64, NetworkRuleState>,
}

impl RulesetState {
    fn unknown(id: RulesetId) -> Self {
        Self {
            id,
            lifecycle: LifecycleState::Unknown,
            creation_timestamp: None,
            handled_fs: None,
            handled_net: None,
            scoped: None,
            max_observed_version: None,
            final_version: None,
            free_timestamp: None,
            filesystem_rules: HashMap::new(),
            network_rules: HashMap::new(),
        }
    }

    fn mark_allocated(&mut self) {
        if self.lifecycle == LifecycleState::Unknown {
            self.lifecycle = LifecycleState::Allocated;
        }
    }

    fn update_version(&mut self, version: u32) {
        update_max(&mut self.max_observed_version, version);
    }

    /// Returns the ruleset identity.
    pub const fn ruleset_id(&self) -> RulesetId {
        self.id
    }

    /// Returns the strongest observed lifecycle fact.
    pub const fn lifecycle(&self) -> LifecycleState {
        self.lifecycle
    }

    /// Returns the latest observed creation-event timestamp, if one was seen.
    pub const fn creation_timestamp(&self) -> Option<KernelTimestamp> {
        self.creation_timestamp
    }

    /// Returns the handled filesystem mask, if creation was observed.
    pub const fn handled_fs(&self) -> Option<FilesystemAccess> {
        self.handled_fs
    }

    /// Returns the handled network mask, if creation was observed.
    pub const fn handled_net(&self) -> Option<NetworkAccess> {
        self.handled_net
    }

    /// Returns the scoped-access mask, if creation was observed.
    pub const fn scoped(&self) -> Option<ScopeAccess> {
        self.scoped
    }

    /// Returns the greatest observed version, or `None` when no version is known.
    ///
    /// Final versions reported by free events participate in this maximum.
    pub const fn max_observed_version(&self) -> Option<u32> {
        self.max_observed_version
    }

    /// Returns the greatest final version reported by a free event, if any.
    pub const fn final_version(&self) -> Option<u32> {
        self.final_version
    }

    /// Returns the latest observed free-event timestamp, if one was seen.
    pub const fn free_timestamp(&self) -> Option<KernelTimestamp> {
        self.free_timestamp
    }

    /// Looks up a filesystem rule by its natural `(device, inode)` identity.
    pub fn filesystem_rule(&self, device: u32, inode: u64) -> Option<&FilesystemRuleState> {
        self.filesystem_rules.get(&(device, inode))
    }

    /// Iterates over observed filesystem rules in unspecified order.
    pub fn filesystem_rules(&self) -> impl Iterator<Item = &FilesystemRuleState> {
        self.filesystem_rules.values()
    }

    /// Returns the number of distinct observed filesystem targets.
    pub fn filesystem_rule_count(&self) -> usize {
        self.filesystem_rules.len()
    }

    /// Looks up a network rule by its natural port identity.
    pub fn network_rule(&self, port: u64) -> Option<&NetworkRuleState> {
        self.network_rules.get(&port)
    }

    /// Iterates over observed network rules in unspecified order.
    pub fn network_rules(&self) -> impl Iterator<Item = &NetworkRuleState> {
        self.network_rules.values()
    }

    /// Returns the number of distinct observed network targets.
    pub fn network_rule_count(&self) -> usize {
        self.network_rules.len()
    }
}

/// Reconstructed facts about a Landlock domain.
#[derive(Debug)]
#[non_exhaustive]
pub struct DomainState {
    id: DomainId,
    lifecycle: LifecycleState,
    creation_timestamp: Option<KernelTimestamp>,
    parent: Option<DomainParent>,
    creator_tgid: Option<u32>,
    creator_comm: Option<CapturedString>,
    ruleset: Option<RulesetVersion>,
    cumulative_denial_count: Option<u64>,
    final_denial_count: Option<u64>,
    free_timestamp: Option<KernelTimestamp>,
    enforcement_events: HashMap<u32, EnforceDomainEvent>,
    any_process_wide_enforcement: bool,
}

impl DomainState {
    fn unknown(id: DomainId) -> Self {
        Self {
            id,
            lifecycle: LifecycleState::Unknown,
            creation_timestamp: None,
            parent: None,
            creator_tgid: None,
            creator_comm: None,
            ruleset: None,
            cumulative_denial_count: None,
            final_denial_count: None,
            free_timestamp: None,
            enforcement_events: HashMap::new(),
            any_process_wide_enforcement: false,
        }
    }

    fn mark_allocated(&mut self) {
        if self.lifecycle == LifecycleState::Unknown {
            self.lifecycle = LifecycleState::Allocated;
        }
    }

    /// Returns the domain identity.
    pub const fn domain_id(&self) -> DomainId {
        self.id
    }

    /// Returns the strongest observed lifecycle fact.
    pub const fn lifecycle(&self) -> LifecycleState {
        self.lifecycle
    }

    /// Returns the latest observed creation-event timestamp, if one was seen.
    pub const fn creation_timestamp(&self) -> Option<KernelTimestamp> {
        self.creation_timestamp
    }

    /// Returns explicit parent knowledge.
    ///
    /// `None` means parentage is unknown, [`DomainParent::Root`] is a known
    /// null parent, and [`DomainParent::Domain`] identifies a known parent.
    pub const fn parent(&self) -> Option<DomainParent> {
        self.parent
    }

    /// Returns the creator thread-group ID when known.
    pub const fn creator_tgid(&self) -> Option<u32> {
        self.creator_tgid
    }

    /// Returns the captured creator command when known.
    pub const fn creator_comm(&self) -> Option<&CapturedString> {
        self.creator_comm.as_ref()
    }

    /// Returns the ruleset identity and version frozen into this domain, if known.
    pub const fn ruleset(&self) -> Option<RulesetVersion> {
        self.ruleset
    }

    /// Returns the greatest observed kernel cumulative denial count, if known.
    pub const fn cumulative_denial_count(&self) -> Option<u64> {
        self.cumulative_denial_count
    }

    /// Returns the greatest final denial count reported by a free event, if any.
    pub const fn final_denial_count(&self) -> Option<u64> {
        self.final_denial_count
    }

    /// Returns the latest observed free-event timestamp, if one was seen.
    pub const fn free_timestamp(&self) -> Option<KernelTimestamp> {
        self.free_timestamp
    }

    /// Looks up the selected enforcement event for a thread.
    ///
    /// The greatest timestamp wins for each numeric TID; equal timestamps use
    /// the event applied last. This is not a live-thread census.
    pub fn enforcement_event(&self, enforcing_tid: u32) -> Option<&EnforceDomainEvent> {
        self.enforcement_events.get(&enforcing_tid)
    }

    /// Iterates over selected per-thread enforcement events in unspecified order.
    ///
    /// Per-TID selection follows [`Self::enforcement_event()`].
    pub fn enforcement_events(&self) -> impl Iterator<Item = &EnforceDomainEvent> {
        self.enforcement_events.values()
    }

    /// Returns the number of thread IDs with a selected enforcement event.
    ///
    /// This is an observed-key count, not a domain thread count.
    pub fn enforcement_event_count(&self) -> usize {
        self.enforcement_events.len()
    }

    /// Returns the weakest observed latest-per-thread `no_new_privs` fact.
    ///
    /// `None` means no enforcement was observed. Once observations exist,
    /// `Some(true)` means every latest per-TID observation had `no_new_privs`
    /// set, while one latest observation without it yields `Some(false)`.
    /// Observed TIDs are not a live-thread census.
    pub fn no_new_privs(&self) -> Option<bool> {
        (!self.enforcement_events.is_empty()).then(|| {
            self.enforcement_events
                .values()
                .all(EnforceDomainEvent::no_new_privs)
        })
    }

    /// Returns whether any observed enforcement event was process-wide.
    pub const fn any_process_wide_enforcement(&self) -> bool {
        self.any_process_wide_enforcement
    }
}

/// Partial ruleset and domain state reconstructed from an event stream.
///
/// State preserves incomplete knowledge and monotonic facts. It does not retain
/// or aggregate individual denial entries; consumers that need chronology must
/// keep the original [`Event`] values.
///
/// # Memory use
///
/// `State` currently has no capacity or eviction policy. It retains
/// reconstructed rulesets, domains, and rules, plus one enforcement event per
/// observed TID in each domain, until it is dropped. Memory can therefore grow
/// without a configured bound in a long-running process. Configurable retention
/// limits and eviction are planned but are not implemented yet; the bounded
/// collector queue and [`crate::aggregate::DenialAggregator`] do not bound
/// `State`.
#[derive(Debug)]
#[non_exhaustive]
pub struct State {
    rulesets: HashMap<RulesetId, RulesetState>,
    domains: HashMap<DomainId, DomainState>,
}

impl State {
    /// Creates empty reconstructed state.
    pub fn new() -> Self {
        Self {
            rulesets: HashMap::new(),
            domains: HashMap::new(),
        }
    }

    /// Applies one semantic observation.
    ///
    /// Applying an unknown event has no effect. Updates are infallible and
    /// retain stronger facts already learned from other event orderings.
    pub fn apply(&mut self, event: &Event) {
        match event {
            Event::CreateRuleset(event) => {
                let state = self
                    .rulesets
                    .entry(event.ruleset_id())
                    .or_insert_with(|| RulesetState::unknown(event.ruleset_id()));
                state.mark_allocated();
                state.update_version(event.ruleset_version());
                let replace = state.creation_timestamp.is_none_or(|timestamp| {
                    timestamp_value(event.timestamp()) >= timestamp_value(timestamp)
                });
                if replace {
                    state.creation_timestamp = Some(event.timestamp());
                    state.handled_fs = Some(event.handled_fs());
                    state.handled_net = Some(event.handled_net());
                    state.scoped = Some(event.scoped());
                }
            }
            Event::AddRuleFs(event) => {
                let state = self
                    .rulesets
                    .entry(event.ruleset_id())
                    .or_insert_with(|| RulesetState::unknown(event.ruleset_id()));
                state.mark_allocated();
                state.update_version(event.ruleset_version());
                let key = (event.device(), event.inode());
                match state.filesystem_rules.get_mut(&key) {
                    Some(rule) => {
                        rule.access_rights = FilesystemAccess::from_bits(
                            rule.access_rights.bits() | event.access_rights().bits(),
                        );
                        if timestamp_value(event.timestamp())
                            >= timestamp_value(rule.pathname_timestamp)
                        {
                            rule.pathname = event.pathname().clone();
                            rule.pathname_timestamp = event.timestamp();
                        }
                    }
                    None => {
                        state.filesystem_rules.insert(
                            key,
                            FilesystemRuleState {
                                device: event.device(),
                                inode: event.inode(),
                                access_rights: event.access_rights(),
                                pathname: event.pathname().clone(),
                                pathname_timestamp: event.timestamp(),
                            },
                        );
                    }
                }
            }
            Event::AddRuleNet(event) => {
                let state = self
                    .rulesets
                    .entry(event.ruleset_id())
                    .or_insert_with(|| RulesetState::unknown(event.ruleset_id()));
                state.mark_allocated();
                state.update_version(event.ruleset_version());
                state
                    .network_rules
                    .entry(event.port())
                    .and_modify(|rule| {
                        rule.access_rights = NetworkAccess::from_bits(
                            rule.access_rights.bits() | event.access_rights().bits(),
                        );
                    })
                    .or_insert(NetworkRuleState {
                        port: event.port(),
                        access_rights: event.access_rights(),
                    });
            }
            Event::CreateDomain(event) => {
                let ruleset = self
                    .rulesets
                    .entry(event.ruleset_id())
                    .or_insert_with(|| RulesetState::unknown(event.ruleset_id()));
                ruleset.mark_allocated();
                ruleset.update_version(event.ruleset_version());

                if let Some(parent_id) = event.parent_id() {
                    self.domains
                        .entry(parent_id)
                        .or_insert_with(|| DomainState::unknown(parent_id));
                }

                let state = self
                    .domains
                    .entry(event.domain_id())
                    .or_insert_with(|| DomainState::unknown(event.domain_id()));
                state.mark_allocated();
                update_max(&mut state.cumulative_denial_count, 0);
                let replace = state.creation_timestamp.is_none_or(|timestamp| {
                    timestamp_value(event.timestamp()) >= timestamp_value(timestamp)
                });
                if replace {
                    state.creation_timestamp = Some(event.timestamp());
                    state.parent = Some(match event.parent_id() {
                        Some(id) => DomainParent::Domain(id),
                        None => DomainParent::Root,
                    });
                    state.creator_tgid = Some(event.creator_tgid());
                    state.creator_comm = Some(event.creator_comm().clone());
                    state.ruleset = Some(RulesetVersion::new(
                        event.ruleset_id(),
                        event.ruleset_version(),
                    ));
                }
            }
            Event::DenyAccessFs(event) => {
                self.apply_denial(event.context(), None);
            }
            Event::DenyAccessNet(event) => {
                self.apply_denial(event.context(), None);
            }
            Event::DenyPtrace(event) => {
                self.apply_denial(event.context(), Some(event.tracee_domain()));
            }
            Event::DenyScopeSignal(event) => {
                self.apply_denial(event.context(), Some(event.target_domain()));
            }
            Event::DenyScopeAbstractUnixSocket(event) => {
                self.apply_denial(event.context(), Some(event.peer_domain()));
            }
            Event::FreeDomain(event) => {
                let state = self
                    .domains
                    .entry(event.domain_id())
                    .or_insert_with(|| DomainState::unknown(event.domain_id()));
                state.lifecycle = LifecycleState::Deallocated;
                update_latest_timestamp(&mut state.free_timestamp, event.timestamp());
                update_max(&mut state.final_denial_count, event.denial_count());
                update_max(&mut state.cumulative_denial_count, event.denial_count());
            }
            Event::FreeRuleset(event) => {
                let state = self
                    .rulesets
                    .entry(event.ruleset_id())
                    .or_insert_with(|| RulesetState::unknown(event.ruleset_id()));
                state.lifecycle = LifecycleState::Deallocated;
                update_latest_timestamp(&mut state.free_timestamp, event.timestamp());
                update_max(&mut state.final_version, event.ruleset_version());
                state.update_version(event.ruleset_version());
            }
            Event::EnforceDomain(event) => {
                let state = self
                    .domains
                    .entry(event.domain_id())
                    .or_insert_with(|| DomainState::unknown(event.domain_id()));
                state.mark_allocated();
                state.any_process_wide_enforcement |= event.process_wide();
                state
                    .enforcement_events
                    .entry(event.enforcing_tid())
                    .and_modify(|current| {
                        if timestamp_value(event.timestamp())
                            >= timestamp_value(current.timestamp())
                        {
                            *current = event.clone();
                        }
                    })
                    .or_insert_with(|| event.clone());
            }
            Event::Unknown(_) => {}
        }
    }

    fn apply_denial(
        &mut self,
        context: &DenialContext,
        domain_membership: Option<DomainMembership>,
    ) {
        let hierarchy = context.hierarchy();
        let domain_id = hierarchy.domain_id();
        let state = self
            .domains
            .entry(domain_id)
            .or_insert_with(|| DomainState::unknown(domain_id));
        state.mark_allocated();
        if state.parent.is_none() {
            state.parent = Some(match hierarchy.parent_id() {
                Some(id) => DomainParent::Domain(id),
                None => DomainParent::Root,
            });
        }
        if state.creator_tgid.is_none()
            && state.creator_comm.is_none()
            && hierarchy.creator_tgid() != 0
            && !hierarchy.creator_comm().as_bytes().is_empty()
        {
            state.creator_tgid = Some(hierarchy.creator_tgid());
            state.creator_comm = Some(hierarchy.creator_comm().clone());
        }
        update_max(
            &mut state.cumulative_denial_count,
            context.cumulative_denial_count(),
        );

        if let Some(parent_id) = hierarchy.parent_id() {
            self.domains
                .entry(parent_id)
                .or_insert_with(|| DomainState::unknown(parent_id));
        }
        if let Some(DomainMembership::Sandboxed(other_id)) = domain_membership {
            self.domains
                .entry(other_id)
                .or_insert_with(|| DomainState::unknown(other_id));
        }
    }

    /// Looks up reconstructed ruleset state by typed identity.
    pub fn ruleset(&self, id: RulesetId) -> Option<&RulesetState> {
        self.rulesets.get(&id)
    }

    /// Iterates over reconstructed rulesets in unspecified order.
    pub fn rulesets(&self) -> impl Iterator<Item = &RulesetState> {
        self.rulesets.values()
    }

    /// Returns the number of reconstructed rulesets, including tombstones.
    pub fn ruleset_count(&self) -> usize {
        self.rulesets.len()
    }

    /// Looks up reconstructed domain state by typed identity.
    pub fn domain(&self, id: DomainId) -> Option<&DomainState> {
        self.domains.get(&id)
    }

    /// Iterates over reconstructed domains in unspecified order.
    pub fn domains(&self) -> impl Iterator<Item = &DomainState> {
        self.domains.values()
    }

    /// Returns the number of reconstructed domains, including placeholders.
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

fn timestamp_value(timestamp: KernelTimestamp) -> u64 {
    timestamp.as_nanoseconds()
}

fn update_latest_timestamp(current: &mut Option<KernelTimestamp>, candidate: KernelTimestamp) {
    if current.is_none_or(|value| timestamp_value(candidate) >= timestamp_value(value)) {
        *current = Some(candidate);
    }
}

fn update_max<T: Ord + Copy>(current: &mut Option<T>, candidate: T) {
    if current.is_none_or(|value| candidate >= value) {
        *current = Some(candidate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{
        AddRuleFsEvent, AddRuleNetEvent, CreateDomainEvent, CreateRulesetEvent, DenyAccessFsEvent,
        DenyAccessNetEvent, DenyPtraceEvent, DenyScopeAbstractUnixSocketEvent,
        DenyScopeSignalEvent, EnforceDomainEvent, FreeDomainEvent, FreeRulesetEvent,
        HierarchySnapshot, UnknownEvent,
    };

    fn timestamp(value: u64) -> KernelTimestamp {
        KernelTimestamp::from_nanoseconds(value)
    }

    fn string(value: &[u8]) -> CapturedString {
        CapturedString::new(value.to_vec(), false).unwrap()
    }

    fn hierarchy(
        domain: u64,
        parent: Option<u64>,
        creator_tgid: u32,
        creator_comm: &[u8],
    ) -> HierarchySnapshot {
        HierarchySnapshot::new(
            DomainId::new(domain),
            parent.map(DomainId::new),
            creator_tgid,
            string(creator_comm),
        )
    }

    fn context(hierarchy: HierarchySnapshot, count: u64) -> DenialContext {
        DenialContext::new(hierarchy, count, false, true)
    }

    fn apply(state: &mut State, event: Event) {
        state.apply(&event);
    }

    #[test]
    fn full_ruleset_create_and_access() {
        let mut state = State::new();
        apply(
            &mut state,
            Event::CreateRuleset(CreateRulesetEvent::new(
                timestamp(10),
                RulesetId::new(7),
                0,
                FilesystemAccess::from_bits(0x8000_0001),
                NetworkAccess::from_bits(0x8000_0002),
                ScopeAccess::from_bits(0x8000_0001),
            )),
        );

        let ruleset = state.ruleset(RulesetId::new(7)).unwrap();
        assert_eq!(ruleset.ruleset_id(), RulesetId::new(7));
        assert_eq!(ruleset.lifecycle(), LifecycleState::Allocated);
        assert_eq!(ruleset.creation_timestamp(), Some(timestamp(10)));
        assert_eq!(ruleset.max_observed_version(), Some(0));
        assert_eq!(ruleset.handled_fs().unwrap().bits(), 0x8000_0001);
        assert_eq!(ruleset.handled_net().unwrap().bits(), 0x8000_0002);
        assert_eq!(ruleset.scoped().unwrap().bits(), 0x8000_0001);
        assert_eq!(state.ruleset_count(), 1);
        assert_eq!(state.rulesets().count(), 1);
        let default = State::default();
        assert_eq!(default.ruleset_count(), 0);
        assert_eq!(default.domain_count(), 0);
    }

    #[test]
    fn inferred_rules_merge_by_natural_target_and_versions_are_monotonic() {
        let mut state = State::new();
        let id = RulesetId::new(8);
        for event in [
            Event::AddRuleFs(AddRuleFsEvent::new(
                timestamp(20),
                id,
                5,
                FilesystemAccess::from_bits(0x8000_0001),
                3,
                4,
                string(b"new"),
            )),
            Event::AddRuleFs(AddRuleFsEvent::new(
                timestamp(10),
                id,
                2,
                FilesystemAccess::from_bits(0x4000_0002),
                3,
                4,
                string(b"old"),
            )),
            Event::AddRuleFs(AddRuleFsEvent::new(
                timestamp(30),
                id,
                4,
                FilesystemAccess::from_bits(4),
                3,
                5,
                string(b"separate"),
            )),
            Event::AddRuleNet(AddRuleNetEvent::new(
                timestamp(40),
                id,
                8,
                NetworkAccess::from_bits(0x8000_0001),
                80,
            )),
            Event::AddRuleNet(AddRuleNetEvent::new(
                timestamp(35),
                id,
                7,
                NetworkAccess::from_bits(0x4000_0002),
                80,
            )),
            Event::AddRuleNet(AddRuleNetEvent::new(
                timestamp(45),
                id,
                6,
                NetworkAccess::from_bits(4),
                81,
            )),
            Event::AddRuleNet(AddRuleNetEvent::new(
                timestamp(50),
                RulesetId::new(9),
                0,
                NetworkAccess::from_bits(8),
                90,
            )),
        ] {
            apply(&mut state, event);
        }

        let ruleset = state.ruleset(id).unwrap();
        assert_eq!(ruleset.lifecycle(), LifecycleState::Allocated);
        assert_eq!(ruleset.creation_timestamp(), None);
        assert_eq!(ruleset.max_observed_version(), Some(8));
        assert_eq!(ruleset.filesystem_rule_count(), 2);
        assert_eq!(ruleset.filesystem_rules().count(), 2);
        let fs = ruleset.filesystem_rule(3, 4).unwrap();
        assert_eq!(fs.access_rights().bits(), 0xc000_0003);
        assert_eq!(fs.pathname().as_bytes(), b"new");
        assert_eq!(
            ruleset
                .filesystem_rule(3, 5)
                .unwrap()
                .access_rights()
                .bits(),
            4
        );
        assert_eq!(ruleset.network_rule_count(), 2);
        assert_eq!(ruleset.network_rules().count(), 2);
        assert_eq!(
            ruleset.network_rule(80).unwrap().access_rights().bits(),
            0xc000_0003
        );
        assert_eq!(ruleset.network_rule(81).unwrap().access_rights().bits(), 4);
        let network_only = state.ruleset(RulesetId::new(9)).unwrap();
        assert_eq!(network_only.lifecycle(), LifecycleState::Allocated);
        assert_eq!(network_only.creation_timestamp(), None);
        assert_eq!(network_only.max_observed_version(), Some(0));
        assert_eq!(
            network_only
                .network_rule(90)
                .unwrap()
                .access_rights()
                .bits(),
            8
        );
    }

    #[test]
    fn full_domain_create_distinguishes_root_and_unknown_parent() {
        let mut state = State::new();
        apply(
            &mut state,
            Event::CreateDomain(CreateDomainEvent::new(
                timestamp(10),
                RulesetId::new(2),
                3,
                DomainId::new(4),
                None,
                100,
                string(b"creator"),
            )),
        );
        apply(
            &mut state,
            Event::EnforceDomain(EnforceDomainEvent::new(
                timestamp(11),
                DomainId::new(5),
                101,
                false,
                false,
                true,
            )),
        );

        let root = state.domain(DomainId::new(4)).unwrap();
        assert_eq!(root.lifecycle(), LifecycleState::Allocated);
        assert_eq!(root.creation_timestamp(), Some(timestamp(10)));
        assert_eq!(root.parent(), Some(DomainParent::Root));
        assert_eq!(root.no_new_privs(), None);
        assert_eq!(root.creator_tgid(), Some(100));
        assert_eq!(root.creator_comm().unwrap().as_bytes(), b"creator");
        assert_eq!(
            root.ruleset(),
            Some(RulesetVersion::new(RulesetId::new(2), 3))
        );
        assert_eq!(root.cumulative_denial_count(), Some(0));
        assert_eq!(state.domain(DomainId::new(5)).unwrap().parent(), None);
        assert_eq!(state.domain_count(), 2);
        assert_eq!(state.domains().count(), 2);
    }

    #[test]
    fn non_root_domain_create_materializes_unknown_cross_references() {
        let mut state = State::new();
        let ruleset_id = RulesetId::new(6);
        let parent_id = DomainId::new(7);
        let domain_id = DomainId::new(8);
        apply(
            &mut state,
            Event::CreateDomain(CreateDomainEvent::new(
                timestamp(20),
                ruleset_id,
                9,
                domain_id,
                Some(parent_id),
                100,
                string(b"creator"),
            )),
        );

        let domain = state.domain(domain_id).unwrap();
        assert_eq!(domain.lifecycle(), LifecycleState::Allocated);
        assert_eq!(domain.parent(), Some(DomainParent::Domain(parent_id)));
        assert_eq!(domain.ruleset(), Some(RulesetVersion::new(ruleset_id, 9)));
        let parent = state.domain(parent_id).unwrap();
        assert_eq!(parent.lifecycle(), LifecycleState::Unknown);
        assert_eq!(parent.creation_timestamp(), None);
        assert_eq!(parent.cumulative_denial_count(), None);
        assert_eq!(parent.final_denial_count(), None);
        assert_eq!(state.domain_count(), 2);

        let ruleset = state.ruleset(ruleset_id).unwrap();
        assert_eq!(ruleset.lifecycle(), LifecycleState::Allocated);
        assert_eq!(ruleset.creation_timestamp(), None);
        assert_eq!(ruleset.handled_fs(), None);
        assert_eq!(ruleset.handled_net(), None);
        assert_eq!(ruleset.scoped(), None);
        assert_eq!(ruleset.max_observed_version(), Some(9));
        assert_eq!(ruleset.final_version(), None);
        assert_eq!(ruleset.filesystem_rule_count(), 0);
        assert_eq!(ruleset.network_rule_count(), 0);
        assert_eq!(state.ruleset_count(), 1);
    }

    #[test]
    fn domain_create_does_not_reallocate_deallocated_cross_references() {
        let mut state = State::new();
        let parent_id = DomainId::new(10);
        let ruleset_id = RulesetId::new(11);
        let domain_id = DomainId::new(12);
        apply(
            &mut state,
            Event::FreeDomain(FreeDomainEvent::new(timestamp(20), parent_id, 4)),
        );
        apply(
            &mut state,
            Event::FreeRuleset(FreeRulesetEvent::new(timestamp(21), ruleset_id, 5)),
        );
        apply(
            &mut state,
            Event::CreateDomain(CreateDomainEvent::new(
                timestamp(22),
                ruleset_id,
                7,
                domain_id,
                Some(parent_id),
                100,
                string(b"creator"),
            )),
        );

        let domain = state.domain(domain_id).unwrap();
        assert_eq!(domain.lifecycle(), LifecycleState::Allocated);
        assert_eq!(domain.parent(), Some(DomainParent::Domain(parent_id)));
        assert_eq!(domain.ruleset(), Some(RulesetVersion::new(ruleset_id, 7)));
        let parent = state.domain(parent_id).unwrap();
        assert_eq!(parent.lifecycle(), LifecycleState::Deallocated);
        assert_eq!(parent.free_timestamp(), Some(timestamp(20)));
        assert_eq!(parent.final_denial_count(), Some(4));
        assert_eq!(parent.cumulative_denial_count(), Some(4));
        let ruleset = state.ruleset(ruleset_id).unwrap();
        assert_eq!(ruleset.lifecycle(), LifecycleState::Deallocated);
        assert_eq!(ruleset.free_timestamp(), Some(timestamp(21)));
        assert_eq!(ruleset.final_version(), Some(5));
        assert_eq!(ruleset.max_observed_version(), Some(7));
        assert_eq!(state.domain_count(), 2);
        assert_eq!(state.ruleset_count(), 1);
    }

    #[test]
    fn denial_infers_creator_only_from_one_meaningful_pair() {
        let mut state = State::new();
        let id = DomainId::new(9);
        for snapshot in [hierarchy(9, None, 100, b""), hierarchy(9, None, 0, b"comm")] {
            apply(
                &mut state,
                Event::DenyAccessFs(DenyAccessFsEvent::new(
                    timestamp(1),
                    context(snapshot, 1),
                    FilesystemAccess::from_bits(1),
                    1,
                    2,
                    string(b"path"),
                )),
            );
            let domain = state.domain(id).unwrap();
            assert_eq!(domain.creator_tgid(), None);
            assert_eq!(domain.creator_comm(), None);
        }

        apply(
            &mut state,
            Event::DenyAccessFs(DenyAccessFsEvent::new(
                timestamp(2),
                context(hierarchy(9, None, 200, b"paired"), 2),
                FilesystemAccess::from_bits(1),
                1,
                2,
                string(b"path"),
            )),
        );
        let domain = state.domain(id).unwrap();
        assert_eq!(domain.creator_tgid(), Some(200));
        assert_eq!(domain.creator_comm().unwrap().as_bytes(), b"paired");
    }

    #[test]
    fn every_denial_family_uses_common_late_start_inference_without_double_counting() {
        let mut state = State::new();
        let events = [
            Event::DenyAccessFs(DenyAccessFsEvent::new(
                timestamp(1),
                context(hierarchy(10, Some(20), 0, b""), 7),
                FilesystemAccess::from_bits(1),
                1,
                2,
                string(b"path"),
            )),
            Event::DenyAccessNet(DenyAccessNetEvent::new(
                timestamp(2),
                context(hierarchy(11, None, 111, b"net"), 8),
                NetworkAccess::from_bits(1),
                10,
                20,
            )),
            Event::DenyPtrace(DenyPtraceEvent::new(
                timestamp(3),
                context(hierarchy(12, None, 112, b"ptrace"), 9),
                DomainMembership::Unsandboxed,
                1,
                string(b"target"),
            )),
            Event::DenyScopeSignal(DenyScopeSignalEvent::new(
                timestamp(4),
                context(hierarchy(13, None, 113, b"signal"), 10),
                DomainMembership::Unsandboxed,
                1,
                string(b"target"),
            )),
            Event::DenyScopeAbstractUnixSocket(DenyScopeAbstractUnixSocketEvent::new(
                timestamp(5),
                context(hierarchy(14, None, 114, b"unix"), 11),
                DomainMembership::Unsandboxed,
                1,
            )),
        ];
        for event in events {
            apply(&mut state, event);
        }
        apply(
            &mut state,
            Event::DenyAccessFs(DenyAccessFsEvent::new(
                timestamp(6),
                context(hierarchy(10, Some(20), 0, b""), 7),
                FilesystemAccess::from_bits(1),
                1,
                2,
                string(b"path"),
            )),
        );

        let denying = state.domain(DomainId::new(10)).unwrap();
        assert_eq!(denying.lifecycle(), LifecycleState::Allocated);
        assert_eq!(
            denying.parent(),
            Some(DomainParent::Domain(DomainId::new(20)))
        );
        assert_eq!(denying.creator_tgid(), None);
        assert_eq!(denying.creator_comm(), None);
        assert_eq!(denying.cumulative_denial_count(), Some(7));
        let parent = state.domain(DomainId::new(20)).unwrap();
        assert_eq!(parent.lifecycle(), LifecycleState::Unknown);
        assert_eq!(parent.parent(), None);
        assert_eq!(parent.cumulative_denial_count(), None);
        for (id, count) in [(11, 8), (12, 9), (13, 10), (14, 11)] {
            let domain = state.domain(DomainId::new(id)).unwrap();
            assert_eq!(domain.lifecycle(), LifecycleState::Allocated);
            assert_eq!(domain.cumulative_denial_count(), Some(count));
            assert!(domain.creator_tgid().is_some());
            assert!(domain.creator_comm().is_some());
        }
    }

    #[test]
    fn late_create_upgrades_inference_without_lowering_count_or_reallocating() {
        let mut state = State::new();
        let id = DomainId::new(30);
        apply(
            &mut state,
            Event::DenyAccessFs(DenyAccessFsEvent::new(
                timestamp(30),
                context(hierarchy(30, Some(31), 300, b"inferred"), 50),
                FilesystemAccess::from_bits(1),
                1,
                2,
                string(b"path"),
            )),
        );
        apply(
            &mut state,
            Event::FreeDomain(FreeDomainEvent::new(timestamp(40), id, 45)),
        );
        apply(
            &mut state,
            Event::CreateDomain(CreateDomainEvent::new(
                timestamp(10),
                RulesetId::new(6),
                7,
                id,
                None,
                301,
                string(b"explicit"),
            )),
        );

        let domain = state.domain(id).unwrap();
        assert_eq!(domain.lifecycle(), LifecycleState::Deallocated);
        assert_eq!(domain.creation_timestamp(), Some(timestamp(10)));
        assert_eq!(domain.parent(), Some(DomainParent::Root));
        assert_eq!(domain.creator_tgid(), Some(301));
        assert_eq!(domain.creator_comm().unwrap().as_bytes(), b"explicit");
        assert_eq!(
            domain.ruleset(),
            Some(RulesetVersion::new(RulesetId::new(6), 7))
        );
        assert_eq!(domain.cumulative_denial_count(), Some(50));
    }

    #[test]
    fn unseen_deallocation_tombstones_are_monotonic_and_never_reallocate() {
        let mut state = State::new();
        let domain_id = DomainId::new(40);
        let ruleset_id = RulesetId::new(41);
        for event in [
            Event::FreeDomain(FreeDomainEvent::new(timestamp(30), domain_id, 9)),
            Event::FreeDomain(FreeDomainEvent::new(timestamp(20), domain_id, 7)),
            Event::FreeDomain(FreeDomainEvent::new(timestamp(40), domain_id, 11)),
            Event::FreeRuleset(FreeRulesetEvent::new(timestamp(30), ruleset_id, 9)),
            Event::FreeRuleset(FreeRulesetEvent::new(timestamp(20), ruleset_id, 7)),
            Event::FreeRuleset(FreeRulesetEvent::new(timestamp(40), ruleset_id, 11)),
        ] {
            apply(&mut state, event);
        }
        apply(
            &mut state,
            Event::EnforceDomain(EnforceDomainEvent::new(
                timestamp(50),
                domain_id,
                1,
                true,
                true,
                true,
            )),
        );
        apply(
            &mut state,
            Event::AddRuleNet(AddRuleNetEvent::new(
                timestamp(50),
                ruleset_id,
                12,
                NetworkAccess::from_bits(1),
                80,
            )),
        );

        let domain = state.domain(domain_id).unwrap();
        assert_eq!(domain.lifecycle(), LifecycleState::Deallocated);
        assert_eq!(domain.free_timestamp(), Some(timestamp(40)));
        assert_eq!(domain.final_denial_count(), Some(11));
        assert_eq!(domain.cumulative_denial_count(), Some(11));
        let ruleset = state.ruleset(ruleset_id).unwrap();
        assert_eq!(ruleset.lifecycle(), LifecycleState::Deallocated);
        assert_eq!(ruleset.free_timestamp(), Some(timestamp(40)));
        assert_eq!(ruleset.final_version(), Some(11));
        assert_eq!(ruleset.max_observed_version(), Some(12));
    }

    #[test]
    fn enforcement_keeps_latest_per_tid_and_survives_deallocation() {
        let mut state = State::new();
        let id = DomainId::new(50);
        assert!(state.domain(id).is_none());
        for event in [
            Event::EnforceDomain(EnforceDomainEvent::new(
                timestamp(20),
                id,
                100,
                true,
                true,
                true,
            )),
            Event::EnforceDomain(EnforceDomainEvent::new(
                timestamp(10),
                id,
                100,
                false,
                false,
                false,
            )),
            Event::EnforceDomain(EnforceDomainEvent::new(
                timestamp(25),
                id,
                100,
                false,
                false,
                false,
            )),
            Event::EnforceDomain(EnforceDomainEvent::new(
                timestamp(10),
                id,
                100,
                true,
                false,
                true,
            )),
        ] {
            apply(&mut state, event);
        }
        let selected = state.domain(id).unwrap().enforcement_event(100).unwrap();
        assert_eq!(selected.timestamp(), timestamp(25));
        assert!(!selected.complete());
        assert!(state.domain(id).unwrap().any_process_wide_enforcement());

        for event in [
            Event::EnforceDomain(EnforceDomainEvent::new(
                timestamp(25),
                id,
                100,
                true,
                false,
                false,
            )),
            Event::EnforceDomain(EnforceDomainEvent::new(
                timestamp(30),
                id,
                101,
                false,
                false,
                true,
            )),
            Event::FreeDomain(FreeDomainEvent::new(timestamp(40), id, 0)),
        ] {
            apply(&mut state, event);
        }

        let domain = state.domain(id).unwrap();
        assert_eq!(domain.lifecycle(), LifecycleState::Deallocated);
        assert_eq!(domain.enforcement_event_count(), 2);
        assert_eq!(domain.enforcement_events().count(), 2);
        let first = domain.enforcement_event(100).unwrap();
        assert_eq!(first.domain_id(), id);
        assert_eq!(first.enforcing_tid(), 100);
        assert_eq!(first.timestamp(), timestamp(25));
        assert!(first.complete());
        assert!(!first.process_wide());
        assert!(!first.no_new_privs());
        let second = domain.enforcement_event(101).unwrap();
        assert_eq!(second.domain_id(), id);
        assert_eq!(second.enforcing_tid(), 101);
        assert_eq!(second.timestamp(), timestamp(30));
        assert!(!second.complete());
        assert!(!second.process_wide());
        assert!(second.no_new_privs());
        assert!(domain.any_process_wide_enforcement());
        assert_eq!(domain.no_new_privs(), Some(false));

        apply(
            &mut state,
            Event::EnforceDomain(EnforceDomainEvent::new(
                timestamp(50),
                id,
                100,
                true,
                true,
                true,
            )),
        );
        let domain = state.domain(id).unwrap();
        assert_eq!(domain.lifecycle(), LifecycleState::Deallocated);
        assert_eq!(domain.no_new_privs(), Some(true));
    }

    #[test]
    fn relational_placeholders_exclude_unsandboxed_zero() {
        let mut state = State::new();
        apply(
            &mut state,
            Event::DenyPtrace(DenyPtraceEvent::new(
                timestamp(1),
                context(hierarchy(60, None, 1, b"one"), 1),
                DomainMembership::Sandboxed(DomainId::new(61)),
                2,
                string(b"two"),
            )),
        );
        apply(
            &mut state,
            Event::DenyScopeSignal(DenyScopeSignalEvent::new(
                timestamp(2),
                context(hierarchy(62, None, 1, b"one"), 1),
                DomainMembership::Unsandboxed,
                2,
                string(b"two"),
            )),
        );

        let other = state.domain(DomainId::new(61)).unwrap();
        assert_eq!(other.lifecycle(), LifecycleState::Unknown);
        assert_eq!(other.cumulative_denial_count(), None);
        assert!(state.domain(DomainId::new(0)).is_none());
    }

    #[test]
    fn unknown_is_noop_and_duplicate_lifecycle_events_are_idempotent() {
        let mut state = State::new();
        apply(
            &mut state,
            Event::Unknown(UnknownEvent::new(timestamp(1), 200, 344)),
        );
        assert_eq!(state.ruleset_count(), 0);
        assert_eq!(state.domain_count(), 0);

        let id = RulesetId::new(70);
        let create = Event::CreateRuleset(CreateRulesetEvent::new(
            timestamp(2),
            id,
            1,
            FilesystemAccess::from_bits(1),
            NetworkAccess::from_bits(2),
            ScopeAccess::from_bits(1),
        ));
        apply(&mut state, create.clone());
        apply(&mut state, create);
        assert_eq!(state.ruleset_count(), 1);
        let ruleset = state.ruleset(id).unwrap();
        assert_eq!(ruleset.lifecycle(), LifecycleState::Allocated);
        assert_eq!(ruleset.creation_timestamp(), Some(timestamp(2)));
        assert_eq!(ruleset.max_observed_version(), Some(1));
        assert_eq!(ruleset.handled_fs().unwrap().bits(), 1);
        assert_eq!(ruleset.handled_net().unwrap().bits(), 2);
        assert_eq!(ruleset.scoped().unwrap().bits(), 1);
        assert_eq!(ruleset.filesystem_rule_count(), 0);
        assert_eq!(ruleset.network_rule_count(), 0);

        let free = Event::FreeRuleset(FreeRulesetEvent::new(timestamp(3), id, 1));
        apply(&mut state, free.clone());
        apply(&mut state, free);
        assert_eq!(state.ruleset_count(), 1);
        let ruleset = state.ruleset(id).unwrap();
        assert_eq!(ruleset.lifecycle(), LifecycleState::Deallocated);
        assert_eq!(ruleset.free_timestamp(), Some(timestamp(3)));
        assert_eq!(ruleset.final_version(), Some(1));
        assert_eq!(ruleset.max_observed_version(), Some(1));
    }
}
