// SPDX-License-Identifier: MIT OR Apache-2.0

use landlock_observability::collector::{
    CollectorConfig, CollectorReceiveErrorKind, ReceiveTimeoutError, TryReceiveError,
};
use landlock_observability::event::{
    CreateRulesetEvent, DenyScopeAbstractUnixSocketEvent, DomainId, DomainMembership,
    EnforceDomainEvent, Event, FilesystemAccess, KernelTimestamp, NetworkAccess, ProcessId,
    RulesetId, ScopeAccess, ThreadId, MIN_LANDLOCK_ID,
};
use landlock_observability::state::{DomainParent, LifecycleState, RulesetVersion, State};

// These matches intentionally have no wildcard: the value domains are closed.
fn domain_parent_id(parent: DomainParent) -> Option<DomainId> {
    match parent {
        DomainParent::Root => None,
        DomainParent::Domain(id) => Some(id),
    }
}

fn membership_id(membership: DomainMembership) -> Option<DomainId> {
    match membership {
        DomainMembership::Unsandboxed => None,
        DomainMembership::Sandboxed(id) => Some(id),
    }
}

fn lifecycle_name(lifecycle: LifecycleState) -> &'static str {
    match lifecycle {
        LifecycleState::Allocated => "allocated",
        LifecycleState::Deallocated => "deallocated",
    }
}

fn try_receive_kind(error: TryReceiveError) -> Option<CollectorReceiveErrorKind> {
    match error {
        TryReceiveError::Empty => None,
        TryReceiveError::Collector(error) => Some(error.kind()),
        _ => None,
    }
}

fn peer_pid(event: &DenyScopeAbstractUnixSocketEvent) -> Option<ProcessId> {
    event.peer_pid()
}

fn timeout_kind(error: ReceiveTimeoutError) -> Option<CollectorReceiveErrorKind> {
    match error {
        ReceiveTimeoutError::Timeout => None,
        ReceiveTimeoutError::Collector(error) => Some(error.kind()),
        _ => None,
    }
}

#[test]
fn collector_configuration_has_an_inert_default() {
    let default = CollectorConfig::default();
    assert_eq!(default.event_capacity(), 1024);
    assert_eq!(
        CollectorConfig::builder().build().unwrap().event_capacity(),
        default.event_capacity()
    );
}

#[test]
fn collector_receive_variants_expose_their_errors() {
    assert_eq!(try_receive_kind(TryReceiveError::Empty), None);
    assert_eq!(timeout_kind(ReceiveTimeoutError::Timeout), None);
}

#[test]
fn public_state_enums_are_exhaustive() {
    let id = DomainId::new(0x1_0000_0000).unwrap();
    assert_eq!(domain_parent_id(DomainParent::Root), None);
    assert_eq!(domain_parent_id(DomainParent::Domain(id)), Some(id));
    assert_eq!(membership_id(DomainMembership::Unsandboxed), None);
    assert_eq!(membership_id(DomainMembership::Sandboxed(id)), Some(id));
    assert_eq!(lifecycle_name(LifecycleState::Allocated), "allocated");
    assert_eq!(lifecycle_name(LifecycleState::Deallocated), "deallocated");
}

#[test]
fn canonical_identifiers_have_public_display_contracts() {
    let domain = DomainId::new(MIN_LANDLOCK_ID).unwrap();
    assert_eq!(domain.to_string(), "100000000");
    assert_eq!(format!("{domain:#020}"), "100000000");
    assert_eq!(format!("{domain:*>20}"), "100000000");

    let ruleset = RulesetVersion::new(RulesetId::new(MIN_LANDLOCK_ID).unwrap(), 7);
    assert_eq!(ruleset.to_string(), "100000000.7");
    assert_eq!(format!("{ruleset:#020}"), "100000000.7");
    assert_eq!(format!("{ruleset:*>20}"), "100000000.7");
}

#[test]
fn task_ids_are_checked_and_peer_pid_is_optional() {
    let process = ProcessId::new(1).unwrap();
    let thread = ThreadId::try_from(2).unwrap();
    assert_eq!(process.get(), 1);
    assert_eq!(u32::from(thread), 2);
    assert_eq!(ProcessId::new(0).unwrap_err().value(), 0);

    let _peer_accessor: fn(&DenyScopeAbstractUnixSocketEvent) -> Option<ProcessId> = peer_pid;
}

#[test]
fn direct_ruleset_version_and_enforcement_accessors() {
    let ruleset_id = RulesetId::new(0x1_0000_0001).unwrap();
    let create = CreateRulesetEvent::builder()
        .timestamp(KernelTimestamp::from_nanoseconds(8))
        .ruleset_id(ruleset_id)
        .ruleset_version(3)
        .handled_fs(FilesystemAccess::from_bits(1))
        .handled_net(NetworkAccess::from_bits(2))
        .scoped(ScopeAccess::from_bits(1))
        .build();
    let mut state = State::new();
    state.apply(&Event::CreateRuleset(create));
    let version: u32 = state.ruleset(ruleset_id).unwrap().max_observed_version();
    assert_eq!(version, 3);

    let id = DomainId::new(0x1_0000_0002).unwrap();
    let tid = ThreadId::new(10).unwrap();
    let event = EnforceDomainEvent::builder()
        .timestamp(KernelTimestamp::from_nanoseconds(9))
        .domain_id(id)
        .enforcing_tid(tid)
        .complete(true)
        .process_wide(false)
        .no_new_privs(true)
        .build();
    state.apply(&Event::EnforceDomain(event.clone()));

    let domain = state.domain(id).unwrap();
    let lifecycle: LifecycleState = domain.lifecycle();
    assert_eq!(lifecycle, LifecycleState::Allocated);
    let selected: &EnforceDomainEvent = domain.enforcement_event(tid).unwrap();
    assert_eq!(selected, &event);
    let events: Vec<&EnforceDomainEvent> = domain.enforcement_events().collect();
    assert_eq!(selected.domain_id(), id);
    assert!(selected.no_new_privs());
    assert_eq!(events, vec![selected]);
    assert_eq!(domain.enforcement_event_count(), 1);
    assert_eq!(domain.no_new_privs(), Some(true));
}
