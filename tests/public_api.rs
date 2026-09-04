// SPDX-License-Identifier: MIT OR Apache-2.0

use landlock_observability::collector::{
    CollectorReceiveErrorKind, ReceiveTimeoutError, TryReceiveError,
};
use landlock_observability::event::{
    DomainId, DomainMembership, EnforceDomainEvent, Event, KernelTimestamp,
};
use landlock_observability::state::{DomainParent, LifecycleState, State};

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
        LifecycleState::Unknown => "unknown",
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

fn timeout_kind(error: ReceiveTimeoutError) -> Option<CollectorReceiveErrorKind> {
    match error {
        ReceiveTimeoutError::Timeout => None,
        ReceiveTimeoutError::Collector(error) => Some(error.kind()),
        _ => None,
    }
}

#[test]
fn collector_receive_variants_expose_their_errors() {
    assert_eq!(try_receive_kind(TryReceiveError::Empty), None);
    assert_eq!(timeout_kind(ReceiveTimeoutError::Timeout), None);
}

#[test]
fn public_state_enums_are_exhaustive() {
    let id = DomainId::new(0x1_0000_0000);
    assert_eq!(domain_parent_id(DomainParent::Root), None);
    assert_eq!(domain_parent_id(DomainParent::Domain(id)), Some(id));
    assert_eq!(membership_id(DomainMembership::Unsandboxed), None);
    assert_eq!(membership_id(DomainMembership::Sandboxed(id)), Some(id));
    assert_eq!(lifecycle_name(LifecycleState::Unknown), "unknown");
    assert_eq!(lifecycle_name(LifecycleState::Allocated), "allocated");
    assert_eq!(lifecycle_name(LifecycleState::Deallocated), "deallocated");
}

#[test]
fn enforcement_accessors_expose_events() {
    let id = DomainId::new(0x1_0000_0001);
    let event = EnforceDomainEvent::new(
        KernelTimestamp::from_nanoseconds(9),
        id,
        10,
        true,
        false,
        true,
    );
    let mut state = State::new();
    state.apply(&Event::EnforceDomain(event.clone()));

    let domain = state.domain(id).unwrap();
    let selected: &EnforceDomainEvent = domain.enforcement_event(10).unwrap();
    assert_eq!(selected, &event);
    let events: Vec<&EnforceDomainEvent> = domain.enforcement_events().collect();
    assert_eq!(selected.domain_id(), id);
    assert!(selected.no_new_privs());
    assert_eq!(events, vec![selected]);
    assert_eq!(domain.enforcement_event_count(), 1);
    assert_eq!(domain.no_new_privs(), Some(true));
}
