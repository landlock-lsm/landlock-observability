// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{HashMap, HashSet};

use landlock_observability::aggregate::{AggregatedDenial, DenialAggregator, DenialKey};
use landlock_observability::event::{DomainId, Event, KernelTimestamp, Observation, RulesetId};
use landlock_observability::state::{DomainParent, DomainState, LifecycleState, State};

const KIND_COUNT: usize = 5;

#[derive(Default)]
pub(super) struct Stats {
    pub(super) total: u64,
    pub(super) by_kind: [u64; KIND_COUNT],
}

pub(super) struct ObservationModel {
    pub(super) state: State,
    pub(super) denials: DenialAggregator,
    pub(super) stats: Stats,
    pub(super) latest_seen: KernelTimestamp,
}

impl ObservationModel {
    pub(super) fn new() -> Self {
        Self {
            state: State::new(),
            denials: DenialAggregator::new(),
            stats: Stats::default(),
            latest_seen: KernelTimestamp::from_nanoseconds(0),
        }
    }

    pub(super) fn observe(&mut self, event: &Event) {
        self.latest_seen = KernelTimestamp::from_nanoseconds(
            self.latest_seen
                .as_nanoseconds()
                .max(event.timestamp().as_nanoseconds()),
        );
        let [fs, net, ptrace, signal, abstract_unix] = &mut self.stats.by_kind;
        let count = match event {
            Event::DenyAccessFs(_) => Some(fs),
            Event::DenyAccessNet(_) => Some(net),
            Event::DenyPtrace(_) => Some(ptrace),
            Event::DenyScopeSignal(_) => Some(signal),
            Event::DenyScopeAbstractUnixSocket(_) => Some(abstract_unix),
            _ => None,
        };
        if let Some(count) = count {
            self.stats.total = self.stats.total.saturating_add(1);
            *count = count.saturating_add(1);
        }
        self.state.apply(event);
        self.denials.observe(event);
    }

    pub(super) fn allocated_domains(&self) -> usize {
        self.state
            .domains()
            .filter(|domain| domain.lifecycle() == LifecycleState::Allocated)
            .count()
    }

    pub(super) fn allocated_rulesets(&self) -> usize {
        self.state
            .rulesets()
            .filter(|ruleset| ruleset.lifecycle() == LifecycleState::Allocated)
            .count()
    }

    pub(super) fn denial_age_ns(&self, denial: &AggregatedDenial) -> u64 {
        self.latest_seen
            .as_nanoseconds()
            .saturating_sub(denial.latest_timestamp().as_nanoseconds())
    }

    pub(super) fn denial(&self, key: &DenialKey) -> Option<&AggregatedDenial> {
        self.denials.get(key)
    }

    /// Returns domains in tree order with each ancestor's last-child bit.
    pub(super) fn domain_tree(&self) -> Vec<(DomainId, Vec<bool>)> {
        let domains = self
            .state
            .domains()
            .map(|domain| (domain.domain_id(), domain))
            .collect::<HashMap<_, _>>();
        let mut children: HashMap<Option<DomainId>, Vec<DomainId>> = HashMap::new();
        for domain in domains.values() {
            let parent = match domain.parent() {
                None | Some(DomainParent::Root) => None,
                Some(DomainParent::Domain(id)) if domains.contains_key(&id) => Some(id),
                Some(DomainParent::Domain(_)) => None,
            };
            children.entry(parent).or_default().push(domain.domain_id());
        }
        for values in children.values_mut() {
            values.sort_unstable_by_key(|id| id.get());
        }

        fn append(
            id: DomainId,
            trail: Vec<bool>,
            children: &HashMap<Option<DomainId>, Vec<DomainId>>,
            visited: &mut HashSet<DomainId>,
            output: &mut Vec<(DomainId, Vec<bool>)>,
        ) {
            let mut pending = vec![(id, trail)];
            while let Some((id, trail)) = pending.pop() {
                if !visited.insert(id) {
                    continue;
                }
                output.push((id, trail.clone()));
                if let Some(descendants) = children.get(&Some(id)) {
                    let last = descendants.len().saturating_sub(1);
                    for (index, child) in descendants.iter().enumerate().rev() {
                        let mut child_trail = trail.clone();
                        child_trail.push(index == last);
                        pending.push((*child, child_trail));
                    }
                }
            }
        }

        let mut output = Vec::new();
        let mut visited = HashSet::new();
        let roots = children.get(&None).cloned().unwrap_or_default();
        let last_root = roots.len().saturating_sub(1);
        for (index, root) in roots.iter().enumerate() {
            append(
                *root,
                vec![index == last_root],
                &children,
                &mut visited,
                &mut output,
            );
        }
        let mut remaining = domains.keys().copied().collect::<Vec<_>>();
        remaining.sort_unstable_by_key(|id| id.get());
        for id in remaining {
            if !visited.contains(&id) {
                append(id, vec![true], &children, &mut visited, &mut output);
            }
        }
        output
    }
}

pub(super) fn domain_ruleset(domain: &DomainState) -> Option<RulesetId> {
    domain.ruleset().map(|ruleset| ruleset.ruleset_id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use landlock_observability::event::{
        CapturedCommand, CreateDomainEvent, EnforceDomainEvent, ProcessId, ThreadId,
        MIN_LANDLOCK_ID,
    };

    fn create(id_offset: u64, parent_offset: Option<u64>) -> Event {
        Event::CreateDomain(
            CreateDomainEvent::builder()
                .timestamp(KernelTimestamp::from_nanoseconds(id_offset))
                .ruleset_id(RulesetId::new(MIN_LANDLOCK_ID + 1).unwrap())
                .ruleset_version(0)
                .domain_id(DomainId::new(MIN_LANDLOCK_ID + id_offset).unwrap())
                .parent_id(
                    parent_offset.map(|offset| DomainId::new(MIN_LANDLOCK_ID + offset).unwrap()),
                )
                .creator_tgid(ProcessId::new(1).unwrap())
                .creator_comm(CapturedCommand::new(b"x".to_vec(), false).unwrap())
                .build(),
        )
    }

    #[test]
    fn tree_retains_ancestor_last_child_metadata() {
        let mut model = ObservationModel::new();
        for event in [
            create(1, None),
            create(2, Some(1)),
            create(3, Some(1)),
            create(4, Some(2)),
        ] {
            model.observe(&event);
        }
        model.observe(&Event::EnforceDomain(
            EnforceDomainEvent::builder()
                .timestamp(KernelTimestamp::from_nanoseconds(5))
                .domain_id(DomainId::new(MIN_LANDLOCK_ID + 5).unwrap())
                .enforcing_tid(ThreadId::new(1).unwrap())
                .complete(true)
                .process_wide(false)
                .no_new_privs(true)
                .build(),
        ));
        assert_eq!(model.allocated_domains(), 5);
        assert_eq!(model.allocated_rulesets(), 1);
        assert_eq!(
            model.domain_tree(),
            [
                (DomainId::new(MIN_LANDLOCK_ID + 1).unwrap(), vec![false]),
                (
                    DomainId::new(MIN_LANDLOCK_ID + 2).unwrap(),
                    vec![false, false]
                ),
                (
                    DomainId::new(MIN_LANDLOCK_ID + 4).unwrap(),
                    vec![false, false, true]
                ),
                (
                    DomainId::new(MIN_LANDLOCK_ID + 3).unwrap(),
                    vec![false, true]
                ),
                (DomainId::new(MIN_LANDLOCK_ID + 5).unwrap(), vec![true]),
            ]
        );
    }

    #[test]
    fn cyclic_observations_are_rendered_once_without_recursion() {
        let mut model = ObservationModel::new();
        model.observe(&create(1, Some(2)));
        model.observe(&create(2, Some(1)));

        assert_eq!(
            model.domain_tree(),
            [
                (DomainId::new(MIN_LANDLOCK_ID + 1).unwrap(), vec![true]),
                (
                    DomainId::new(MIN_LANDLOCK_ID + 2).unwrap(),
                    vec![true, true]
                ),
            ]
        );
    }
}
