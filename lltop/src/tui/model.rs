// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{HashMap, HashSet};

use landlock_observability::aggregate::{AggregatedDenial, DenialAggregator, DenialKey};
use landlock_observability::event::{DomainId, Event, KernelTimestamp, RulesetId};
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
        let kind = match event {
            Event::DenyAccessFs(_) => Some(0),
            Event::DenyAccessNet(_) => Some(1),
            Event::DenyPtrace(_) => Some(2),
            Event::DenyScopeSignal(_) => Some(3),
            Event::DenyScopeAbstractUnixSocket(_) => Some(4),
            _ => None,
        };
        if let Some(kind) = kind {
            self.stats.total = self.stats.total.saturating_add(1);
            self.stats.by_kind[kind] = self.stats.by_kind[kind].saturating_add(1);
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
            children: &HashMap<Option<DomainId>, Vec<DomainId>>,
            trail: &mut Vec<bool>,
            visited: &mut HashSet<DomainId>,
            output: &mut Vec<(DomainId, Vec<bool>)>,
        ) {
            if !visited.insert(id) {
                return;
            }
            output.push((id, trail.clone()));
            if let Some(descendants) = children.get(&Some(id)) {
                for (index, child) in descendants.iter().enumerate() {
                    trail.push(index + 1 == descendants.len());
                    append(*child, children, trail, visited, output);
                    trail.pop();
                }
            }
        }

        let mut output = Vec::new();
        let mut visited = HashSet::new();
        let roots = children.get(&None).cloned().unwrap_or_default();
        for (index, root) in roots.iter().enumerate() {
            append(
                *root,
                &children,
                &mut vec![index + 1 == roots.len()],
                &mut visited,
                &mut output,
            );
        }
        let mut remaining = domains.keys().copied().collect::<Vec<_>>();
        remaining.sort_unstable_by_key(|id| id.get());
        for id in remaining {
            if !visited.contains(&id) {
                append(id, &children, &mut vec![true], &mut visited, &mut output);
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
        CapturedString, CreateDomainEvent, EnforceDomainEvent, RulesetId,
    };

    fn create(id: u64, parent: Option<u64>) -> Event {
        Event::CreateDomain(CreateDomainEvent::new(
            KernelTimestamp::from_nanoseconds(id),
            RulesetId::new(1),
            0,
            DomainId::new(id),
            parent.map(DomainId::new),
            1,
            CapturedString::new(b"x".to_vec(), false).unwrap(),
        ))
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
        model.observe(&Event::EnforceDomain(EnforceDomainEvent::new(
            KernelTimestamp::from_nanoseconds(5),
            DomainId::new(5),
            1,
            true,
            false,
        )));
        assert_eq!(model.allocated_domains(), 5);
        assert_eq!(model.allocated_rulesets(), 1);
        assert_eq!(
            model.domain_tree(),
            [
                (DomainId::new(1), vec![false]),
                (DomainId::new(2), vec![false, false]),
                (DomainId::new(4), vec![false, false, true]),
                (DomainId::new(3), vec![false, true]),
                (DomainId::new(5), vec![true]),
            ]
        );
    }
}
