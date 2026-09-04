// SPDX-License-Identifier: MIT OR Apache-2.0

use std::io::{self, Write};

use landlock_observability::aggregate::{AggregatedDenial, DenialAggregator};
use landlock_observability::event::{
    CapturedString, DomainId, DomainMembership, Event, FilesystemAccess, NetworkAccess, RulesetId,
};
use landlock_observability::state::{DomainParent, DomainState, LifecycleState, State};

const DENIAL_KIND_COUNT: usize = 5;

#[derive(Clone, Copy)]
enum DenialKind {
    Fs,
    Net,
    Ptrace,
    Signal,
    AbstractUnix,
}

impl DenialKind {
    const ALL: [Self; DENIAL_KIND_COUNT] = [
        Self::Fs,
        Self::Net,
        Self::Ptrace,
        Self::Signal,
        Self::AbstractUnix,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Fs => 0,
            Self::Net => 1,
            Self::Ptrace => 2,
            Self::Signal => 3,
            Self::AbstractUnix => 4,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Fs => "FS",
            Self::Net => "NET",
            Self::Ptrace => "PTRACE",
            Self::Signal => "SIGNAL",
            Self::AbstractUnix => "ABSTRACT_UNIX",
        }
    }

    const fn stats_label(self) -> &'static str {
        match self {
            Self::Fs => "fs",
            Self::Net => "net",
            Self::Ptrace => "ptrace",
            Self::Signal => "signal",
            Self::AbstractUnix => "abstract_unix",
        }
    }

    fn from_event(event: &Event) -> Option<Self> {
        match event {
            Event::DenyAccessFs(_) => Some(Self::Fs),
            Event::DenyAccessNet(_) => Some(Self::Net),
            Event::DenyPtrace(_) => Some(Self::Ptrace),
            Event::DenyScopeSignal(_) => Some(Self::Signal),
            Event::DenyScopeAbstractUnixSocket(_) => Some(Self::AbstractUnix),
            _ => None,
        }
    }
}

#[derive(Default)]
struct Stats {
    total_denials: u64,
    denials: [u64; DENIAL_KIND_COUNT],
}

impl Stats {
    fn observe(&mut self, kind: DenialKind) {
        self.total_denials = self.total_denials.saturating_add(1);
        let counter = &mut self.denials[kind.index()];
        *counter = counter.saturating_add(1);
    }
}

pub(crate) struct Batch {
    state: State,
    denials: DenialAggregator,
    stats: Stats,
    allocated_domains: usize,
}

impl Batch {
    pub(crate) fn new() -> Self {
        Self {
            state: State::new(),
            denials: DenialAggregator::new(),
            stats: Stats::default(),
            allocated_domains: 0,
        }
    }

    fn process(&mut self, event: &Event) -> Vec<String> {
        let affected_domains = affected_domain_ids(event);
        let previous_domains = affected_domains
            .iter()
            .map(|id| {
                self.state.domain(*id).map(|domain| {
                    (
                        format_domain(domain),
                        domain.lifecycle() == LifecycleState::Allocated,
                    )
                })
            })
            .collect::<Vec<_>>();
        let deallocated_ruleset = match event {
            Event::FreeRuleset(event) => Some((
                event.ruleset_id(),
                deallocated_ruleset_identity(&self.state, event.ruleset_id()),
            )),
            _ => None,
        };
        let previous_domain_counts = (self.allocated_domains, self.state.domain_count());

        self.state.apply(event);
        let denial_record = DenialKind::from_event(event).and_then(|kind| {
            self.denials
                .observe_entry(event)
                .map(|denial| format_denial(kind, denial))
        });
        if let Some(kind) = DenialKind::from_event(event) {
            self.stats.observe(kind);
        }

        let mut records = Vec::new();
        for (id, previous) in affected_domains.into_iter().zip(previous_domains) {
            let current = self.state.domain(id).map(|domain| {
                (
                    format_domain(domain),
                    domain.lifecycle() == LifecycleState::Allocated,
                )
            });
            match (
                previous.as_ref().map(|(_, allocated)| *allocated),
                current.as_ref(),
            ) {
                (Some(true), Some((_, false))) => self.allocated_domains -= 1,
                (Some(false) | None, Some((_, true))) => self.allocated_domains += 1,
                _ => {}
            }
            if current.as_ref().map(|(record, _)| record)
                != previous.as_ref().map(|(record, _)| record)
            {
                if let Some((record, _)) = current {
                    records.push(record);
                }
            }
        }

        if let Some((id, previous)) = deallocated_ruleset {
            let current = deallocated_ruleset_identity(&self.state, id);
            if current != previous {
                if let Some((id, version)) = current {
                    records.push(format!("DROP_RULESET ruleset={}", ruleset(id, version)));
                }
            }
        }

        if let Some(record) = denial_record {
            records.push(record);
        }

        let domain_counts = (self.allocated_domains, self.state.domain_count());
        if !records.is_empty() || previous_domain_counts != domain_counts {
            records.push(format_stats(
                self.allocated_domains,
                self.state.domain_count(),
                &self.stats,
            ));
        }
        records
    }

    pub(crate) fn process_and_write<W: Write>(
        &mut self,
        event: &Event,
        output: &mut W,
    ) -> io::Result<()> {
        let records = self.process(event);
        if records.is_empty() {
            return Ok(());
        }
        for record in records {
            writeln!(output, "{record}")?;
        }
        output.flush()
    }
}

fn affected_domain_ids(event: &Event) -> Vec<DomainId> {
    fn add_denial(
        ids: &mut Vec<DomainId>,
        domain: DomainId,
        parent: Option<DomainId>,
        membership: Option<DomainMembership>,
    ) {
        ids.push(domain);
        ids.extend(parent);
        if let Some(DomainMembership::Sandboxed(id)) = membership {
            ids.push(id);
        }
    }

    let mut ids = Vec::with_capacity(3);
    match event {
        Event::CreateDomain(event) => {
            ids.push(event.domain_id());
            ids.extend(event.parent_id());
        }
        Event::FreeDomain(event) => ids.push(event.domain_id()),
        Event::EnforceDomain(event) => ids.push(event.domain_id()),
        Event::DenyAccessFs(event) => add_denial(
            &mut ids,
            event.context().hierarchy().domain_id(),
            event.context().hierarchy().parent_id(),
            None,
        ),
        Event::DenyAccessNet(event) => add_denial(
            &mut ids,
            event.context().hierarchy().domain_id(),
            event.context().hierarchy().parent_id(),
            None,
        ),
        Event::DenyPtrace(event) => add_denial(
            &mut ids,
            event.context().hierarchy().domain_id(),
            event.context().hierarchy().parent_id(),
            Some(event.tracee_domain()),
        ),
        Event::DenyScopeSignal(event) => add_denial(
            &mut ids,
            event.context().hierarchy().domain_id(),
            event.context().hierarchy().parent_id(),
            Some(event.target_domain()),
        ),
        Event::DenyScopeAbstractUnixSocket(event) => add_denial(
            &mut ids,
            event.context().hierarchy().domain_id(),
            event.context().hierarchy().parent_id(),
            Some(event.peer_domain()),
        ),
        _ => {}
    }
    ids.sort_unstable_by_key(|id| id.get());
    ids.dedup();
    ids
}

fn deallocated_ruleset_identity(state: &State, id: RulesetId) -> Option<(RulesetId, u32)> {
    let ruleset = state.ruleset(id)?;
    if ruleset.lifecycle() != LifecycleState::Deallocated {
        return None;
    }
    ruleset.final_version().map(|version| (id, version))
}

fn hex_id(value: u64) -> String {
    format!("{value:x}")
}

fn ruleset(id: RulesetId, version: u32) -> String {
    format!("{}.{version}", hex_id(id.get()))
}

fn format_domain(domain: &DomainState) -> String {
    let parent = match domain.parent() {
        None => "?".to_owned(),
        Some(DomainParent::Root) => "0".to_owned(),
        Some(DomainParent::Domain(id)) => hex_id(id.get()),
    };
    let ruleset = domain.ruleset().map_or_else(
        || "?".to_owned(),
        |value| ruleset(value.ruleset_id(), value.ruleset_version()),
    );
    let creator = match (domain.creator_comm(), domain.creator_tgid()) {
        (Some(comm), Some(tgid)) => format!("{}[{tgid}]", escape(comm)),
        _ => "?".to_owned(),
    };
    let no_new_privs = domain
        .no_new_privs()
        .map_or("?", |value| if value { "1" } else { "0" });
    format!(
        "DOMAIN domain={} parent={parent} ruleset={ruleset} creator={creator} no_new_privs={no_new_privs}",
        hex_id(domain.domain_id().get())
    )
}

fn escape(value: &CapturedString) -> String {
    let mut escaped = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/') {
            escaped.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            write!(escaped, "\\x{byte:02x}").expect("writing to a String cannot fail");
        }
    }
    escaped
}

fn filesystem_blockers(access: FilesystemAccess) -> String {
    access_blockers(
        "FS",
        access.known_names().map(|name| name.as_str()),
        access.unknown_bits(),
    )
}

fn network_blockers(access: NetworkAccess) -> String {
    access_blockers(
        "Net",
        access.known_names().map(|name| name.as_str()),
        access.unknown_bits(),
    )
}

fn access_blockers<'a>(
    prefix: &str,
    names: impl Iterator<Item = &'a str>,
    unknown_bits: u32,
) -> String {
    let mut parts = names.map(str::to_owned).collect::<Vec<_>>();
    if unknown_bits != 0 {
        parts.push(format!("0x{unknown_bits:x}"));
    }
    if parts.is_empty() {
        format!("0x{unknown_bits:x}")
    } else {
        format!("{prefix}:{}", parts.join(","))
    }
}

fn domain_membership(value: DomainMembership) -> u64 {
    value.domain_id().map_or(0, DomainId::get)
}

fn elapsed(first_ns: u64, latest_ns: u64) -> String {
    let seconds = latest_ns.saturating_sub(first_ns) / 1_000_000_000;
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m{}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h{}m", seconds / 3600, (seconds % 3600) / 60)
    }
}

fn format_denial(kind: DenialKind, denial: &AggregatedDenial) -> String {
    let event = denial.latest_event();
    let (domain, blockers, target, relation) = match event {
        Event::DenyAccessFs(event) => (
            event.context().hierarchy().domain_id(),
            filesystem_blockers(event.blockers()),
            escape(event.pathname()),
            None,
        ),
        Event::DenyAccessNet(event) => {
            let (mut has_bind, mut has_connect) = (false, false);
            for name in event.blockers().known_names() {
                has_bind |= name.as_str().starts_with("bind_");
                has_connect |= name.as_str().starts_with("connect_");
            }
            let target = match (has_bind, has_connect) {
                (true, false) => format!("sport:{}", event.source_port()),
                (false, true) => format!("dport:{}", event.destination_port()),
                _ => format!(
                    "sport:{},dport:{}",
                    event.source_port(),
                    event.destination_port()
                ),
            };
            (
                event.context().hierarchy().domain_id(),
                network_blockers(event.blockers()),
                target,
                None,
            )
        }
        Event::DenyPtrace(event) => (
            event.context().hierarchy().domain_id(),
            "ptrace".to_owned(),
            format!("pid:{}:{}", event.tracee_pid(), escape(event.tracee_comm())),
            Some(("tracee_domain", event.tracee_domain())),
        ),
        Event::DenyScopeSignal(event) => (
            event.context().hierarchy().domain_id(),
            "Scope:signal".to_owned(),
            format!("pid:{}:{}", event.target_pid(), escape(event.target_comm())),
            Some(("target_domain", event.target_domain())),
        ),
        Event::DenyScopeAbstractUnixSocket(event) => (
            event.context().hierarchy().domain_id(),
            "Scope:abstract_unix_socket".to_owned(),
            format!("peer:{}", event.peer_pid()),
            Some(("peer_domain", event.peer_domain())),
        ),
        _ => unreachable!("an aggregated denial contains a denial event"),
    };
    let relation = relation.map_or_else(String::new, |(label, membership)| {
        format!(" {label}={}", hex_id(domain_membership(membership)))
    });
    format!(
        "DENIAL type={} domain={} blockers={blockers} target={target} count={} age={} same_exec={} logged={}{}",
        kind.label(),
        hex_id(domain.get()),
        denial.occurrence_count(),
        elapsed(
            denial.first_timestamp().as_nanoseconds(),
            denial.latest_timestamp().as_nanoseconds()
        ),
        u8::from(denial.same_exec()),
        u8::from(denial.logged()),
        relation,
    )
}

fn format_stats(allocated: usize, total: usize, stats: &Stats) -> String {
    let mut kinds = String::new();
    for (index, kind) in DenialKind::ALL.into_iter().enumerate() {
        if index != 0 {
            kinds.push(' ');
        }
        use std::fmt::Write as _;
        write!(
            kinds,
            "{}={}",
            kind.stats_label(),
            stats.denials[kind.index()]
        )
        .expect("writing to a String cannot fail");
    }
    format!(
        "STATS domains={allocated}/{} denials={} ({kinds})",
        total, stats.total_denials
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use landlock_observability::event::{
        CreateDomainEvent, DenialContext, DenyAccessFsEvent, DenyAccessNetEvent, DenyPtraceEvent,
        DenyScopeAbstractUnixSocketEvent, DenyScopeSignalEvent, EnforceDomainEvent,
        FreeDomainEvent, FreeRulesetEvent, HierarchySnapshot, KernelTimestamp, UnknownEvent,
    };

    fn timestamp(seconds: u64) -> KernelTimestamp {
        KernelTimestamp::from_nanoseconds(seconds * 1_000_000_000)
    }

    fn captured(bytes: &[u8]) -> CapturedString {
        CapturedString::new(bytes.to_vec(), false).unwrap()
    }

    fn context(domain: u64, parent: Option<u64>, count: u64) -> DenialContext {
        DenialContext::new(
            HierarchySnapshot::new(
                DomainId::new(domain),
                parent.map(DomainId::new),
                10,
                captured(b"creator"),
            ),
            count,
            true,
            false,
        )
    }

    fn fs(seconds: u64, blockers: u32, path: &[u8]) -> Event {
        Event::DenyAccessFs(DenyAccessFsEvent::new(
            timestamp(seconds),
            context(0x10, None, seconds),
            FilesystemAccess::from_bits(blockers),
            1,
            2,
            captured(path),
        ))
    }

    #[test]
    fn lifecycle_records_are_identity_deduplicated_and_accept_late_objects() {
        let create = Event::CreateDomain(CreateDomainEvent::new(
            timestamp(1),
            RulesetId::new(0x20),
            3,
            DomainId::new(0x10),
            None,
            42,
            captured(b"shell"),
        ));
        let mut batch = Batch::new();
        assert_eq!(
            batch.process(&create),
            [
                "DOMAIN domain=10 parent=0 ruleset=20.3 creator=shell[42] no_new_privs=?",
                "STATS domains=1/1 denials=0 (fs=0 net=0 ptrace=0 signal=0 abstract_unix=0)",
            ]
        );
        assert!(batch.process(&create).is_empty());

        let late_create = Event::CreateDomain(CreateDomainEvent::new(
            timestamp(2),
            RulesetId::new(0x30),
            4,
            DomainId::new(0x10),
            Some(DomainId::new(0x11)),
            43,
            captured(b"upgraded"),
        ));
        assert_eq!(
            batch.process(&late_create),
            [
                "DOMAIN domain=10 parent=11 ruleset=30.4 creator=upgraded[43] no_new_privs=?",
                "DOMAIN domain=11 parent=? ruleset=? creator=? no_new_privs=?",
                "STATS domains=1/2 denials=0 (fs=0 net=0 ptrace=0 signal=0 abstract_unix=0)",
            ]
        );
        assert!(batch.process(&late_create).is_empty());

        let late_free =
            Event::FreeRuleset(FreeRulesetEvent::new(timestamp(2), RulesetId::new(0xab), 7));
        assert_eq!(
            batch.process(&late_free),
            [
                "DROP_RULESET ruleset=ab.7",
                "STATS domains=1/2 denials=0 (fs=0 net=0 ptrace=0 signal=0 abstract_unix=0)",
            ]
        );
        assert!(batch.process(&late_free).is_empty());

        let late_domain =
            Event::FreeDomain(FreeDomainEvent::new(timestamp(3), DomainId::new(0xcd), 0));
        assert_eq!(
            batch.process(&late_domain),
            [
                "DOMAIN domain=cd parent=? ruleset=? creator=? no_new_privs=?",
                "STATS domains=1/3 denials=0 (fs=0 net=0 ptrace=0 signal=0 abstract_unix=0)",
            ]
        );
    }

    #[test]
    fn enforcement_reports_weakest_observed_no_new_privs_fact() {
        let mut batch = Batch::new();
        let id = DomainId::new(0x10);
        let first = Event::EnforceDomain(EnforceDomainEvent::new(
            timestamp(1),
            id,
            100,
            false,
            true,
            true,
        ));
        let weakest = Event::EnforceDomain(EnforceDomainEvent::new(
            timestamp(2),
            id,
            101,
            true,
            true,
            false,
        ));
        let updated = Event::EnforceDomain(EnforceDomainEvent::new(
            timestamp(3),
            id,
            101,
            true,
            true,
            true,
        ));
        assert_eq!(
            batch.process(&first),
            [
                "DOMAIN domain=10 parent=? ruleset=? creator=? no_new_privs=1",
                "STATS domains=1/1 denials=0 (fs=0 net=0 ptrace=0 signal=0 abstract_unix=0)",
            ]
        );
        assert_eq!(
            batch.process(&weakest),
            [
                "DOMAIN domain=10 parent=? ruleset=? creator=? no_new_privs=0",
                "STATS domains=1/1 denials=0 (fs=0 net=0 ptrace=0 signal=0 abstract_unix=0)",
            ]
        );
        assert_eq!(
            batch.process(&updated),
            [
                "DOMAIN domain=10 parent=? ruleset=? creator=? no_new_privs=1",
                "STATS domains=1/1 denials=0 (fs=0 net=0 ptrace=0 signal=0 abstract_unix=0)",
            ]
        );
    }

    #[test]
    fn all_denial_kinds_have_lines_relations_and_independent_counters() {
        let events = [
            fs(1, 4, b"/tmp/file"),
            Event::DenyAccessNet(DenyAccessNetEvent::new(
                timestamp(2),
                context(0x10, None, 2),
                NetworkAccess::from_bits(2),
                0,
                443,
            )),
            Event::DenyPtrace(DenyPtraceEvent::new(
                timestamp(3),
                context(0x10, None, 3),
                DomainMembership::Unsandboxed,
                20,
                captured(b"tracee"),
            )),
            Event::DenyScopeSignal(DenyScopeSignalEvent::new(
                timestamp(4),
                context(0x10, None, 4),
                DomainMembership::Sandboxed(DomainId::new(0x22)),
                21,
                captured(b"tar:get"),
            )),
            Event::DenyScopeAbstractUnixSocket(DenyScopeAbstractUnixSocketEvent::new(
                timestamp(5),
                context(0x10, None, 5),
                DomainMembership::Unsandboxed,
                22,
            )),
        ];
        let mut batch = Batch::new();
        let output = events
            .iter()
            .flat_map(|event| batch.process(event))
            .collect::<Vec<_>>()
            .join("\n");

        let denials = output
            .lines()
            .filter(|line| line.starts_with("DENIAL "))
            .collect::<Vec<_>>();
        assert_eq!(
            denials,
            [
                "DENIAL type=FS domain=10 blockers=FS:read_file target=/tmp/file count=1 age=0s same_exec=1 logged=0",
                "DENIAL type=NET domain=10 blockers=Net:connect_tcp target=dport:443 count=1 age=0s same_exec=1 logged=0",
                "DENIAL type=PTRACE domain=10 blockers=ptrace target=pid:20:tracee count=1 age=0s same_exec=1 logged=0 tracee_domain=0",
                "DENIAL type=SIGNAL domain=10 blockers=Scope:signal target=pid:21:tar\\x3aget count=1 age=0s same_exec=1 logged=0 target_domain=22",
                "DENIAL type=ABSTRACT_UNIX domain=10 blockers=Scope:abstract_unix_socket target=peer:22 count=1 age=0s same_exec=1 logged=0 peer_domain=0",
            ]
        );
        assert!(output.ends_with(
            "STATS domains=1/2 denials=5 (fs=1 net=1 ptrace=1 signal=1 abstract_unix=1)"
        ));
    }

    #[test]
    fn denial_flags_are_rendered_exactly() {
        let event = Event::DenyAccessFs(DenyAccessFsEvent::new(
            timestamp(1),
            DenialContext::new(
                HierarchySnapshot::new(DomainId::new(0x10), None, 10, captured(b"creator")),
                1,
                false,
                true,
            ),
            FilesystemAccess::from_bits(4),
            1,
            2,
            captured(b"/tmp/file"),
        ));

        assert_eq!(
            Batch::new().process(&event)[1],
            "DENIAL type=FS domain=10 blockers=FS:read_file target=/tmp/file count=1 age=0s same_exec=0 logged=1"
        );
    }

    #[test]
    fn unknown_access_bits_are_numeric_alongside_semantic_names() {
        let mut batch = Batch::new();
        let output = batch.process(&fs(1, 0x8000_0004, b"/x"));
        assert!(output[1].contains("blockers=FS:read_file,0x80000000"));

        let network = Event::DenyAccessNet(DenyAccessNetEvent::new(
            timestamp(2),
            context(0x10, None, 2),
            NetworkAccess::from_bits(0x8000_0001),
            7,
            9,
        ));
        let output = batch.process(&network);
        assert!(output[0].contains("blockers=Net:bind_tcp,0x80000000"));
    }

    #[test]
    fn kernel_bytes_are_escaped_without_utf8_or_terminal_interpretation() {
        assert_eq!(
            escape(&captured(b"safe/path A=%,\\\n\x1b\xff")),
            "safe/path\\x20A\\x3d\\x25\\x2c\\x5c\\x0a\\x1b\\xff"
        );
        let create = Event::CreateDomain(CreateDomainEvent::new(
            timestamp(1),
            RulesetId::new(1),
            0,
            DomainId::new(2),
            None,
            3,
            captured(b"a b]\\\x1b"),
        ));
        assert!(Batch::new().process(&create)[0].contains("creator=a\\x20b\\x5d\\x5c\\x1b[3]"));
    }

    #[test]
    fn network_target_direction_comes_from_access_even_for_zero_ports() {
        let mut batch = Batch::new();
        let bind = Event::DenyAccessNet(DenyAccessNetEvent::new(
            timestamp(1),
            context(1, None, 1),
            NetworkAccess::from_bits(4),
            0,
            99,
        ));
        assert!(batch.process(&bind)[1].contains("target=sport:0"));

        let connect = Event::DenyAccessNet(DenyAccessNetEvent::new(
            timestamp(2),
            context(1, None, 2),
            NetworkAccess::from_bits(8),
            99,
            0,
        ));
        assert!(batch.process(&connect)[0].contains("target=dport:0"));

        let unknown = Event::DenyAccessNet(DenyAccessNetEvent::new(
            timestamp(3),
            context(1, None, 3),
            NetworkAccess::from_bits(0x8000_0000),
            7,
            8,
        ));
        assert!(batch.process(&unknown)[0].contains("target=sport:7,dport:8"));
    }

    #[test]
    fn aggregation_updates_count_age_and_latest_flags() {
        let mut batch = Batch::new();
        batch.process(&fs(2, 4, b"/same"));
        let output = batch.process(&fs(67, 4, b"/new-description"));
        assert!(output[0].contains("count=2 age=1m5s same_exec=1 logged=0"));
        assert!(output[0].contains("target=/new-description"));
        assert!(output[1].contains("denials=2 (fs=2"));

        let mut decreasing = Batch::new();
        decreasing.process(&fs(67, 4, b"/same"));
        let output = decreasing.process(&fs(2, 4, b"/same"));
        assert!(output[0].contains("count=2 age=0s same_exec=1 logged=0"));
    }

    #[test]
    fn irrelevant_events_are_silent_and_stats_use_reconstructed_lifecycle() {
        let mut batch = Batch::new();
        assert!(batch
            .process(&Event::Unknown(UnknownEvent::new(timestamp(1), 99, 16)))
            .is_empty());

        let relational = Event::DenyScopeSignal(DenyScopeSignalEvent::new(
            timestamp(2),
            context(1, None, 1),
            DomainMembership::Sandboxed(DomainId::new(2)),
            3,
            captured(b"target"),
        ));
        let output = batch.process(&relational);
        assert_eq!(
            output,
            [
                "DOMAIN domain=1 parent=0 ruleset=? creator=creator[10] no_new_privs=?",
                "DOMAIN domain=2 parent=? ruleset=? creator=? no_new_privs=?",
                "DENIAL type=SIGNAL domain=1 blockers=Scope:signal target=pid:3:target count=1 age=0s same_exec=1 logged=0 target_domain=2",
                "STATS domains=1/2 denials=1 (fs=0 net=0 ptrace=0 signal=1 abstract_unix=0)",
            ]
        );

        let deallocated = batch.process(&Event::FreeDomain(FreeDomainEvent::new(
            timestamp(3),
            DomainId::new(1),
            1,
        )));
        assert_eq!(
            deallocated,
            ["STATS domains=0/2 denials=1 (fs=0 net=0 ptrace=0 signal=1 abstract_unix=0)"]
        );
    }

    struct FlushFailure;

    impl Write for FlushFailure {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("flush failed"))
        }
    }

    #[test]
    fn output_and_flush_errors_are_propagated() {
        let mut batch = Batch::new();
        let error = batch
            .process_and_write(&fs(1, 4, b"/x"), &mut FlushFailure)
            .unwrap_err();
        assert_eq!(error.to_string(), "flush failed");
    }

    #[test]
    fn observed_stats_counters_saturate_independently() {
        let mut stats = Stats {
            total_denials: u64::MAX,
            denials: [u64::MAX, 7, 8, 9, 10],
        };
        stats.observe(DenialKind::Fs);
        assert_eq!(stats.total_denials, u64::MAX);
        assert_eq!(stats.denials, [u64::MAX, 7, 8, 9, 10]);
        stats.observe(DenialKind::Net);
        assert_eq!(stats.denials, [u64::MAX, 8, 8, 9, 10]);
    }
}
