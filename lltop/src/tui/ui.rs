// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cmp::Ordering;
use std::collections::HashMap;

use landlock_observability::aggregate::{AggregatedDenial, DenialKey};
use landlock_observability::event::{DomainId, Event, RulesetId, ScopeAccess};
use landlock_observability::state::{DomainParent, LifecycleState};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Tabs,
};
use ratatui::Frame;

use super::format;
use super::model::{domain_ruleset, ObservationModel};
use super::theme;

const AUDIT_VISIBLE_ICON: &str = "🔔";
const TRACE_ONLY_ICON: &str = "🔕";

fn visibility(logged: bool) -> (&'static str, &'static str) {
    if logged {
        (AUDIT_VISIBLE_ICON, "audit-visible")
    } else {
        (TRACE_ONLY_ICON, "trace-only")
    }
}

fn denial_row_text(count: u64, visibility: &str, target: &str) -> (String, usize) {
    let prefix = format!("    {count:>6} {visibility}  ");
    let continuation_indent = format::display_width(&prefix);
    (format!("{prefix}{target}"), continuation_indent)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Tab {
    Domains,
    Denials,
    Rulesets,
    Stats,
}

impl Tab {
    const ALL: [Self; 4] = [Self::Domains, Self::Denials, Self::Rulesets, Self::Stats];
    const TITLES: [&'static str; 4] = ["Domains [1]", "Denials [2]", "Rulesets [3]", "Stats [4]"];

    fn index(self) -> usize {
        match self {
            Self::Domains => 0,
            Self::Denials => 1,
            Self::Rulesets => 2,
            Self::Stats => 3,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RowKind {
    Domain(DomainId),
    DenialDomain(DomainId),
    Denial(DenialKey),
    Ruleset(RulesetId),
    Heading,
}

impl RowKind {
    fn selectable(&self) -> bool {
        !matches!(self, Self::Heading)
    }
}

#[derive(Default)]
pub(super) struct HitMap {
    pub(super) tabs: Rect,
    pub(super) list: Rect,
    pub(super) rows: Vec<RowKind>,
    pub(super) header_rows: u16,
}

pub(super) struct App {
    pub(super) tab: Tab,
    pub(super) paused: bool,
    collector_warning: Option<String>,
    pub(super) selected: Option<RowKind>,
    pub(super) detail: bool,
    pub(super) scroll: usize,
    follow_selection: bool,
    pub(super) dragging_scrollbar: bool,
    pub(super) hit: HitMap,
}

impl App {
    pub(super) fn new() -> Self {
        Self {
            tab: Tab::Domains,
            paused: false,
            collector_warning: None,
            selected: None,
            detail: false,
            scroll: 0,
            follow_selection: true,
            dragging_scrollbar: false,
            hit: HitMap::default(),
        }
    }

    pub(super) fn set_collector_warning(&mut self, warning: String) {
        self.collector_warning = Some(warning);
    }

    pub(super) fn close_detail(&mut self) {
        self.detail = false;
    }

    pub(super) fn set_tab(&mut self, tab: Tab) {
        self.tab = tab;
        self.selected = None;
        self.detail = false;
        self.scroll = 0;
        self.follow_selection = true;
    }

    pub(super) fn cycle_tab(&mut self) {
        self.set_tab(Tab::ALL[(self.tab.index() + 1) % Tab::ALL.len()]);
    }

    pub(super) fn scroll_by(&mut self, delta: isize) {
        self.follow_selection = false;
        if delta < 0 {
            self.scroll = self.scroll.saturating_sub(delta.unsigned_abs());
        } else {
            self.scroll = self.scroll.saturating_add(delta.unsigned_abs());
        }
    }

    pub(super) fn scroll_to(&mut self, scroll: usize) {
        self.follow_selection = false;
        self.scroll = scroll;
    }

    pub(super) fn move_selection(&mut self, delta: isize) {
        self.follow_selection = true;
        let mut selectable = Vec::new();
        for (index, row) in self.hit.rows.iter().enumerate() {
            if row.selectable()
                && selectable
                    .last()
                    .is_none_or(|(_, previous): &(usize, &RowKind)| *previous != row)
            {
                selectable.push((index, row));
            }
        }
        if selectable.is_empty() {
            return;
        }
        let current = self
            .selected
            .as_ref()
            .and_then(|selected| selectable.iter().position(|(_, row)| *row == selected));
        let next = match (current, delta.cmp(&0)) {
            (None, Ordering::Less) => selectable.len() - 1,
            (None, _) => 0,
            (Some(index), Ordering::Less) => index.saturating_sub(1),
            (Some(index), _) => (index + 1).min(selectable.len() - 1),
        };
        let (_, row) = selectable[next];
        self.selected = Some(row.clone());
        self.detail = true;
    }

    fn adjust_viewport(&mut self, row_count: usize, visible: usize, selected_index: Option<usize>) {
        self.scroll = viewport_scroll(
            self.scroll,
            row_count,
            visible,
            selected_index,
            self.follow_selection,
        );
    }
}

struct DisplayRow {
    kind: RowKind,
    text: String,
    style: Style,
    continuation_indent: Option<usize>,
}

fn viewport_scroll(
    scroll: usize,
    row_count: usize,
    visible: usize,
    selected_index: Option<usize>,
    follow_selection: bool,
) -> usize {
    let scroll = scroll.min(row_count.saturating_sub(visible));
    if !follow_selection {
        return scroll;
    }
    match selected_index {
        Some(index) if index < scroll => index,
        Some(index) if index >= scroll.saturating_add(visible) => {
            index.saturating_add(1).saturating_sub(visible)
        }
        _ => scroll,
    }
}

pub(super) fn draw(frame: &mut Frame<'_>, app: &mut App, model: &ObservationModel) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(frame.area());
    app.hit.tabs = vertical[0];
    let titles = Tab::TITLES.into_iter().map(Line::from).collect::<Vec<_>>();
    let status = status_line(app, model);
    frame.render_widget(
        Tabs::new(titles)
            .select(app.tab.index())
            .highlight_style(theme::heading())
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" lltop ")
                    .title_bottom(Line::from(status).right_aligned()),
            ),
        vertical[0],
    );

    let panes = if app.detail && app.tab != Tab::Stats {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(vertical[1])
            .to_vec()
    } else {
        vec![vertical[1]]
    };
    let rows = match app.tab {
        Tab::Domains => domain_rows(model, app.selected.as_ref()),
        Tab::Denials => denial_rows(model, app.selected.as_ref()),
        Tab::Rulesets => ruleset_rows(model, app.selected.as_ref()),
        Tab::Stats => Vec::new(),
    };
    if app.tab == Tab::Stats {
        draw_stats(frame, panes[0], model);
        app.hit = HitMap {
            tabs: vertical[0],
            ..HitMap::default()
        };
    } else {
        draw_list(frame, panes[0], app, rows);
        if panes.len() == 2 {
            draw_detail(frame, panes[1], app, model);
        }
    }
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" q/Esc", theme::heading()),
            Span::raw(" quit/close  "),
            Span::styled("1-4/Tab", theme::heading()),
            Span::raw(" tabs  "),
            Span::styled("↑↓", theme::heading()),
            Span::raw(" select  "),
            Span::styled("p", theme::heading()),
            Span::raw(" pause  "),
            Span::styled("Enter", theme::heading()),
            Span::raw(" follow"),
        ])),
        vertical[2],
    );
}

fn status_line(app: &App, model: &ObservationModel) -> String {
    let missing_no_new_privs = model.state.domains().any(|domain| {
        domain.lifecycle() == LifecycleState::Allocated && domain.no_new_privs() == Some(false)
    });
    format!(
        " {} domains ({} allocated) | {} denials{}{}{}",
        model.state.domain_count(),
        model.allocated_domains(),
        model.stats.total,
        if app.paused { " | PAUSED" } else { "" },
        if missing_no_new_privs {
            " | WARNING: missing no_new_privs means privilege gain is possible"
        } else {
            ""
        },
        app.collector_warning
            .as_ref()
            .map_or_else(String::new, |warning| format!(
                " | COLLECTOR WARNING: {warning}"
            ))
    )
}

fn draw_list(frame: &mut Frame<'_>, area: Rect, app: &mut App, rows: Vec<DisplayRow>) {
    let content_width = area.width.saturating_sub(2) as usize;
    let rows = rows
        .into_iter()
        .flat_map(|row| {
            let content_start = row
                .text
                .chars()
                .take_while(|character| *character == ' ')
                .count();
            let continuation = row
                .continuation_indent
                .unwrap_or_else(|| content_start.saturating_add(4))
                .min(content_width.saturating_sub(1));
            format::wrap(
                &row.text,
                content_width,
                content_width.saturating_sub(continuation),
            )
            .into_iter()
            .enumerate()
            .map(move |(index, text)| DisplayRow {
                kind: row.kind.clone(),
                text: if index == 0 {
                    text
                } else {
                    format!("{}{text}", " ".repeat(continuation))
                },
                style: row.style,
                continuation_indent: row.continuation_indent,
            })
        })
        .collect::<Vec<_>>();
    let visible = area.height.saturating_sub(2) as usize;
    let selected_index = app
        .selected
        .as_ref()
        .and_then(|selected| rows.iter().position(|row| &row.kind == selected));
    app.adjust_viewport(rows.len(), visible, selected_index);
    app.hit.list = area;
    app.hit.header_rows = 1;
    app.hit.rows = rows.iter().map(|row| row.kind.clone()).collect();
    let lines = rows
        .iter()
        .skip(app.scroll)
        .take(visible)
        .map(|row| Line::from(Span::styled(row.text.clone(), row.style)))
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {} ", Tab::TITLES[app.tab.index()])),
        ),
        area,
    );
    if rows.len() > visible {
        let mut state = ScrollbarState::new(rows.len())
            .position(app.scroll)
            .viewport_content_length(visible);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight),
            area,
            &mut state,
        );
    }
}

fn selected_style(kind: &RowKind, selected: Option<&RowKind>, base: Style) -> Style {
    if selected == Some(kind) {
        base.patch(theme::selected())
    } else {
        base
    }
}

fn tree_prefix(last: &[bool]) -> String {
    if last.len() <= 1 {
        return String::new();
    }
    let mut prefix = String::new();
    for (index, is_last) in last.iter().enumerate().skip(1) {
        if index + 1 == last.len() {
            prefix.push_str(if *is_last { "└─ " } else { "├─ " });
        } else {
            prefix.push_str(if *is_last { "   " } else { "│  " });
        }
    }
    prefix
}

fn domain_rows(model: &ObservationModel, selected: Option<&RowKind>) -> Vec<DisplayRow> {
    model
        .domain_tree()
        .into_iter()
        .filter_map(|(id, trail)| {
            let domain = model.state.domain(id)?;
            let kind = RowKind::Domain(id);
            let creator = match (domain.creator_comm(), domain.creator_tgid()) {
                (Some(comm), Some(tgid)) => format!("{}[{tgid}]", format::escape(comm)),
                _ => "?".to_owned(),
            };
            let count = domain
                .cumulative_denial_count()
                .map_or_else(|| "?".to_owned(), |value| value.to_string());
            let status = match (domain.lifecycle(), domain.no_new_privs()) {
                (LifecycleState::Allocated, Some(false)) => format!(
                    "{}; WARNING: missing no_new_privs means privilege gain is possible",
                    lifecycle(domain.lifecycle())
                ),
                _ => lifecycle(domain.lifecycle()).to_owned(),
            };
            Some(DisplayRow {
                style: selected_style(&kind, selected, lifecycle_style(domain.lifecycle())),
                kind,
                text: format!(
                    "{}{}  {creator}  denials={count}  {status}",
                    tree_prefix(&trail),
                    format::hex_id(id.get())
                ),
                continuation_indent: None,
            })
        })
        .collect()
}

fn denial_rows(model: &ObservationModel, selected: Option<&RowKind>) -> Vec<DisplayRow> {
    let mut domains: HashMap<DomainId, Vec<&AggregatedDenial>> = HashMap::new();
    for denial in model.denials.entries() {
        domains
            .entry(denial.key().domain_id())
            .or_default()
            .push(denial);
    }
    let mut domains = domains.into_iter().collect::<Vec<_>>();
    domains.sort_by(|(aid, a), (bid, b)| {
        total(b)
            .cmp(&total(a))
            .then_with(|| aid.get().cmp(&bid.get()))
    });
    let selected_target = match selected {
        Some(RowKind::Denial(key)) => model.denial(key).map(target),
        _ => None,
    };
    let mut rows = Vec::new();
    for (domain, entries) in domains {
        if !rows.is_empty() {
            rows.push(DisplayRow {
                kind: RowKind::Heading,
                text: String::new(),
                style: theme::normal(),
                continuation_indent: None,
            });
        }
        let kind = RowKind::DenialDomain(domain);
        let creator = model
            .state
            .domain(domain)
            .and_then(
                |domain| match (domain.creator_comm(), domain.creator_tgid()) {
                    (Some(comm), Some(tgid)) => Some(format!("{}[{tgid}]", format::escape(comm))),
                    _ => None,
                },
            )
            .unwrap_or_else(|| "?".to_owned());
        rows.push(DisplayRow {
            style: selected_style(
                &kind,
                selected,
                theme::observed().add_modifier(ratatui::style::Modifier::BOLD),
            ),
            kind,
            text: format!("Domain {} ({creator})", format::hex_id(domain.get())),
            continuation_indent: None,
        });
        let mut groups: HashMap<String, Vec<&AggregatedDenial>> = HashMap::new();
        for entry in entries {
            groups.entry(blockers(entry)).or_default().push(entry);
        }
        let mut groups = groups.into_iter().collect::<Vec<_>>();
        groups.sort_by(|(al, a), (bl, b)| {
            maximum(b)
                .cmp(&maximum(a))
                .then_with(|| total(b).cmp(&total(a)))
                .then_with(|| al.cmp(bl))
        });
        for (label, mut entries) in groups {
            rows.push(DisplayRow {
                kind: RowKind::Heading,
                text: format!("  {label}"),
                style: theme::heading(),
                continuation_indent: None,
            });
            entries.sort_by(|a, b| {
                b.occurrence_count()
                    .cmp(&a.occurrence_count())
                    .then_with(|| {
                        b.latest_timestamp()
                            .as_nanoseconds()
                            .cmp(&a.latest_timestamp().as_nanoseconds())
                    })
                    .then_with(|| target(a).cmp(&target(b)))
            });
            for entry in entries {
                let key = RowKind::Denial(entry.key().clone());
                let (visibility, _) = visibility(entry.logged());
                let mut style = theme::recency(model.denial_age_ns(entry));
                if selected_target
                    .as_ref()
                    .is_some_and(|value| *value == target(entry))
                    && selected != Some(&key)
                {
                    style = style.patch(theme::related());
                }
                style = selected_style(&key, selected, style);
                let (text, continuation_indent) =
                    denial_row_text(entry.occurrence_count(), visibility, &target(entry));
                rows.push(DisplayRow {
                    kind: key,
                    text,
                    style,
                    continuation_indent: Some(continuation_indent),
                });
            }
        }
    }
    rows
}

fn ruleset_rows(model: &ObservationModel, selected: Option<&RowKind>) -> Vec<DisplayRow> {
    let mut rulesets = model.state.rulesets().collect::<Vec<_>>();
    rulesets.sort_by(|a, b| {
        b.creation_timestamp()
            .map(|v| v.as_nanoseconds())
            .cmp(&a.creation_timestamp().map(|v| v.as_nanoseconds()))
            .then_with(|| a.ruleset_id().get().cmp(&b.ruleset_id().get()))
    });
    rulesets
        .into_iter()
        .map(|ruleset| {
            let kind = RowKind::Ruleset(ruleset.ruleset_id());
            DisplayRow {
                style: selected_style(&kind, selected, lifecycle_style(ruleset.lifecycle())),
                kind,
                text: format!(
                    "{}  rules={}  {}",
                    format::ruleset(ruleset.ruleset_id().get(), ruleset.max_observed_version()),
                    ruleset.filesystem_rule_count() + ruleset.network_rule_count(),
                    lifecycle(ruleset.lifecycle())
                ),
                continuation_indent: None,
            }
        })
        .collect()
}

fn total(entries: &[&AggregatedDenial]) -> u64 {
    entries
        .iter()
        .fold(0, |sum, entry| sum.saturating_add(entry.occurrence_count()))
}
fn maximum(entries: &[&AggregatedDenial]) -> u64 {
    entries
        .iter()
        .map(|entry| entry.occurrence_count())
        .max()
        .unwrap_or(0)
}
fn lifecycle(value: LifecycleState) -> &'static str {
    match value {
        LifecycleState::Unknown => "partial",
        LifecycleState::Allocated => "allocated",
        LifecycleState::Deallocated => "deallocated",
    }
}
fn lifecycle_style(value: LifecycleState) -> Style {
    match value {
        LifecycleState::Unknown => theme::unknown(),
        LifecycleState::Allocated => theme::observed(),
        LifecycleState::Deallocated => theme::tombstone(),
    }
}

fn blockers(entry: &AggregatedDenial) -> String {
    match entry.latest_event() {
        Event::DenyAccessFs(event) => format::filesystem(event.blockers()),
        Event::DenyAccessNet(event) => format::network(event.blockers()),
        Event::DenyPtrace(_) => "ptrace".to_owned(),
        Event::DenyScopeSignal(_) => format::scope(ScopeAccess::from_bits(1 << 1)),
        Event::DenyScopeAbstractUnixSocket(_) => format::scope(ScopeAccess::from_bits(1 << 0)),
        _ => unreachable!("aggregated entries contain denials"),
    }
}

fn target(entry: &AggregatedDenial) -> String {
    match entry.latest_event() {
        Event::DenyAccessFs(event) => format::escape(event.pathname()),
        Event::DenyAccessNet(event) => {
            let (mut bind, mut connect) = (false, false);
            for name in event.blockers().known_names() {
                bind |= name.as_str().starts_with("bind_");
                connect |= name.as_str().starts_with("connect_");
            }
            match (bind, connect) {
                (true, false) => format!("sport:{}", event.source_port()),
                (false, true) => format!("dport:{}", event.destination_port()),
                _ => format!(
                    "sport:{}, dport:{}",
                    event.source_port(),
                    event.destination_port()
                ),
            }
        }
        Event::DenyPtrace(event) => format!(
            "pid:{} {}",
            event.tracee_pid(),
            format::escape(event.tracee_comm())
        ),
        Event::DenyScopeSignal(event) => format!(
            "pid:{} {}",
            event.target_pid(),
            format::escape(event.target_comm())
        ),
        Event::DenyScopeAbstractUnixSocket(event) => format!("peer:{}", event.peer_pid()),
        _ => unreachable!("aggregated entries contain denials"),
    }
}

fn detail_lines(app: &App, model: &ObservationModel, width: usize) -> Vec<Line<'static>> {
    let mut fields = Vec::<(String, String, Style)>::new();
    match app.selected.as_ref() {
        Some(RowKind::Domain(id)) | Some(RowKind::DenialDomain(id)) => {
            if let Some(domain) = model.state.domain(*id) {
                fields.push(("Domain: ".into(), format::hex_id(id.get()), theme::normal()));
                fields.push((
                    "Status: ".into(),
                    lifecycle(domain.lifecycle()).into(),
                    lifecycle_style(domain.lifecycle()),
                ));
                fields.push((
                    "Parent: ".into(),
                    match domain.parent() {
                        None => "?".into(),
                        Some(DomainParent::Root) => "0".into(),
                        Some(DomainParent::Domain(id)) => format::hex_id(id.get()),
                    },
                    theme::normal(),
                ));
                fields.push((
                    "Ruleset: ".into(),
                    domain.ruleset().map_or_else(
                        || "?".into(),
                        |r| format::ruleset(r.ruleset_id().get(), Some(r.ruleset_version())),
                    ),
                    theme::normal(),
                ));
                fields.push((
                    "Created: ".into(),
                    format::timestamp(domain.creation_timestamp()),
                    theme::normal(),
                ));
                fields.push((
                    "Observed enforcing TIDs: ".into(),
                    domain.enforcement_event_count().to_string(),
                    theme::normal(),
                ));
                fields.push(match (domain.lifecycle(), domain.no_new_privs()) {
                    (_, None) => ("no_new_privs: ".into(), "unknown".into(), theme::unknown()),
                    (_, Some(true)) => (
                        "no_new_privs: ".into(),
                        "set for all latest observed enforcing TIDs".into(),
                        theme::observed(),
                    ),
                    (LifecycleState::Allocated, Some(false)) => (
                        "no_new_privs: ".into(),
                        "WARNING: missing no_new_privs means privilege gain is possible".into(),
                        theme::hot(),
                    ),
                    (_, Some(false)) => (
                        "no_new_privs: ".into(),
                        "historical observation: missing no_new_privs; privilege gain was possible"
                            .into(),
                        theme::tombstone(),
                    ),
                });
                if domain_ruleset(domain).is_some() {
                    fields.push((
                        String::new(),
                        "[Enter] View ruleset".into(),
                        theme::unknown(),
                    ));
                }
            }
        }
        Some(RowKind::Denial(key)) => {
            if let Some(entry) = model.denial(key) {
                fields.push((
                    "Domain: ".into(),
                    format::hex_id(key.domain_id().get()),
                    theme::normal(),
                ));
                fields.push(("Blocked: ".into(), blockers(entry), theme::normal()));
                fields.push(("Target: ".into(), target(entry), theme::normal()));
                fields.push((
                    "Count: ".into(),
                    entry.occurrence_count().to_string(),
                    theme::normal(),
                ));
                fields.push((
                    "First seen: ".into(),
                    format!("{}ns", entry.first_timestamp().as_nanoseconds()),
                    theme::normal(),
                ));
                fields.push((
                    "Latest seen: ".into(),
                    format!("{}ns", entry.latest_timestamp().as_nanoseconds()),
                    theme::normal(),
                ));
                fields.push((
                    "same_exec: ".into(),
                    entry.same_exec().to_string(),
                    theme::normal(),
                ));
                fields.push((
                    "Logged: ".into(),
                    {
                        let (marker, label) = visibility(entry.logged());
                        format!("{marker} {label}")
                    },
                    if entry.logged() {
                        theme::observed()
                    } else {
                        theme::trace_only()
                    },
                ));
            }
        }
        Some(RowKind::Ruleset(id)) => {
            if let Some(ruleset) = model.state.ruleset(*id) {
                fields.push((
                    "Ruleset: ".into(),
                    format::ruleset(id.get(), ruleset.max_observed_version()),
                    theme::normal(),
                ));
                fields.push((
                    "Status: ".into(),
                    lifecycle(ruleset.lifecycle()).into(),
                    lifecycle_style(ruleset.lifecycle()),
                ));
                fields.push((
                    "Handled FS: ".into(),
                    ruleset
                        .handled_fs()
                        .map_or_else(|| "?".into(), format::filesystem_rights),
                    theme::normal(),
                ));
                fields.push((
                    "Handled Net: ".into(),
                    ruleset
                        .handled_net()
                        .map_or_else(|| "?".into(), format::network_rights),
                    theme::normal(),
                ));
                fields.push((
                    "Scoped: ".into(),
                    ruleset
                        .scoped()
                        .map_or_else(|| "?".into(), format::scope_rights),
                    theme::normal(),
                ));
                let mut fs_groups: HashMap<String, Vec<String>> = HashMap::new();
                for rule in ruleset.filesystem_rules() {
                    fs_groups
                        .entry(format::filesystem_rights(rule.access_rights()))
                        .or_default()
                        .push(format::escape(rule.pathname()));
                }
                let mut fs_groups = fs_groups.into_iter().collect::<Vec<_>>();
                fs_groups.sort_by(|a, b| a.0.cmp(&b.0));
                for (allowed, mut objects) in fs_groups {
                    fields.push(("FS: ".into(), allowed, theme::heading()));
                    objects.sort();
                    for object in objects {
                        fields.push(("    ".into(), object, theme::normal()));
                    }
                }
                let mut net_groups: HashMap<String, Vec<u64>> = HashMap::new();
                for rule in ruleset.network_rules() {
                    net_groups
                        .entry(format::network_rights(rule.access_rights()))
                        .or_default()
                        .push(rule.port());
                }
                let mut net_groups = net_groups.into_iter().collect::<Vec<_>>();
                net_groups.sort_by(|a, b| a.0.cmp(&b.0));
                for (allowed, mut objects) in net_groups {
                    fields.push(("Net: ".into(), allowed, theme::heading()));
                    objects.sort_unstable();
                    for object in objects {
                        fields.push(("    ".into(), format!("port {object}"), theme::normal()));
                    }
                }
            }
        }
        _ => {}
    }
    if fields.is_empty() {
        return vec![Line::from(Span::styled(
            "Selection no longer retained",
            theme::unknown(),
        ))];
    }
    let mut lines = Vec::new();
    for (label, value, style) in fields {
        let indent = (label.chars().count() + 4).min(width.saturating_sub(1));
        for (index, part) in format::wrap(
            &value,
            width.saturating_sub(label.chars().count()),
            width.saturating_sub(indent),
        )
        .into_iter()
        .enumerate()
        {
            if index == 0 {
                lines.push(Line::from(vec![
                    Span::styled(label.clone(), theme::heading()),
                    Span::styled(part, style),
                ]));
            } else {
                lines.push(Line::from(Span::styled(
                    format!("{}{}", " ".repeat(indent), part),
                    style,
                )));
            }
        }
    }
    lines
}

fn draw_detail(frame: &mut Frame<'_>, area: Rect, app: &App, model: &ObservationModel) {
    let lines = detail_lines(app, model, area.width.saturating_sub(2) as usize);
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Details ")),
        area,
    );
}

fn draw_stats(frame: &mut Frame<'_>, area: Rect, model: &ObservationModel) {
    let labels = ["Filesystem", "Network", "Ptrace", "Signal", "Abstract Unix"];
    let mut lines = vec![Line::from(vec![
        Span::styled("Observed denials: ", theme::heading()),
        Span::raw(model.stats.total.to_string()),
    ])];
    for (label, value) in labels.into_iter().zip(model.stats.by_kind) {
        lines.push(Line::from(format!("  {label}: {value}")));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(format!(
        "Domains: {} allocated / {} observed",
        model.allocated_domains(),
        model.state.domain_count()
    )));
    lines.push(Line::from(format!(
        "Rulesets: {} allocated / {} observed",
        model.allocated_rulesets(),
        model.state.ruleset_count()
    )));
    lines.push(Line::from(format!(
        "Latest event: {}ns",
        model.latest_seen.as_nanoseconds()
    )));
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(" Statistics ")),
        area,
    );
}

pub(super) fn clicked_tab(area: Rect, column: u16, row: u16) -> Option<Tab> {
    if row != area.y + 1 || column <= area.x {
        return None;
    }
    let relative = usize::from(column - area.x - 1);
    let mut start = 0;
    for (index, title) in Tab::TITLES.iter().enumerate() {
        let end = start + title.len() + 2;
        if (start..end).contains(&relative) {
            return Some(Tab::ALL[index]);
        }
        start = end + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use landlock_observability::event::{
        AddRuleFsEvent, AddRuleNetEvent, CapturedString, CreateRulesetEvent, DenialContext,
        DenyAccessFsEvent, DenyAccessNetEvent, EnforceDomainEvent, FilesystemAccess,
        FreeDomainEvent, HierarchySnapshot, KernelTimestamp, NetworkAccess, ScopeAccess,
    };

    fn denial(domain: u64, count: u64, timestamp: u64, inode: u64) -> Event {
        Event::DenyAccessFs(DenyAccessFsEvent::new(
            KernelTimestamp::from_nanoseconds(timestamp),
            DenialContext::new(
                HierarchySnapshot::new(
                    DomainId::new(domain),
                    None,
                    1,
                    CapturedString::new(b"x".to_vec(), false).unwrap(),
                ),
                count,
                true,
                count & 1 == 0,
            ),
            FilesystemAccess::from_bits(4),
            1,
            inode,
            CapturedString::new(format!("/p/{inode}").into_bytes(), false).unwrap(),
        ))
    }

    #[test]
    fn lifecycle_labels_cover_the_closed_statuses() {
        assert_eq!(lifecycle(LifecycleState::Unknown), "partial");
        assert_eq!(lifecycle(LifecycleState::Allocated), "allocated");
        assert_eq!(lifecycle(LifecycleState::Deallocated), "deallocated");
    }

    #[test]
    fn missing_no_new_privs_has_precise_status_and_detail_warning() {
        let mut model = ObservationModel::new();
        let id = DomainId::new(7);
        model.observe(&Event::EnforceDomain(EnforceDomainEvent::new(
            KernelTimestamp::from_nanoseconds(1),
            id,
            10,
            true,
            true,
            false,
        )));

        let rows = domain_rows(&model, None);
        assert!(rows[0]
            .text
            .contains("WARNING: missing no_new_privs means privilege gain is possible"));
        let mut app = App::new();
        assert!(status_line(&app, &model)
            .contains("WARNING: missing no_new_privs means privilege gain is possible"));
        app.selected = Some(RowKind::Domain(id));
        let detail = detail_lines(&app, &model, 120)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(detail.contains("WARNING: missing no_new_privs means privilege gain is possible"));
        assert!(!detail.contains("capability"));
        assert!(!detail.contains("escape"));

        model.observe(&Event::FreeDomain(FreeDomainEvent::new(
            KernelTimestamp::from_nanoseconds(2),
            id,
            0,
        )));
        assert!(!domain_rows(&model, None)[0].text.contains("WARNING"));
        assert!(!status_line(&app, &model).contains("missing no_new_privs means"));
        let detail = detail_lines(&app, &model, 120)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(detail
            .contains("historical observation: missing no_new_privs; privilege gain was possible"));
        assert!(!detail.contains("WARNING"));
    }

    #[test]
    fn collector_warning_persists_in_status() {
        let model = ObservationModel::new();
        let mut app = App::new();
        app.set_collector_warning("collector output queue is full".to_owned());

        assert!(
            status_line(&app, &model).contains("COLLECTOR WARNING: collector output queue is full")
        );
        app.set_tab(Tab::Denials);
        assert!(
            status_line(&app, &model).contains("COLLECTOR WARNING: collector output queue is full")
        );
    }

    #[test]
    fn closing_detail_retains_semantic_selection() {
        let mut app = App::new();
        app.selected = Some(RowKind::Domain(DomainId::new(7)));
        app.detail = true;

        app.close_detail();

        assert!(!app.detail);
        assert_eq!(app.selected, Some(RowKind::Domain(DomainId::new(7))));
    }

    #[test]
    fn denial_details_keep_access_family_prefix() {
        let events = [
            denial(1, 1, 1, 1),
            Event::DenyAccessNet(DenyAccessNetEvent::new(
                KernelTimestamp::from_nanoseconds(1),
                DenialContext::new(
                    HierarchySnapshot::new(
                        DomainId::new(1),
                        None,
                        1,
                        CapturedString::new(b"x".to_vec(), false).unwrap(),
                    ),
                    1,
                    true,
                    false,
                ),
                NetworkAccess::from_bits(1 << 1),
                0,
                443,
            )),
        ];

        for (event, expected) in events
            .into_iter()
            .zip(["Blocked: FS: read_file", "Blocked: Net: connect_tcp"])
        {
            let mut model = ObservationModel::new();
            model.observe(&event);
            let mut app = App::new();
            app.selected = denial_rows(&model, None)
                .into_iter()
                .find_map(|row| match row.kind {
                    RowKind::Denial(_) => Some(row.kind),
                    _ => None,
                });

            let blocked = detail_lines(&app, &model, 80)
                .into_iter()
                .map(|line| {
                    line.spans
                        .into_iter()
                        .map(|span| span.content)
                        .collect::<String>()
                })
                .find(|line| line.starts_with("Blocked: "))
                .unwrap();

            assert_eq!(blocked, expected);
        }
    }

    #[test]
    fn ruleset_details_use_one_access_family_prefix() {
        let id = RulesetId::new(7);
        let mut model = ObservationModel::new();
        for event in [
            Event::CreateRuleset(CreateRulesetEvent::new(
                KernelTimestamp::from_nanoseconds(1),
                id,
                0,
                FilesystemAccess::from_bits(1 << 2),
                NetworkAccess::from_bits(1 << 1),
                ScopeAccess::from_bits(1 << 1),
            )),
            Event::AddRuleFs(AddRuleFsEvent::new(
                KernelTimestamp::from_nanoseconds(2),
                id,
                1,
                FilesystemAccess::from_bits(1 << 1),
                1,
                2,
                CapturedString::new(b"/tmp/file".to_vec(), false).unwrap(),
            )),
            Event::AddRuleNet(AddRuleNetEvent::new(
                KernelTimestamp::from_nanoseconds(3),
                id,
                2,
                NetworkAccess::from_bits(1 << 1),
                443,
            )),
        ] {
            model.observe(&event);
        }
        let mut app = App::new();
        app.selected = Some(RowKind::Ruleset(id));

        let lines = detail_lines(&app, &model, 80)
            .into_iter()
            .map(|line| {
                line.spans
                    .into_iter()
                    .map(|span| span.content)
                    .collect::<String>()
            })
            .collect::<Vec<_>>();

        assert_eq!(
            lines,
            [
                "Ruleset: 7.2",
                "Status: allocated",
                "Handled FS: read_file",
                "Handled Net: connect_tcp",
                "Scoped: signal",
                "FS: write_file",
                "    /tmp/file",
                "Net: connect_tcp",
                "    port 443",
            ]
        );
    }

    #[test]
    fn denial_groups_follow_impact_policy_and_headings_have_no_counts() {
        let mut model = ObservationModel::new();
        for event in [
            denial(1, 1, 1, 1),
            denial(2, 1, 2, 2),
            denial(2, 2, 3, 2),
            denial(2, 3, 4, 3),
        ] {
            model.observe(&event);
        }
        let rows = denial_rows(&model, None);
        assert!(rows[0].text.starts_with("Domain 2 ("));
        assert!(!rows[0].text.contains("denials="));
        assert!(rows.iter().any(|row| row.text.contains(AUDIT_VISIBLE_ICON)));
        assert!(rows.iter().any(|row| row.text.contains(TRACE_ONLY_ICON)));
    }

    #[test]
    fn visibility_column_is_two_cells_and_target_continuations_align() {
        let (audit_marker, _) = visibility(true);
        let (trace_marker, _) = visibility(false);
        assert_eq!(Line::from(audit_marker).width(), 2);
        assert_eq!(Line::from(trace_marker).width(), 2);

        let mut model = ObservationModel::new();
        model.observe(&denial(1, 1, 1, 1));
        model.observe(&denial(1, 2, 2, 2));
        let rows = denial_rows(&model, None);
        let trace = rows.iter().find(|row| row.text.contains("/p/1")).unwrap();
        let audit = rows.iter().find(|row| row.text.contains("/p/2")).unwrap();
        let trace_prefix = trace.text.split_once("/p/1").unwrap().0;
        let audit_prefix = audit.text.split_once("/p/2").unwrap().0;

        assert_eq!(Line::from(trace_prefix).width(), 15);
        assert_eq!(Line::from(audit_prefix).width(), 15);
        assert_eq!(trace.continuation_indent, Some(15));
        assert_eq!(audit.continuation_indent, Some(15));

        let (wide_count, wide_indent) = denial_row_text(1_000_000, TRACE_ONLY_ICON, "/wide/count");
        let wide_prefix = wide_count.split_once("/wide/count").unwrap().0;
        assert_eq!(format::display_width(wide_prefix), wide_indent);
        assert_eq!(wide_indent, 16);

        let mut app = App::new();
        app.selected = Some(trace.kind.clone());
        let detail = detail_lines(&app, &model, 80)
            .into_iter()
            .map(|line| {
                line.spans
                    .into_iter()
                    .map(|span| span.content)
                    .collect::<String>()
            })
            .find(|line| line.starts_with("Logged: "))
            .unwrap();
        assert_eq!(detail, "Logged: 🔕 trace-only");
    }

    #[test]
    fn trace_only_rows_preserve_every_recency_style() {
        let mut model = ObservationModel::new();
        for event in [
            denial(1, 1, 31_000_000_000, 1),
            denial(1, 3, 29_000_000_000, 2),
            denial(1, 5, 5_000_000_000, 3),
            denial(1, 7, 0, 4),
        ] {
            model.observe(&event);
        }

        let rows = denial_rows(&model, None);
        for (inode, expected) in [
            (1, theme::hot()),
            (2, theme::recent()),
            (3, theme::cooling()),
            (4, theme::cold()),
        ] {
            let row = rows
                .iter()
                .find(|row| {
                    let (marker, _) = visibility(false);
                    row.text.contains(&format!("{marker}  /p/{inode}"))
                })
                .unwrap();
            assert_eq!(row.style, expected);
        }
    }

    #[test]
    fn selection_survives_row_reordering_by_key() {
        let mut model = ObservationModel::new();
        model.observe(&denial(1, 1, 1, 1));
        model.observe(&denial(1, 2, 2, 2));
        let rows = denial_rows(&model, None);
        let selected = rows
            .iter()
            .find_map(|row| match &row.kind {
                RowKind::Denial(key) if target(model.denial(key).unwrap()).ends_with("/1") => {
                    Some(row.kind.clone())
                }
                _ => None,
            })
            .unwrap();
        model.observe(&denial(1, 3, 3, 1));
        let reordered = denial_rows(&model, Some(&selected));
        assert!(reordered.iter().any(|row| row.kind == selected));
    }

    #[test]
    fn keyboard_selection_resumes_following_after_manual_scroll() {
        let domains = (1..=5)
            .map(|id| RowKind::Domain(DomainId::new(id)))
            .collect::<Vec<_>>();
        let mut app = App::new();
        app.hit.rows = vec![
            domains[0].clone(),
            domains[0].clone(),
            domains[1].clone(),
            domains[2].clone(),
            domains[2].clone(),
            domains[3].clone(),
            domains[4].clone(),
        ];
        app.selected = Some(domains[4].clone());
        app.scroll_to(2);

        app.adjust_viewport(app.hit.rows.len(), 3, Some(6));
        assert_eq!(app.scroll, 2);

        app.move_selection(-1);
        assert_eq!(app.selected, Some(domains[3].clone()));
        app.adjust_viewport(app.hit.rows.len(), 3, Some(5));
        assert_eq!(app.scroll, 3);
    }

    #[test]
    fn mouse_tab_mapping_matches_rendered_titles() {
        let area = Rect::new(0, 0, 80, 3);
        assert_eq!(clicked_tab(area, 2, 1), Some(Tab::Domains));
        assert_eq!(clicked_tab(area, 16, 1), Some(Tab::Denials));
        assert_eq!(clicked_tab(area, 1, 0), None);
    }
}
