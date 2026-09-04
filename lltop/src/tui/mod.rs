// SPDX-License-Identifier: MIT OR Apache-2.0

mod format;
mod model;
mod terminal;
mod theme;
mod ui;

use std::error::Error;
use std::io;
use std::time::Duration;

use crossterm::event::{
    self, Event as TerminalEvent, KeyCode, KeyEventKind, MouseButton, MouseEventKind,
};
use landlock_observability::collector::{
    Collector, CollectorReceiveError, CollectorReceiveErrorKind, ReceiveTimeoutError,
    TryReceiveError,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use model::{domain_ruleset, ObservationModel};
use terminal::TerminalSession;
use ui::{App, RowKind, Tab};

const COLLECT_TIMEOUT: Duration = Duration::from_millis(10);
const INPUT_TIMEOUT: Duration = Duration::from_millis(40);
const MAX_READY_EVENTS_PER_CYCLE: usize = 1024;
const WHEEL_SCROLL_ROWS: isize = 3;

pub(crate) fn run(mut collector: Collector) -> Result<(), Box<dyn Error>> {
    let _session = TerminalSession::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    terminal.clear()?;
    let mut app = App::new();
    let mut model = ObservationModel::new();

    loop {
        if !app.paused {
            match collector.recv_timeout(COLLECT_TIMEOUT) {
                Ok(event) => model.observe(&event),
                Err(ReceiveTimeoutError::Timeout) => {}
                Err(error) => handle_collector_error(&mut app, error)?,
            }
            drain_ready_events(&mut app, &mut model, || collector.try_recv())?;
        }

        terminal.draw(|frame| ui::draw(frame, &mut app, &model))?;
        if !event::poll(INPUT_TIMEOUT)? {
            continue;
        }
        match event::read()? {
            TerminalEvent::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Esc if app.detail => app.close_detail(),
                KeyCode::Esc => break,
                KeyCode::Char('1') => app.set_tab(Tab::Domains),
                KeyCode::Char('2') => app.set_tab(Tab::Denials),
                KeyCode::Char('3') => app.set_tab(Tab::Rulesets),
                KeyCode::Char('4') => app.set_tab(Tab::Stats),
                KeyCode::Tab => app.cycle_tab(),
                KeyCode::Char('p') => app.paused = !app.paused,
                KeyCode::Up => app.move_selection(-1),
                KeyCode::Down => app.move_selection(1),
                KeyCode::Enter => follow_domain(&mut app, &model),
                _ => {}
            },
            TerminalEvent::Mouse(mouse) => match mouse.kind {
                MouseEventKind::ScrollUp => app.scroll_by(-WHEEL_SCROLL_ROWS),
                MouseEventKind::ScrollDown => app.scroll_by(WHEEL_SCROLL_ROWS),
                MouseEventKind::Down(MouseButton::Left) => {
                    if let Some(tab) = ui::clicked_tab(app.hit.tabs, mouse.column, mouse.row) {
                        app.set_tab(tab);
                        continue;
                    }
                    let scrollbar_column = app.hit.list.x + app.hit.list.width.saturating_sub(1);
                    if mouse.column == scrollbar_column
                        && mouse.row > app.hit.list.y
                        && mouse.row < app.hit.list.y + app.hit.list.height.saturating_sub(1)
                    {
                        app.dragging_scrollbar = true;
                        drag_scrollbar(&mut app, mouse.row);
                    } else {
                        click_row(&mut app, mouse.column, mouse.row);
                    }
                }
                MouseEventKind::Drag(MouseButton::Left) if app.dragging_scrollbar => {
                    drag_scrollbar(&mut app, mouse.row);
                }
                MouseEventKind::Up(MouseButton::Left) => app.dragging_scrollbar = false,
                _ => {}
            },
            _ => {}
        }
    }
    Ok(())
}

fn drain_ready_events<F>(
    app: &mut App,
    model: &mut ObservationModel,
    mut receive: F,
) -> Result<usize, Box<dyn Error>>
where
    F: FnMut() -> Result<landlock_observability::event::Event, TryReceiveError>,
{
    let mut count = 0;
    while count < MAX_READY_EVENTS_PER_CYCLE {
        match receive() {
            Ok(event) => {
                model.observe(&event);
                count += 1;
            }
            Err(TryReceiveError::Empty) => break,
            Err(error) => handle_collector_error(app, error)?,
        }
    }
    Ok(count)
}

fn handle_collector_error<E>(app: &mut App, error: E) -> Result<(), Box<dyn Error>>
where
    E: Error + 'static,
{
    let kind = error
        .source()
        .and_then(|source| source.downcast_ref::<CollectorReceiveError>())
        .map(CollectorReceiveError::kind);
    if recoverable_collector_error(kind) {
        app.set_collector_warning(error.to_string());
        Ok(())
    } else {
        Err(Box::new(error))
    }
}

fn recoverable_collector_error(kind: Option<CollectorReceiveErrorKind>) -> bool {
    matches!(
        kind,
        Some(
            CollectorReceiveErrorKind::OutputQueueFull | CollectorReceiveErrorKind::MalformedSample
        )
    )
}

fn follow_domain(app: &mut App, model: &ObservationModel) {
    let id = match app.selected {
        Some(RowKind::Domain(id) | RowKind::DenialDomain(id)) => id,
        _ => return,
    };
    let Some(ruleset) = model.state.domain(id).and_then(domain_ruleset) else {
        return;
    };
    app.set_tab(Tab::Rulesets);
    app.selected = Some(RowKind::Ruleset(ruleset));
    app.detail = true;
}

fn click_row(app: &mut App, column: u16, row: u16) {
    let area = app.hit.list;
    if column < area.x
        || column >= area.x + area.width
        || row <= area.y
        || row >= area.y + area.height.saturating_sub(1)
    {
        return;
    }
    let visible = usize::from(row - area.y - app.hit.header_rows);
    let index = app.scroll.saturating_add(visible);
    if let Some(kind) = app
        .hit
        .rows
        .get(index)
        .filter(|kind| !matches!(kind, RowKind::Heading))
    {
        app.selected = Some(kind.clone());
        app.detail = true;
    }
}

fn drag_scrollbar(app: &mut App, row: u16) {
    let height = app.hit.list.height.saturating_sub(2).max(1);
    let relative = row.saturating_sub(app.hit.list.y + 1).min(height - 1);
    let max_scroll = app.hit.rows.len().saturating_sub(usize::from(height));
    let scroll = usize::from(relative).saturating_mul(max_scroll)
        / usize::from(height.saturating_sub(1).max(1));
    app.scroll_to(scroll);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::layout::Rect;

    #[test]
    fn only_nonterminal_collector_errors_are_recoverable() {
        assert!(recoverable_collector_error(Some(
            CollectorReceiveErrorKind::OutputQueueFull
        )));
        assert!(recoverable_collector_error(Some(
            CollectorReceiveErrorKind::MalformedSample
        )));
        assert!(!recoverable_collector_error(Some(
            CollectorReceiveErrorKind::PollFailure
        )));
        assert!(!recoverable_collector_error(Some(
            CollectorReceiveErrorKind::WorkerStop
        )));
        assert!(!recoverable_collector_error(None));
    }

    #[test]
    fn ready_events_are_drained_with_a_rendering_bound() {
        use landlock_observability::event::{Event, KernelTimestamp, UnknownEvent};
        use std::collections::VecDeque;

        let mut events = (0..=MAX_READY_EVENTS_PER_CYCLE)
            .map(|timestamp| {
                Event::Unknown(UnknownEvent::new(
                    KernelTimestamp::from_nanoseconds(timestamp as u64),
                    255,
                    344,
                ))
            })
            .collect::<VecDeque<_>>();
        let mut app = App::new();
        let mut model = ObservationModel::new();

        let count = drain_ready_events(&mut app, &mut model, || {
            events.pop_front().ok_or(TryReceiveError::Empty)
        })
        .unwrap();

        assert_eq!(count, MAX_READY_EVENTS_PER_CYCLE);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn row_click_uses_scroll_and_ignores_headings() {
        let mut app = App::new();
        app.hit.list = Rect::new(5, 5, 20, 10);
        app.hit.header_rows = 1;
        app.hit.rows = vec![
            RowKind::Heading,
            RowKind::Domain(landlock_observability::event::DomainId::new(2)),
        ];
        app.scroll = 1;
        click_row(&mut app, 6, 6);
        assert_eq!(
            app.selected,
            Some(RowKind::Domain(
                landlock_observability::event::DomainId::new(2)
            ))
        );
        app.selected = None;
        app.detail = false;
        click_row(&mut app, 6, 5);
        assert_eq!(app.selected, None);
        assert!(!app.detail);
        click_row(&mut app, 6, 14);
        assert_eq!(app.selected, None);
    }
}
