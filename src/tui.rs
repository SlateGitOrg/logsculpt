//! Interactive terminal timeline viewer, built on ratatui.
//!
//! The app state (`TuiApp`) and the render function (`ui`) are both
//! decoupled from any real terminal: `ui` takes a ratatui `Frame`, which
//! works identically against `ratatui::backend::TestBackend` in unit tests
//! and against a real `crossterm` terminal at runtime. Only [`run`] (the
//! event loop) needs an actual TTY, so it's excluded from the unit-tested
//! surface and exercised only via manual/E2E use.

use crate::anomaly::{ErrorCluster, RateSpike};
use crate::output::AnomalyIndex;
use crate::schema::{LogEntry, Severity};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

/// Everything the TUI needs to render one frame; independent of I/O so it's
/// trivially unit-testable.
pub struct TuiApp {
    pub entries: Vec<LogEntry>,
    /// Parallel to `entries`: true if that entry falls in a rate-spike
    /// bucket or a rare-error cluster.
    pub anomalies: Vec<bool>,
    pub selected: usize,
    pub should_quit: bool,
    pub spike_count: usize,
    pub cluster_count: usize,
}

impl TuiApp {
    pub fn new(
        entries: Vec<LogEntry>,
        spikes: &[RateSpike],
        bucket_ms: i64,
        clusters: &[ErrorCluster],
    ) -> Self {
        let index = AnomalyIndex::build(spikes, bucket_ms, clusters);
        let anomalies = entries
            .iter()
            .map(|e| {
                let rec = crate::output::annotate(e, &index);
                rec.is_rate_spike || rec.is_rare_error_cluster
            })
            .collect();
        TuiApp {
            entries,
            anomalies,
            selected: 0,
            should_quit: false,
            spike_count: spikes.len(),
            cluster_count: clusters.len(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn move_down(&mut self, n: usize) {
        if self.entries.is_empty() {
            return;
        }
        self.selected = (self.selected + n).min(self.entries.len() - 1);
    }

    pub fn move_up(&mut self, n: usize) {
        self.selected = self.selected.saturating_sub(n);
    }

    pub fn move_to_top(&mut self) {
        self.selected = 0;
    }

    pub fn move_to_bottom(&mut self) {
        self.selected = self.entries.len().saturating_sub(1);
    }

    pub fn jump_to_next_anomaly(&mut self) {
        if let Some(offset) = self.anomalies
            [self.selected.saturating_add(1).min(self.anomalies.len())..]
            .iter()
            .position(|&a| a)
        {
            self.selected = self.selected + 1 + offset;
        }
    }

    pub fn quit(&mut self) {
        self.should_quit = true;
    }
}

fn severity_color(sev: Severity) -> Color {
    match sev {
        Severity::Critical => Color::Magenta,
        Severity::Error => Color::Red,
        Severity::Warn => Color::Yellow,
        Severity::Notice => Color::Cyan,
        Severity::Info => Color::Green,
        Severity::Debug | Severity::Trace => Color::DarkGray,
        Severity::Unknown => Color::Gray,
    }
}

/// Render one frame. Public and side-effect-free beyond drawing, so it can
/// be driven by a `TestBackend` in tests just as well as a real terminal.
pub fn ui(f: &mut Frame, app: &TuiApp) {
    let area = f.area();
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(area);

    render_header(f, chunks[0], app);
    render_list(f, chunks[1], app);
    render_footer(f, chunks[2], app);
}

fn render_header(f: &mut Frame, area: Rect, app: &TuiApp) {
    let text = format!(
        " logsculpt — {} entries — {} rate spikes — {} rare-error clusters ",
        app.entries.len(),
        app.spike_count,
        app.cluster_count
    );
    f.render_widget(
        Paragraph::new(text).style(Style::default().add_modifier(Modifier::BOLD)),
        area,
    );
}

fn render_footer(f: &mut Frame, area: Rect, _app: &TuiApp) {
    f.render_widget(
        Paragraph::new(" ↑/↓ scroll · n next anomaly · g/G top/bottom · q quit ")
            .style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

fn render_list(f: &mut Frame, area: Rect, app: &TuiApp) {
    let visible_height = area.height as usize;
    let start = visible_window_start(app.selected, app.entries.len(), visible_height);
    let end = (start + visible_height).min(app.entries.len());

    let items: Vec<ListItem> = app.entries[start..end]
        .iter()
        .zip(app.anomalies[start..end].iter())
        .enumerate()
        .map(|(offset, (entry, &is_anomaly))| {
            let idx = start + offset;
            let marker = if is_anomaly { "⚠ " } else { "  " };
            let mut style = Style::default().fg(severity_color(entry.severity));
            if idx == app.selected {
                style = style.add_modifier(Modifier::REVERSED);
            }
            let line = Line::from(vec![
                Span::raw(marker),
                Span::raw(format!("{} ", entry.timestamp_rfc3339())),
                Span::styled(format!("[{:<8}] ", entry.severity), style),
                Span::raw(
                    entry
                        .service
                        .clone()
                        .unwrap_or_else(|| entry.source_name.clone()),
                ),
                Span::raw(": "),
                Span::raw(entry.message.clone()),
            ]);
            ListItem::new(line).style(if idx == app.selected {
                Style::default().add_modifier(Modifier::REVERSED)
            } else {
                Style::default()
            })
        })
        .collect();

    let list = List::new(items).block(Block::default().borders(Borders::NONE));
    f.render_widget(list, area);
}

/// Compute the top-of-viewport index so the selected row stays visible,
/// keeping it vertically centered where possible (classic pager behavior).
fn visible_window_start(selected: usize, total: usize, height: usize) -> usize {
    if height == 0 || total <= height {
        return 0;
    }
    let half = height / 2;
    let start = selected.saturating_sub(half);
    start.min(total - height)
}

#[cfg(not(test))]
pub fn run(app: TuiApp) -> anyhow::Result<()> {
    use crossterm::{
        event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::{backend::CrosstermBackend, Terminal};
    use std::io::stdout;

    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let mut app = app;
    let result = (|| -> anyhow::Result<()> {
        loop {
            terminal.draw(|f| ui(f, &app))?;
            if event::poll(std::time::Duration::from_millis(200))? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.quit(),
                        KeyCode::Down | KeyCode::Char('j') => app.move_down(1),
                        KeyCode::Up | KeyCode::Char('k') => app.move_up(1),
                        KeyCode::PageDown => app.move_down(20),
                        KeyCode::PageUp => app.move_up(20),
                        KeyCode::Char('g') => app.move_to_top(),
                        KeyCode::Char('G') => app.move_to_bottom(),
                        KeyCode::Char('n') => app.jump_to_next_anomaly(),
                        _ => {}
                    }
                }
            }
            if app.should_quit {
                break;
            }
        }
        Ok(())
    })();

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::SourceFormat;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::collections::BTreeMap;

    fn mk_entry(ts: i64, sev: Severity, msg: &str) -> LogEntry {
        LogEntry {
            timestamp_ms: ts,
            severity: sev,
            host: None,
            service: Some("svc".to_string()),
            message: msg.to_string(),
            source_format: SourceFormat::Json,
            source_name: "a.log".to_string(),
            fields: BTreeMap::new(),
            raw: msg.to_string(),
        }
    }

    fn sample_app(n: usize) -> TuiApp {
        let entries: Vec<LogEntry> = (0..n)
            .map(|i| mk_entry(i as i64 * 1000, Severity::Info, &format!("line {i}")))
            .collect();
        TuiApp::new(entries, &[], 1000, &[])
    }

    #[test]
    fn navigation_bounds_are_clamped() {
        let mut app = sample_app(5);
        app.move_up(10);
        assert_eq!(app.selected, 0);
        app.move_down(100);
        assert_eq!(app.selected, 4);
        app.move_to_top();
        assert_eq!(app.selected, 0);
        app.move_to_bottom();
        assert_eq!(app.selected, 4);
    }

    #[test]
    fn empty_app_does_not_panic_on_navigation() {
        let mut app = TuiApp::new(Vec::new(), &[], 1000, &[]);
        app.move_down(5);
        app.move_up(5);
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn jump_to_next_anomaly_skips_normal_entries() {
        let entries: Vec<LogEntry> = (0..10)
            .map(|i| mk_entry(i * 1000, Severity::Error, "boom unique-marker"))
            .collect();
        // Force entry 5 into a rate-spike bucket by constructing a synthetic spike.
        let spike = RateSpike {
            bucket_start_ms: 5000,
            count: 1,
            mean: 0.0,
            stddev: 0.0,
            z_score: 0.0,
        };
        let mut app = TuiApp::new(entries, &[spike], 1000, &[]);
        assert!(app.anomalies[5]);
        app.selected = 0;
        app.jump_to_next_anomaly();
        assert_eq!(app.selected, 5);
    }

    #[test]
    fn renders_without_panicking_on_test_backend() {
        let app = sample_app(50);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui(f, &app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let content: String = buffer.content.iter().map(|c| c.symbol()).collect();
        assert!(content.contains("logsculpt"));
    }

    #[test]
    fn renders_selected_row_within_small_viewport() {
        let mut app = sample_app(200);
        app.selected = 150;
        let backend = TestBackend::new(80, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|f| ui(f, &app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let content: String = buffer.content.iter().map(|c| c.symbol()).collect();
        // The line around the selected entry should be visible in the viewport.
        assert!(content.contains("line 150"));
    }

    #[test]
    fn visible_window_start_keeps_selection_in_range() {
        assert_eq!(visible_window_start(0, 100, 10), 0);
        assert_eq!(visible_window_start(99, 100, 10), 90);
        let start = visible_window_start(50, 100, 10);
        assert!(50 >= start && 50 < start + 10);
    }
}
