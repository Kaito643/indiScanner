//! Interactive terminal UI over the same engine the CLI uses.
//!
//! A single-binary front door: type `enrich <ioc>` or `collect <name>` in the
//! query bar, browse the scored indicators on the left, read full provenance on
//! the right. Queries run on background tasks so the UI never freezes; results
//! arrive over a channel. `e` exports the current set to JSON, `d` downloads the
//! selected SHA-256 sample.

use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use ratatui::{prelude::*, widgets::*};
use std::path::Path;
use std::sync::Arc;
use threat_harvester::engine::{Engine, Outcome};
use threat_harvester::export::{self, Format};
use threat_harvester::model::entity::ThreatEntity;
use threat_harvester::model::indicator::{Indicator, IndicatorType};
use threat_harvester::model::request::{Filters, RawIoc, Request};
use tokio::sync::mpsc;

const EXPORT_PATH: &str = "th-export.json";

/// Launch the TUI, borrowing the built engine. Returns when the user quits.
pub async fn run(engine: Engine) -> anyhow::Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut app = App::new(Arc::new(engine), tx);

    let mut terminal = ratatui::init();
    let mut events = EventStream::new();
    let result = loop {
        if let Err(e) = terminal.draw(|f| ui(f, &mut app)) {
            break Err(e.into());
        }
        tokio::select! {
            maybe = events.next() => match maybe {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                    if app.on_key(key) {
                        break Ok(());
                    }
                }
                Some(Err(e)) => break Err(e.into()),
                None => break Ok(()),
                _ => {}
            },
            Some(msg) = rx.recv() => app.apply(msg),
        }
    };
    ratatui::restore();
    result
}

/// A message from a background task back to the UI.
enum Msg {
    Results(Vec<Indicator>),
    Error(String),
    Status(String),
}

enum Mode {
    /// Typing a query in the bar.
    Input,
    /// Navigating results.
    Browse,
}

struct App {
    engine: Arc<Engine>,
    tx: mpsc::UnboundedSender<Msg>,
    mode: Mode,
    input: String,
    status: String,
    indicators: Vec<Indicator>,
    list: ListState,
    samples_dir: String,
}

impl App {
    fn new(engine: Arc<Engine>, tx: mpsc::UnboundedSender<Msg>) -> Self {
        Self {
            engine,
            tx,
            mode: Mode::Input,
            input: String::new(),
            status: "type a query, e.g. `enrich 1.1.1.1` or `collect LockBit`".to_string(),
            indicators: Vec::new(),
            list: ListState::default(),
            samples_dir: "samples".to_string(),
        }
    }

    fn selected(&self) -> Option<&Indicator> {
        self.list.selected().and_then(|i| self.indicators.get(i))
    }

    /// Returns `true` when the app should quit.
    fn on_key(&mut self, key: KeyEvent) -> bool {
        // Ctrl-C always quits.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return true;
        }
        match self.mode {
            Mode::Input => match key.code {
                KeyCode::Enter => self.submit(),
                KeyCode::Esc => self.mode = Mode::Browse,
                KeyCode::Backspace => {
                    self.input.pop();
                }
                KeyCode::Char(c) => self.input.push(c),
                _ => {}
            },
            Mode::Browse => match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Char('i') | KeyCode::Char('/') => self.mode = Mode::Input,
                KeyCode::Char('j') | KeyCode::Down => self.step(1),
                KeyCode::Char('k') | KeyCode::Up => self.step(-1),
                KeyCode::Char('e') => self.export(),
                KeyCode::Char('d') => self.download_selected(),
                _ => {}
            },
        }
        false
    }

    fn step(&mut self, delta: isize) {
        if self.indicators.is_empty() {
            return;
        }
        let last = self.indicators.len() - 1;
        let cur = self.list.selected().unwrap_or(0) as isize;
        let next = (cur + delta).clamp(0, last as isize) as usize;
        self.list.select(Some(next));
    }

    fn submit(&mut self) {
        let query = self.input.trim().to_string();
        self.mode = Mode::Browse;
        if query.is_empty() {
            return;
        }
        let request = match parse_query(&query) {
            Ok(r) => r,
            Err(e) => {
                self.status = format!("parse error: {e}");
                return;
            }
        };
        self.status = format!("querying: {query} …");
        let engine = self.engine.clone();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let msg = match engine.run(request).await {
                Ok(inds) => Msg::Results(inds),
                Err(e) => Msg::Error(format!("{e:#}")),
            };
            let _ = tx.send(msg);
        });
    }

    fn export(&mut self) {
        if self.indicators.is_empty() {
            self.status = "nothing to export".to_string();
            return;
        }
        self.status = match export::render(&self.indicators, Format::Json)
            .map_err(|e| e.to_string())
            .and_then(|s| std::fs::write(EXPORT_PATH, s).map_err(|e| e.to_string()))
        {
            Ok(()) => format!(
                "exported {} indicator(s) to {EXPORT_PATH}",
                self.indicators.len()
            ),
            Err(e) => format!("export failed: {e}"),
        };
    }

    fn download_selected(&mut self) {
        let Some(ind) = self.selected() else {
            self.status = "nothing selected".to_string();
            return;
        };
        if ind.indicator_type != IndicatorType::Sha256 {
            self.status = "select a SHA-256 indicator to download".to_string();
            return;
        }
        let hash = ind.value.clone();
        let dir = self.samples_dir.clone();
        let engine = self.engine.clone();
        let tx = self.tx.clone();
        self.status = format!("downloading {}… ", &hash[..16.min(hash.len())]);
        tokio::spawn(async move {
            let reports = engine.download(&[hash], Path::new(&dir), false).await;
            let text = match reports.into_iter().next().map(|r| r.outcome) {
                Some(Outcome::Saved { archive, .. }) => format!("saved {}", archive.display()),
                Some(Outcome::NotFound) => "sample not available from any source".to_string(),
                Some(Outcome::Failed(e)) => format!("download failed: {e}"),
                None => "no download result".to_string(),
            };
            let _ = tx.send(Msg::Status(text));
        });
    }

    fn apply(&mut self, msg: Msg) {
        match msg {
            Msg::Results(mut inds) => {
                inds.sort_by_key(|i| std::cmp::Reverse(i.confidence));
                let n = inds.len();
                self.indicators = inds;
                self.list.select((n > 0).then_some(0));
                self.status = format!("{n} indicator(s) — j/k to browse");
            }
            Msg::Error(e) => self.status = format!("error: {e}"),
            Msg::Status(s) => self.status = s,
        }
    }
}

/// Parse a query-bar line into a [`Request`]. A bare value (no verb) enriches.
fn parse_query(q: &str) -> Result<Request, String> {
    let parts: Vec<&str> = q.split_whitespace().collect();
    match parts.first().copied() {
        Some("enrich") => {
            let value = parts.get(1).ok_or("`enrich` needs a value")?;
            Ok(Request::Enrich(RawIoc::new(*value)))
        }
        Some("collect") => {
            let name = parts.get(1).ok_or("`collect` needs a name")?;
            let mut kind = "malware";
            let mut filters = Filters::default();
            let mut i = 2;
            while i < parts.len() {
                let val = || parts.get(i + 1).copied();
                match parts[i] {
                    "--kind" | "-k" => {
                        kind = val().ok_or("`--kind` needs a value")?;
                        i += 2;
                    }
                    "--limit" | "-l" => {
                        let n = val().ok_or("`--limit` needs a number")?;
                        filters.max_results =
                            Some(n.parse().map_err(|_| "`--limit` must be a number")?);
                        i += 2;
                    }
                    "--tag" => {
                        filters.tag = Some(val().ok_or("`--tag` needs a value")?.to_string());
                        i += 2;
                    }
                    "--type" => {
                        filters.ioc_type = Some(val().ok_or("`--type` needs a value")?.to_string());
                        i += 2;
                    }
                    "--min-confidence" | "-m" => {
                        let n = val().ok_or("`--min-confidence` needs a number")?;
                        filters.min_confidence =
                            Some(n.parse().map_err(|_| "`--min-confidence` must be 0-100")?);
                        i += 2;
                    }
                    other => return Err(format!("unknown option `{other}`")),
                }
            }
            Ok(Request::Collect {
                entity: ThreatEntity::new(name.to_string(), crate::parse_kind(kind)),
                filters,
            })
        }
        Some(_) => Ok(Request::Enrich(RawIoc::new(q.trim()))),
        None => Err("empty query".to_string()),
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(f.area());

    // Query bar.
    let editing = matches!(app.mode, Mode::Input);
    let bar_style = if editing {
        Style::new().fg(Color::Yellow)
    } else {
        Style::new().fg(Color::DarkGray)
    };
    let bar = Paragraph::new(format!("query> {}", app.input)).block(
        Block::bordered()
            .border_style(bar_style)
            .title("ThreatHarvester"),
    );
    f.render_widget(bar, rows[0]);
    if editing {
        let x = rows[0].x + 8 + app.input.chars().count() as u16;
        f.set_cursor_position((x, rows[0].y + 1));
    }

    // Left list / right detail.
    let cols =
        Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)]).split(rows[1]);

    let items: Vec<ListItem> = app
        .indicators
        .iter()
        .map(|ind| {
            let color = conf_color(ind.confidence);
            ListItem::new(Line::from(vec![
                Span::styled("● ", Style::new().fg(color)),
                Span::styled(format!("{:>3} ", ind.confidence), Style::new().fg(color)),
                Span::styled(
                    ind.indicator_type.as_tag().to_string(),
                    Style::new().fg(Color::DarkGray),
                ),
                Span::raw(format!(" {}", truncate(&ind.value, 24))),
            ]))
        })
        .collect();
    let list = List::new(items)
        .block(Block::bordered().title(format!("Indicators ({})", app.indicators.len())))
        .highlight_style(
            Style::new()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    f.render_stateful_widget(list, cols[0], &mut app.list);

    let detail = Paragraph::new(detail_lines(app))
        .block(Block::bordered().title("Detail"))
        .wrap(Wrap { trim: false });
    f.render_widget(detail, cols[1]);

    // Footer: status + context help.
    let help = if editing {
        "Enter run · Esc cancel"
    } else {
        "i search · j/k move · e export · d download · q quit"
    };
    let footer = Line::from(vec![
        Span::styled(format!(" {} ", app.status), Style::new().fg(Color::Cyan)),
        Span::styled(format!("  {help}"), Style::new().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(footer), rows[2]);
}

fn detail_lines(app: &App) -> Vec<Line<'static>> {
    let Some(ind) = app.selected() else {
        return vec![Line::from(Span::styled(
            "no indicator selected",
            Style::new().fg(Color::DarkGray),
        ))];
    };

    let label = |s: &str| Span::styled(format!("{s:<10}"), Style::new().fg(Color::DarkGray));
    let mut lines = vec![
        Line::from(vec![label("value"), Span::raw(ind.value.clone())]),
        Line::from(vec![
            label("type"),
            Span::raw(ind.indicator_type.as_tag().to_string()),
        ]),
        Line::from(vec![
            label("confidence"),
            Span::styled(
                ind.confidence.to_string(),
                Style::new()
                    .fg(conf_color(ind.confidence))
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled("SOURCES", Style::new().fg(Color::Cyan))),
    ];
    for o in &ind.observations {
        let mut spans = vec![
            Span::raw(format!("  {:<14}", o.source)),
            Span::styled(
                format!("{:>3}", o.confidence),
                Style::new().fg(conf_color(o.confidence)),
            ),
        ];
        if let Some((k, v)) = o.context.iter().next() {
            spans.push(Span::styled(
                format!("  {k}={v}"),
                Style::new().fg(Color::DarkGray),
            ));
        }
        lines.push(Line::from(spans));
    }

    if !ind.attack_patterns.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "ATT&CK",
            Style::new().fg(Color::Cyan),
        )));
        let ids = ind
            .attack_patterns
            .iter()
            .map(|p| p.technique_id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(Line::from(format!("  {ids}")));
    }

    if !ind.relationships.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("EDGES ({})", ind.relationships.len()),
            Style::new().fg(Color::Cyan),
        )));
        for r in ind.relationships.iter().take(6) {
            lines.push(Line::from(Span::styled(
                format!("  {:?} → {}", r.kind, truncate(&r.target_value, 30)),
                Style::new().fg(Color::DarkGray),
            )));
        }
    }

    if !ind.tags.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "TAGS",
            Style::new().fg(Color::Cyan),
        )));
        lines.push(Line::from(format!(
            "  {}",
            truncate(&ind.tags.join(", "), 200)
        )));
    }
    lines
}

fn conf_color(c: u8) -> Color {
    match c {
        80..=100 => Color::Green,
        50..=79 => Color::Yellow,
        _ => Color::Gray,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        format!(
            "{}…",
            s.chars().take(max.saturating_sub(1)).collect::<String>()
        )
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_enrich_and_bare_value() {
        assert!(matches!(
            parse_query("enrich 1.2.3.4"),
            Ok(Request::Enrich(_))
        ));
        assert!(matches!(parse_query("1.2.3.4"), Ok(Request::Enrich(_))));
    }

    #[test]
    fn parses_collect_with_options() {
        let r = parse_query("collect LockBit --kind actor --limit 20").unwrap();
        match r {
            Request::Collect { entity, filters } => {
                assert_eq!(entity.name, "LockBit");
                assert_eq!(filters.max_results, Some(20));
            }
            _ => panic!("expected collect"),
        }
    }

    #[test]
    fn rejects_bad_options() {
        assert!(parse_query("collect X --limit abc").is_err());
        assert!(parse_query("collect X --bogus").is_err());
        assert!(parse_query("").is_err());
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("abc", 4), "abc");
    }
}
