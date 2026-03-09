//! UI rendering for the review TUI.

use super::app::{
    App, DetailRow, LayoutAreas, MessageKind, Panel, describe_pattern, extract_operators,
};
use crate::pending::display_project_path;
use crate::settings_writer::Scope;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

const SIDEBAR_WIDTH: u16 = 24;
const DETAIL_HEIGHT: u16 = 12;

pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),             // Header
            Constraint::Min(6),                // Main (sidebar + commands)
            Constraint::Length(DETAIL_HEIGHT), // Detail panel
            Constraint::Length(1),             // Footer
        ])
        .split(f.area());

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(SIDEBAR_WIDTH), Constraint::Min(30)])
        .split(chunks[1]);

    // Store layout for mouse hit-testing
    app.layout = LayoutAreas {
        sidebar: main_chunks[0],
        commands: main_chunks[1],
        detail: chunks[2],
    };

    draw_header(f, app, chunks[0]);
    draw_sidebar(f, app, main_chunks[0]);
    draw_command_list(f, app, main_chunks[1]);
    draw_detail(f, app, chunks[2]);
    draw_footer(f, app, chunks[3]);
}

// === Header ===

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let total = app.total_pending();
    let visible = app.visible.len();
    let projects = app.projects.len();

    let project_name = if app.is_all_view() {
        "all projects".to_string()
    } else if let Some(p) = app.projects.get(app.project_cursor) {
        p.name.clone()
    } else {
        "unknown".to_string()
    };

    let text = format!(
        " bash-gates review -- {visible} commands ({project_name}) -- {total} total across {projects} project(s)"
    );

    let header = Paragraph::new(Line::from(Span::styled(
        text,
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    f.render_widget(header, area);
}

// === Sidebar ===

fn draw_sidebar(f: &mut Frame, app: &mut App, area: Rect) {
    let focused = app.panel == Panel::Sidebar;
    let mut items: Vec<ListItem> = Vec::new();

    for (i, project) in app.projects.iter().enumerate() {
        let selected = i == app.project_cursor;
        let style = if selected {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let prefix = if selected { " > " } else { "   " };
        let count_str = format!(" ({})", project.count);

        // Truncate name to fit sidebar
        let max_name = (SIDEBAR_WIDTH as usize).saturating_sub(count_str.len() + 5);
        let name = if project.name.chars().count() > max_name {
            let truncated: String = project
                .name
                .chars()
                .take(max_name.saturating_sub(3))
                .collect();
            format!("{}...", truncated)
        } else {
            project.name.clone()
        };

        items.push(ListItem::new(Line::from(vec![
            Span::styled(prefix, style),
            Span::styled(name, style),
            Span::styled(count_str, Style::default().fg(Color::DarkGray)),
        ])));
    }

    // "All" entry
    let all_selected = app.project_cursor >= app.projects.len();
    let all_style = if all_selected {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    let all_prefix = if all_selected { " > " } else { "   " };
    let all_count = format!(" ({})", app.entries.len());

    // Separator before "All"
    if !app.projects.is_empty() {
        items.push(ListItem::new(Line::from(Span::styled(
            "   -------",
            Style::default().fg(Color::DarkGray),
        ))));
    }
    items.push(ListItem::new(Line::from(vec![
        Span::styled(all_prefix, all_style),
        Span::styled("All", all_style),
        Span::styled(all_count, Style::default().fg(Color::DarkGray)),
    ])));

    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let list = List::new(items).highlight_style(Style::default()).block(
        Block::default()
            .title(" Projects ")
            .borders(Borders::ALL)
            .border_style(border_style),
    );
    f.render_stateful_widget(list, area, &mut app.sidebar_state);
}

// === Command List ===

fn draw_command_list(f: &mut Frame, app: &mut App, area: Rect) {
    let focused = app.panel == Panel::CommandList;
    let is_all = app.is_all_view();
    let cursor = app.command_cursor;

    // Build items from borrowed data, then release borrow for stateful render
    let items: Vec<ListItem> = app
        .visible
        .iter()
        .enumerate()
        .map(|(i, &entry_idx)| {
            let entry = &app.entries[entry_idx];
            let is_cursor = i == cursor;
            let is_multi = app.multi_selected.contains(&i);

            let prefix = if is_multi {
                " + "
            } else if is_cursor {
                " > "
            } else {
                "   "
            };

            let prefix_style = if is_multi {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else if is_cursor {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let cmd_spans = command_spans(entry);
            let count_str = format!("  {}x", entry.count);

            let mut spans = vec![Span::styled(prefix, prefix_style)];
            spans.extend(cmd_spans);
            spans.push(Span::styled(
                count_str,
                Style::default().fg(Color::DarkGray),
            ));

            if is_all {
                let proj = display_project_path(entry);
                let short = proj.rsplit('/').next().unwrap_or(&proj).to_string();
                spans.push(Span::styled(
                    format!("  {}", short),
                    Style::default().fg(Color::DarkGray),
                ));
            }

            ListItem::new(Line::from(spans))
        })
        .collect();

    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let title = if app.multi_selected.is_empty() {
        " Commands ".to_string()
    } else {
        format!(" Commands ({} selected) ", app.multi_selected.len())
    };

    let list = List::new(items).highlight_style(Style::default()).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style),
    );
    f.render_stateful_widget(list, area, &mut app.command_state);
}

/// Build colored spans for a command, highlighting segments by decision
fn command_spans<'a>(entry: &'a crate::pending::PendingApproval) -> Vec<Span<'a>> {
    if entry.breakdown.len() <= 1 {
        // Simple command - single color
        let color = entry
            .breakdown
            .first()
            .map(|p| decision_color(&p.decision))
            .unwrap_or(Color::Yellow);
        return vec![Span::styled(
            entry.command.as_str(),
            Style::default().fg(color),
        )];
    }

    // Compound command - color each segment
    let operators = extract_operators(&entry.command);
    let mut spans = Vec::new();

    for (i, part) in entry.breakdown.iter().enumerate() {
        if i > 0 {
            let op = operators.get(i - 1).copied().unwrap_or("&&");
            spans.push(Span::styled(
                format!(" {} ", op),
                Style::default().fg(Color::DarkGray),
            ));
        }

        let color = decision_color(&part.decision);
        let text = if part.args.is_empty() {
            part.program.clone()
        } else {
            format!("{} {}", part.program, part.args.join(" "))
        };
        spans.push(Span::styled(text, Style::default().fg(color)));
    }

    spans
}

fn decision_color(decision: &str) -> Color {
    match decision {
        "allow" => Color::Green,
        "block" => Color::Red,
        _ => Color::Yellow,
    }
}

// === Detail Panel ===

fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let focused = app.panel == Panel::Detail;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let Some(entry) = app.current_entry() else {
        let empty = Paragraph::new(" No commands to review")
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(border_style),
            );
        f.render_widget(empty, area);
        return;
    };

    // Title: full command + count
    let title = format!(" {} ", entry.command);
    let block = Block::default()
        .title(title)
        .title_bottom(Line::from(message_spans(app)))
        .borders(Borders::ALL)
        .border_style(border_style);

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Layout inside detail panel
    let is_compound = entry.breakdown.len() > 1;
    let has_tip = app.compound_tip().is_some();
    let has_reason = app.current_reason().is_some();

    let mut constraints = Vec::new();
    if is_compound {
        constraints.push(Constraint::Length(2)); // Segments
    }
    if has_reason {
        constraints.push(Constraint::Length(1)); // Reason
    }
    constraints.push(Constraint::Length(1)); // Pattern
    constraints.push(Constraint::Length(2)); // Scope + target
    if has_tip {
        constraints.push(Constraint::Length(1)); // Tip
    }
    constraints.push(Constraint::Length(1)); // Actions
    constraints.push(Constraint::Min(0)); // Spacer

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let mut row_idx = 0;

    // Segments (compound only)
    if is_compound {
        draw_segments(f, app, entry, rows[row_idx]);
        row_idx += 1;
    }

    // Reason
    if let Some(reason) = app.current_reason() {
        let reason_line = Line::from(vec![
            Span::styled(" Reason: ", Style::default().fg(Color::DarkGray)),
            Span::styled(reason, Style::default().fg(Color::White)),
        ]);
        f.render_widget(Paragraph::new(reason_line), rows[row_idx]);
        row_idx += 1;
    }

    // Pattern
    draw_pattern_row(f, app, rows[row_idx]);
    row_idx += 1;

    // Scope + target
    draw_scope_row(f, app, rows[row_idx]);
    row_idx += 1;

    // Tip
    if let Some(tip) = app.compound_tip() {
        let tip_line = Line::from(Span::styled(
            format!(" i {}", tip),
            Style::default().fg(Color::DarkGray),
        ));
        f.render_widget(Paragraph::new(tip_line), rows[row_idx]);
        row_idx += 1;
    }

    // Actions
    draw_actions(f, app, rows[row_idx]);
}

fn draw_segments(f: &mut Frame, app: &App, entry: &crate::pending::PendingApproval, area: Rect) {
    let focused = app.panel == Panel::Detail && app.detail_row == DetailRow::Segments;
    let actionable = app.actionable_segments();
    let operators = extract_operators(&entry.command);

    let mut spans: Vec<Span> = vec![Span::raw(" ")];

    for (i, part) in entry.breakdown.iter().enumerate() {
        if i > 0 {
            let op = operators.get(i - 1).copied().unwrap_or("&&");
            spans.push(Span::styled(
                format!(" {} ", op),
                Style::default().fg(Color::DarkGray),
            ));
        }

        let is_actionable_idx = actionable.iter().position(|&ai| ai == i);
        let is_selected = focused
            && is_actionable_idx
                .map(|ai| ai == app.selected_segment)
                .unwrap_or(false);

        let color = decision_color(&part.decision);
        let text = if part.args.is_empty() {
            part.program.clone()
        } else {
            format!("{} {}", part.program, part.args.join(" "))
        };

        if is_selected {
            spans.push(Span::styled(
                format!("[{}]", text),
                Style::default()
                    .fg(color)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ));
        } else {
            spans.push(Span::styled(text, Style::default().fg(color)));
        }
    }

    let label = if focused { " Segments " } else { "" };
    let row_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    let para = Paragraph::new(vec![
        Line::from(vec![Span::styled(label, row_style)]),
        Line::from(spans),
    ])
    .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

fn draw_pattern_row(f: &mut Frame, app: &App, area: Rect) {
    let focused = app.panel == Panel::Detail && app.detail_row == DetailRow::Pattern;
    let patterns = app.current_patterns();
    let pattern = patterns.get(app.selected_pattern);

    let description = pattern
        .map(|p| describe_pattern(p))
        .unwrap_or_else(|| "(no patterns)".to_string());

    let technical = pattern.map(|p| p.as_str()).unwrap_or("");

    let label_style = if focused {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let value_style = if focused {
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };

    let arrows = if focused && patterns.len() > 1 {
        " <  > "
    } else {
        ""
    };

    let line = Line::from(vec![
        Span::styled(" Pattern: ", label_style),
        Span::styled(description, value_style),
        Span::styled(
            format!("  ({})", technical),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(arrows, Style::default().fg(Color::Cyan)),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_scope_row(f: &mut Frame, app: &App, area: Rect) {
    let focused = app.panel == Panel::Detail && app.detail_row == DetailRow::Scope;

    let scope_text = match app.scope {
        Scope::User => "Global (all projects)",
        Scope::Project => "This project (shared)",
        Scope::Local => "This project (local only)",
    };

    let label_style = if focused {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let value_style = if focused {
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };

    let arrows = if focused { " <  > " } else { "" };

    let lines = vec![
        Line::from(vec![
            Span::styled(" Scope:   ", label_style),
            Span::styled(scope_text, value_style),
            Span::styled(arrows, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled("          -> ", Style::default().fg(Color::DarkGray)),
            Span::styled(app.target_path(), Style::default().fg(Color::DarkGray)),
        ]),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

fn draw_actions(f: &mut Frame, app: &App, area: Rect) {
    let focused = app.panel == Panel::Detail;
    let has_multi = !app.multi_selected.is_empty();

    let approve_text = if has_multi {
        format!(" Enter: Approve {} ", app.multi_selected.len())
    } else {
        " Enter: Approve ".to_string()
    };

    let skip_text = if has_multi {
        format!(" d: Skip {} ", app.multi_selected.len())
    } else {
        " d: Skip ".to_string()
    };

    let approve_style = if focused {
        Style::default()
            .fg(Color::Black)
            .bg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green)
    };
    let skip_style = if focused {
        Style::default().fg(Color::Black).bg(Color::Yellow)
    } else {
        Style::default().fg(Color::Yellow)
    };
    let deny_style = if focused {
        Style::default().fg(Color::Black).bg(Color::Red)
    } else {
        Style::default().fg(Color::Red)
    };

    let line = Line::from(vec![
        Span::raw("          "),
        Span::styled(approve_text, approve_style),
        Span::raw("   "),
        Span::styled(skip_text, skip_style),
        Span::raw("   "),
        Span::styled(" D: Deny ", deny_style),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn message_spans(app: &App) -> Vec<Span<'static>> {
    let Some((msg, kind)) = &app.message else {
        return Vec::new();
    };
    let color = match kind {
        MessageKind::Success => Color::Green,
        MessageKind::Error => Color::Red,
        MessageKind::Info => Color::Yellow,
    };
    vec![
        Span::raw(" "),
        Span::styled(msg.clone(), Style::default().fg(color)),
        Span::raw(" "),
    ]
}

// === Footer ===

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let has_multi = !app.multi_selected.is_empty();

    let mut spans = vec![
        Span::styled(" Tab", Style::default().fg(Color::Yellow)),
        Span::raw(" panel  "),
        Span::styled("^/v", Style::default().fg(Color::Yellow)),
        Span::raw(" nav  "),
    ];

    if app.panel == Panel::Detail {
        spans.push(Span::styled("</>", Style::default().fg(Color::Yellow)));
        spans.push(Span::raw(" cycle  "));
    }

    if app.panel == Panel::CommandList {
        spans.push(Span::styled("Space", Style::default().fg(Color::Yellow)));
        spans.push(Span::raw(" select  "));
    }

    spans.push(Span::styled("Enter", Style::default().fg(Color::Green)));
    spans.push(Span::raw(" approve  "));
    spans.push(Span::styled("d", Style::default().fg(Color::Yellow)));
    spans.push(Span::raw(" skip  "));

    if !has_multi {
        spans.push(Span::styled("D", Style::default().fg(Color::Red)));
        spans.push(Span::raw(" deny  "));
    }

    spans.push(Span::styled("q", Style::default().fg(Color::Yellow)));
    spans.push(Span::raw(" quit"));

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}
