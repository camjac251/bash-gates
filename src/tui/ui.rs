//! UI rendering for the review TUI.

use super::app::App;
use crate::settings_writer::Scope;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Main content
            Constraint::Length(3), // Footer/help
        ])
        .split(f.area());

    draw_header(f, app, chunks[0]);
    draw_main(f, app, chunks[1]);
    draw_footer(f, app, chunks[2]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let title = format!(" bash-gates review ({} pending) ", app.entries.len());

    let header = Paragraph::new(Line::from(vec![Span::styled(
        title,
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )]))
    .block(Block::default().borders(Borders::ALL));

    f.render_widget(header, area);
}

fn draw_main(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    draw_entry_list(f, app, chunks[0]);
    draw_entry_detail(f, app, chunks[1]);
}

fn draw_entry_list(f: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app
        .entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            // Show project_id (already abbreviated from transcript_path)
            let project_indicator = abbreviate_project_id(&entry.approval.project_id);

            let cmd = if entry.approval.command.chars().count() > 35 {
                let truncated: String = entry.approval.command.chars().take(32).collect();
                format!("{}...", truncated)
            } else {
                entry.approval.command.clone()
            };

            let style = if i == app.selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let prefix = if i == app.selected { "▶ " } else { "  " };

            ListItem::new(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(
                    format!("[{}] ", project_indicator),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(cmd, style),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().title(" Commands ").borders(Borders::ALL))
        .highlight_style(Style::default()); // Already highlighted via our custom styling

    f.render_stateful_widget(list, area, &mut app.list_state.clone());
}

fn draw_entry_detail(f: &mut Frame, app: &App, area: Rect) {
    let Some(entry) = app.current_entry() else {
        let empty = Paragraph::new("No entry selected")
            .block(Block::default().title(" Details ").borders(Borders::ALL));
        f.render_widget(empty, area);
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Command
            Constraint::Min(5),    // Patterns
            Constraint::Length(5), // Scope selection
            Constraint::Length(3), // Message
        ])
        .split(area);

    // Command
    let cmd_block = Paragraph::new(entry.approval.command.clone())
        .style(Style::default().fg(Color::White))
        .block(Block::default().title(" Command ").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    f.render_widget(cmd_block, chunks[0]);

    // Patterns
    let pattern_items: Vec<ListItem> = entry
        .approval
        .patterns
        .iter()
        .enumerate()
        .map(|(i, pattern)| {
            let is_selected = i == app.selected_pattern;
            let style = if is_selected {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let prefix = if is_selected { "● " } else { "○ " };
            let num = format!("[{}] ", i + 1);

            ListItem::new(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(num, Style::default().fg(Color::DarkGray)),
                Span::styled(pattern.clone(), style),
            ]))
        })
        .collect();

    let patterns_list = List::new(pattern_items).block(
        Block::default()
            .title(" Patterns (Tab/1-9 to select) ")
            .borders(Borders::ALL),
    );
    f.render_widget(patterns_list, chunks[1]);

    // Scope selection
    let scope_text = vec![
        Line::from(vec![
            Span::raw("Scope: "),
            scope_span(Scope::Local, app.scope),
            Span::raw(" "),
            scope_span(Scope::User, app.scope),
            Span::raw(" "),
            scope_span(Scope::Project, app.scope),
        ]),
        Line::from(vec![Span::styled(
            "Press 's' to change scope",
            Style::default().fg(Color::DarkGray),
        )]),
    ];

    let scope_block =
        Paragraph::new(scope_text).block(Block::default().title(" Target ").borders(Borders::ALL));
    f.render_widget(scope_block, chunks[2]);

    // Message
    let msg_text = app.message.as_deref().unwrap_or("");
    let msg_style = if msg_text.starts_with('✓') {
        Style::default().fg(Color::Green)
    } else if msg_text.starts_with("Error") {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::Yellow)
    };

    let msg_block = Paragraph::new(Span::styled(msg_text, msg_style))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(msg_block, chunks[3]);
}

fn scope_span(scope: Scope, current: Scope) -> Span<'static> {
    let text = match scope {
        Scope::Local => "[L]ocal",
        Scope::User => "[U]ser",
        Scope::Project => "[P]roject",
    };

    if scope == current {
        Span::styled(
            text,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(text, Style::default().fg(Color::DarkGray))
    }
}

fn draw_footer(f: &mut Frame, _app: &App, area: Rect) {
    let help_text = Line::from(vec![
        Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
        Span::raw(" nav  "),
        Span::styled("Tab", Style::default().fg(Color::Yellow)),
        Span::raw(" pattern  "),
        Span::styled("s", Style::default().fg(Color::Yellow)),
        Span::raw(" scope  "),
        Span::styled("Enter/a", Style::default().fg(Color::Green)),
        Span::raw(" approve  "),
        Span::styled("d", Style::default().fg(Color::Red)),
        Span::raw(" skip  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]);

    let footer = Paragraph::new(help_text).block(Block::default().borders(Borders::ALL));

    f.render_widget(footer, area);
}

/// Abbreviate a project_id for display
/// The project_id format is like "-home-user-projects-myapp"
/// We extract the last segment (after the last dash that follows a letter)
fn abbreviate_project_id(project_id: &str) -> String {
    // Project ID is sanitized path like "-home-user-projects-myapp"
    // Find last meaningful segment
    project_id
        .rsplit('-')
        .find(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| project_id.to_string())
}
