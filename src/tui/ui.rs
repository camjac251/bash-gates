//! UI rendering for the review TUI.

use super::app::{App, Focus};
use crate::pending::CommandGroup;
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
    let total = app.total_pending();
    let groups = app.groups.len();
    let title = format!(
        " bash-gates review ({} commands in {} groups) ",
        total, groups
    );

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

    draw_group_list(f, app, chunks[0]);
    draw_group_detail(f, app, chunks[1]);
}

fn draw_group_list(f: &mut Frame, app: &mut App, area: Rect) {
    let is_focused = app.focus == Focus::CommandList;

    let items: Vec<ListItem> = app
        .groups
        .iter()
        .enumerate()
        .map(|(i, group)| {
            // Show base command and project count
            let cmd = if group.base_command.chars().count() > 30 {
                let truncated: String = group.base_command.chars().take(27).collect();
                format!("{}...", truncated)
            } else {
                group.base_command.clone()
            };

            let style = if i == app.selected_group {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let prefix = if i == app.selected_group {
                "▶ "
            } else {
                "  "
            };

            let project_count = format!("({})", group.projects.len());

            ListItem::new(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(cmd, style),
                Span::styled(" ", Style::default()),
                Span::styled(project_count, Style::default().fg(Color::DarkGray)),
            ]))
        })
        .collect();

    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    let list = List::new(items).block(
        Block::default()
            .title(" Commands ")
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    f.render_stateful_widget(list, area, &mut app.list_state);
}

fn draw_group_detail(f: &mut Frame, app: &App, area: Rect) {
    let Some(group) = app.current_group() else {
        let empty = Paragraph::new("No commands to review")
            .block(Block::default().title(" Details ").borders(Borders::ALL));
        f.render_widget(empty, area);
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),                                        // Command
            Constraint::Length(group.patterns().len().min(6) as u16 + 2), // Patterns
            Constraint::Length(5),                                        // Scope selection
            Constraint::Min(4),                                           // Projects
            Constraint::Length(3),                                        // Message
        ])
        .split(area);

    // Command
    let example_cmd = group
        .entries
        .first()
        .map(|e| e.command.as_str())
        .unwrap_or(&group.base_command);

    let cmd_block = Paragraph::new(example_cmd.to_string())
        .style(Style::default().fg(Color::White))
        .block(Block::default().title(" Command ").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    f.render_widget(cmd_block, chunks[0]);

    // Patterns
    draw_patterns_section(f, app, group, chunks[1]);

    // Scope selection
    draw_scope_section(f, app, chunks[2]);

    // Projects
    draw_projects_section(f, app, group, chunks[3]);

    // Message
    let msg_text = app.message.as_deref().unwrap_or("");
    let msg_style = if msg_text.contains("Approved") {
        Style::default().fg(Color::Green)
    } else if msg_text.contains("Error") {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::Yellow)
    };

    let msg_block = Paragraph::new(Span::styled(msg_text, msg_style))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(msg_block, chunks[4]);
}

fn draw_patterns_section(f: &mut Frame, app: &App, group: &CommandGroup, area: Rect) {
    let is_focused = app.focus == Focus::PatternList;
    let patterns = group.patterns();

    let pattern_items: Vec<ListItem> = patterns
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

    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    let patterns_list = List::new(pattern_items).block(
        Block::default()
            .title(" Patterns (1-9 to select) ")
            .borders(Borders::ALL)
            .border_style(border_style),
    );
    f.render_widget(patterns_list, area);
}

fn draw_scope_section(f: &mut Frame, app: &App, area: Rect) {
    let is_focused = app.focus == Focus::ScopeSelect;

    let scope_text = vec![
        Line::from(vec![
            Span::raw("Scope: "),
            scope_span(Scope::User, app.scope),
            Span::raw("  "),
            scope_span(Scope::Project, app.scope),
            Span::raw("  "),
            scope_span(Scope::Local, app.scope),
        ]),
        Line::from(vec![Span::styled(
            format!("Target: {}", app.target_path()),
            Style::default().fg(Color::DarkGray),
        )]),
    ];

    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    let scope_block = Paragraph::new(scope_text).block(
        Block::default()
            .title(" Scope (u/p/l) ")
            .borders(Borders::ALL)
            .border_style(border_style),
    );
    f.render_widget(scope_block, area);
}

fn draw_projects_section(f: &mut Frame, app: &App, group: &CommandGroup, area: Rect) {
    let is_focused = app.focus == Focus::ProjectList;
    let show_projects = app.scope != Scope::User;

    if !show_projects || group.projects.is_empty() {
        let text = if app.scope == Scope::User {
            "Applies to all projects (global)"
        } else {
            "No projects"
        };

        let block = Paragraph::new(text)
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().title(" Projects ").borders(Borders::ALL));
        f.render_widget(block, area);
        return;
    }

    let items: Vec<ListItem> = group
        .projects
        .iter()
        .enumerate()
        .map(|(i, project)| {
            let is_checked = app.selected_projects.contains(&i);
            let is_cursor = is_focused && i == app.project_cursor;
            let checkbox = if is_checked { "[x]" } else { "[ ]" };
            let checkbox_style = if is_checked {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            };

            // Truncate long paths (char-safe for UTF-8)
            let display_path = if project.chars().count() > 40 {
                let suffix: String = project
                    .chars()
                    .rev()
                    .take(37)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();
                format!("...{}", suffix)
            } else {
                project.clone()
            };

            let cursor_prefix = if is_cursor { "▶ " } else { "  " };
            let path_style = if is_cursor {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            ListItem::new(Line::from(vec![
                Span::styled(cursor_prefix, path_style),
                Span::styled(checkbox, checkbox_style),
                Span::styled(" ", Style::default()),
                Span::styled(display_path, path_style),
            ]))
        })
        .collect();

    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };

    let title = format!(" Projects ({} selected) ", app.selected_projects.len());
    let list = List::new(items).block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style),
    );
    f.render_widget(list, area);
}

fn scope_span(scope: Scope, current: Scope) -> Span<'static> {
    let text = match scope {
        Scope::User => "[U]ser",
        Scope::Project => "[P]roject",
        Scope::Local => "[L]ocal",
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
        Span::styled("Tab", Style::default().fg(Color::Yellow)),
        Span::raw(" focus  "),
        Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
        Span::raw(" nav  "),
        Span::styled("1-9", Style::default().fg(Color::Yellow)),
        Span::raw(" pattern  "),
        Span::styled("u/p/l", Style::default().fg(Color::Yellow)),
        Span::raw(" scope  "),
        Span::styled("Space", Style::default().fg(Color::Yellow)),
        Span::raw(" toggle  "),
        Span::styled("Enter", Style::default().fg(Color::Green)),
        Span::raw(" approve  "),
        Span::styled("d", Style::default().fg(Color::Red)),
        Span::raw(" skip  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]);

    let footer = Paragraph::new(help_text).block(Block::default().borders(Borders::ALL));

    f.render_widget(footer, area);
}
