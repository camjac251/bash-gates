//! Application state and event handling for the review TUI.

use crate::pending::{PendingApproval, read_pending, remove_pending};
use crate::settings_writer::{RuleType, Scope, add_rule};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend, widgets::ListState};
use std::io;
use std::panic::AssertUnwindSafe;

use super::ui;

/// Entry for display (no longer needs location - all entries are global)
pub struct PendingEntry {
    pub approval: PendingApproval,
}

/// Application state
pub struct App {
    pub entries: Vec<PendingEntry>,
    pub selected: usize,
    pub selected_pattern: usize,
    pub scope: Scope,
    pub should_quit: bool,
    pub message: Option<String>,
    pub list_state: ListState,
    /// Cached current working directory (captured at startup)
    cwd: Option<String>,
}

impl App {
    pub fn new() -> Self {
        let cwd = std::env::current_dir()
            .ok()
            .and_then(|p| p.to_str().map(String::from));

        // Load all entries from global queue
        let entries: Vec<PendingEntry> = read_pending(None)
            .into_iter()
            .map(|approval| PendingEntry { approval })
            .collect();

        let mut list_state = ListState::default();
        if !entries.is_empty() {
            list_state.select(Some(0));
        }

        Self {
            entries,
            selected: 0,
            selected_pattern: 0,
            scope: Scope::Local,
            should_quit: false,
            message: None,
            list_state,
            cwd,
        }
    }

    #[allow(dead_code)]
    pub fn cwd(&self) -> Option<&str> {
        self.cwd.as_deref()
    }

    pub fn current_entry(&self) -> Option<&PendingEntry> {
        self.entries.get(self.selected)
    }

    pub fn next_entry(&mut self) {
        if !self.entries.is_empty() {
            self.selected = (self.selected + 1) % self.entries.len();
            self.selected_pattern = 0;
            self.list_state.select(Some(self.selected));
        }
    }

    pub fn prev_entry(&mut self) {
        if !self.entries.is_empty() {
            self.selected = if self.selected == 0 {
                self.entries.len() - 1
            } else {
                self.selected - 1
            };
            self.selected_pattern = 0;
            self.list_state.select(Some(self.selected));
        }
    }

    pub fn next_pattern(&mut self) {
        if let Some(entry) = self.current_entry() {
            let pattern_count = entry.approval.patterns.len();
            if pattern_count > 0 {
                self.selected_pattern = (self.selected_pattern + 1) % pattern_count;
            }
        }
    }

    pub fn prev_pattern(&mut self) {
        if let Some(entry) = self.current_entry() {
            let pattern_count = entry.approval.patterns.len();
            if pattern_count > 0 {
                self.selected_pattern = if self.selected_pattern == 0 {
                    pattern_count - 1
                } else {
                    self.selected_pattern - 1
                };
            }
        }
    }

    pub fn cycle_scope(&mut self) {
        self.scope = match self.scope {
            Scope::Local => Scope::User,
            Scope::User => Scope::Project,
            Scope::Project => Scope::Local,
        };
    }

    pub fn approve_selected(&mut self) {
        let Some(entry) = self.entries.get(self.selected) else {
            return;
        };

        let pattern = entry
            .approval
            .patterns
            .get(self.selected_pattern)
            .cloned()
            .unwrap_or_else(|| {
                format!(
                    "{}*",
                    entry
                        .approval
                        .command
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                )
            });

        let id = entry.approval.id.clone();

        // Add the rule
        match add_rule(self.scope, &pattern, RuleType::Allow) {
            Ok(_) => {
                self.message = Some(format!(
                    "✓ Added: Bash({}) to {}",
                    pattern,
                    self.scope.as_str()
                ));

                // Remove from pending
                let _ = remove_pending(&id);

                // Remove from our list
                self.entries.remove(self.selected);
                if self.selected >= self.entries.len() && self.selected > 0 {
                    self.selected -= 1;
                }
                self.selected_pattern = 0;
                self.list_state.select(if self.entries.is_empty() {
                    None
                } else {
                    Some(self.selected)
                });
            }
            Err(e) => {
                self.message = Some(format!("Error: {}", e));
            }
        }
    }

    pub fn skip_selected(&mut self) {
        if self.entries.is_empty() {
            return;
        }

        let id = self.entries[self.selected].approval.id.clone();

        // Remove from pending
        let _ = remove_pending(&id);

        // Remove from our list
        self.entries.remove(self.selected);
        if self.selected >= self.entries.len() && self.selected > 0 {
            self.selected -= 1;
        }
        self.selected_pattern = 0;
        self.list_state.select(if self.entries.is_empty() {
            None
        } else {
            Some(self.selected)
        });
        self.message = Some("Skipped".to_string());
    }
}

/// Run the review TUI
pub fn run_review() -> io::Result<()> {
    let mut app = App::new();

    if app.entries.is_empty() {
        eprintln!("No pending approvals to review.");
        return Ok(());
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Run the app with catch_unwind to ensure terminal cleanup on panic
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| run_app(&mut terminal, &mut app)));

    // Always restore terminal, even on panic
    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let _ = terminal.show_cursor();

    // Handle panic or normal result
    match result {
        Ok(io_result) => io_result,
        Err(panic_payload) => {
            // Re-panic after terminal is restored
            std::panic::resume_unwind(panic_payload);
        }
    }
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> io::Result<()>
where
    io::Error: From<B::Error>,
{
    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        if app.entries.is_empty() {
            app.should_quit = true;
        }

        if app.should_quit {
            return Ok(());
        }

        if event::poll(std::time::Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) => {
                    app.message = None;

                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            app.should_quit = true;
                        }
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            app.should_quit = true;
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            app.next_entry();
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            app.prev_entry();
                        }
                        KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                            app.next_pattern();
                        }
                        KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                            app.prev_pattern();
                        }
                        KeyCode::Char('s') => {
                            app.cycle_scope();
                        }
                        KeyCode::Enter | KeyCode::Char('a') => {
                            app.approve_selected();
                        }
                        KeyCode::Char('d') | KeyCode::Delete => {
                            app.skip_selected();
                        }
                        KeyCode::Char('1'..='9') => {
                            if let KeyCode::Char(c) = key.code {
                                let idx = (c as usize) - ('1' as usize);
                                if let Some(entry) = app.current_entry() {
                                    if idx < entry.approval.patterns.len() {
                                        app.selected_pattern = idx;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Event::Resize(_, _) => {
                    // Terminal resized - just redraw on next loop iteration
                    // The draw call above handles the new size automatically
                }
                _ => {}
            }
        }
    }
}
