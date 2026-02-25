//! Application state and event handling for the review TUI.

use crate::pending::{
    CommandGroup, display_project_path, group_pending, read_pending, remove_pending_many,
};
use crate::settings_writer::{RuleType, Scope, add_rule, add_rule_to_project};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend, widgets::ListState};
use std::collections::HashSet;
use std::io;
use std::panic::AssertUnwindSafe;

use super::ui;

/// Focus area in the UI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    CommandList,
    PatternList,
    ScopeSelect,
    ProjectList,
}

/// Application state
pub struct App {
    /// Grouped commands
    pub groups: Vec<CommandGroup>,
    /// Currently selected group index
    pub selected_group: usize,
    /// Currently selected pattern index
    pub selected_pattern: usize,
    /// Current scope selection
    pub scope: Scope,
    /// Selected projects for Project/Local scope (indices into current group's projects)
    pub selected_projects: HashSet<usize>,
    /// Current focus area
    pub focus: Focus,
    /// Should quit
    pub should_quit: bool,
    /// Status message
    pub message: Option<String>,
    /// List state for command list
    pub list_state: ListState,
    /// Cursor position within the project list
    pub project_cursor: usize,
}

impl App {
    pub fn new() -> Self {
        let entries = read_pending(None);
        let groups = group_pending(entries);

        let mut list_state = ListState::default();
        if !groups.is_empty() {
            list_state.select(Some(0));
        }

        // Default: all projects selected
        let selected_projects: HashSet<usize> = if groups.is_empty() {
            HashSet::new()
        } else {
            (0..groups[0].projects.len()).collect()
        };

        Self {
            groups,
            selected_group: 0,
            selected_pattern: 0,
            scope: Scope::User,
            selected_projects,
            focus: Focus::CommandList,
            should_quit: false,
            message: None,
            list_state,
            project_cursor: 0,
        }
    }

    pub fn current_group(&self) -> Option<&CommandGroup> {
        self.groups.get(self.selected_group)
    }

    pub fn total_pending(&self) -> usize {
        self.groups.iter().map(|g| g.entries.len()).sum()
    }

    /// Get the target file path based on current selection
    pub fn target_path(&self) -> String {
        match self.scope {
            Scope::User => {
                let path = Scope::User.path();
                if let Some(home) = dirs::home_dir() {
                    path.to_string_lossy()
                        .replacen(&home.to_string_lossy().to_string(), "~", 1)
                } else {
                    path.to_string_lossy().to_string()
                }
            }
            Scope::Project | Scope::Local => {
                if let Some(group) = self.current_group() {
                    if self.selected_projects.len() == 1 {
                        let idx = *self.selected_projects.iter().next().unwrap();
                        let project = &group.projects[idx];
                        let filename = if self.scope == Scope::Project {
                            "settings.json"
                        } else {
                            "settings.local.json"
                        };
                        format!("{}/.claude/{}", project, filename)
                    } else if self.selected_projects.len() > 1 {
                        format!("{} projects", self.selected_projects.len())
                    } else {
                        "(select a project)".to_string()
                    }
                } else {
                    "(no project)".to_string()
                }
            }
        }
    }

    // Navigation methods
    pub fn next_group(&mut self) {
        if !self.groups.is_empty() {
            self.selected_group = (self.selected_group + 1) % self.groups.len();
            self.selected_pattern = 0;
            self.selected_projects = (0..self.groups[self.selected_group].projects.len()).collect();
            self.project_cursor = 0;
            self.list_state.select(Some(self.selected_group));
        }
    }

    pub fn prev_group(&mut self) {
        if !self.groups.is_empty() {
            self.selected_group = if self.selected_group == 0 {
                self.groups.len() - 1
            } else {
                self.selected_group - 1
            };
            self.selected_pattern = 0;
            self.selected_projects = (0..self.groups[self.selected_group].projects.len()).collect();
            self.project_cursor = 0;
            self.list_state.select(Some(self.selected_group));
        }
    }

    pub fn next_pattern(&mut self) {
        if let Some(group) = self.current_group() {
            let count = group.patterns().len();
            if count > 0 {
                self.selected_pattern = (self.selected_pattern + 1) % count;
            }
        }
    }

    pub fn prev_pattern(&mut self) {
        if let Some(group) = self.current_group() {
            let count = group.patterns().len();
            if count > 0 {
                self.selected_pattern = if self.selected_pattern == 0 {
                    count - 1
                } else {
                    self.selected_pattern - 1
                };
            }
        }
    }

    pub fn cycle_scope(&mut self) {
        self.scope = match self.scope {
            Scope::User => Scope::Project,
            Scope::Project => Scope::Local,
            Scope::Local => Scope::User,
        };
    }

    pub fn toggle_project(&mut self, idx: usize) {
        if self.selected_projects.contains(&idx) {
            self.selected_projects.remove(&idx);
        } else {
            self.selected_projects.insert(idx);
        }
    }

    pub fn select_all_projects(&mut self) {
        if let Some(group) = self.current_group() {
            self.selected_projects = (0..group.projects.len()).collect();
        }
    }

    pub fn next_focus(&mut self) {
        self.focus = match self.focus {
            Focus::CommandList => Focus::PatternList,
            Focus::PatternList => Focus::ScopeSelect,
            Focus::ScopeSelect => {
                if self.scope != Scope::User
                    && self.current_group().map(|g| g.projects.len()).unwrap_or(0) > 0
                {
                    Focus::ProjectList
                } else {
                    Focus::CommandList
                }
            }
            Focus::ProjectList => Focus::CommandList,
        };
    }

    pub fn approve(&mut self) {
        let Some(group) = self.groups.get(self.selected_group) else {
            return;
        };

        let patterns = group.patterns();
        let pattern = patterns
            .get(self.selected_pattern)
            .cloned()
            .unwrap_or_else(|| {
                format!(
                    "{}*",
                    group.base_command.split_whitespace().next().unwrap_or("")
                )
            });

        let mut approved_ids = Vec::new();
        let mut errors = Vec::new();

        match self.scope {
            Scope::User => {
                // Global approval - add to user settings, remove all matching entries
                if let Err(e) = add_rule(Scope::User, &pattern, RuleType::Allow) {
                    errors.push(format!("User settings: {}", e));
                } else {
                    // Remove all entries in this group
                    approved_ids.extend(group.entries.iter().map(|e| e.id.clone()));
                }
            }
            Scope::Project | Scope::Local => {
                // Per-project approval
                for &project_idx in &self.selected_projects {
                    if let Some(project_display) = group.projects.get(project_idx) {
                        // Find the first entry matching this display path to get the
                        // real cwd for filesystem operations.
                        let real_path = group
                            .entries
                            .iter()
                            .find(|e| display_project_path(e) == *project_display)
                            .map(|e| {
                                if e.cwd.is_empty() {
                                    // Backwards compat: old entries without cwd
                                    project_display.clone()
                                } else {
                                    e.cwd.clone()
                                }
                            })
                            .unwrap_or_else(|| project_display.clone());

                        if let Err(e) =
                            add_rule_to_project(self.scope, &real_path, &pattern, RuleType::Allow)
                        {
                            errors.push(format!("{}: {}", project_display, e));
                        } else {
                            // Find and mark entries from this project as approved.
                            // Match by comparing display paths (exact equality).
                            for entry in &group.entries {
                                if display_project_path(entry) == *project_display {
                                    approved_ids.push(entry.id.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Remove approved entries
        if !approved_ids.is_empty() {
            let _ = remove_pending_many(&approved_ids);
        }

        // Update message
        if errors.is_empty() {
            let scope_name = match self.scope {
                Scope::User => "user (global)",
                Scope::Project => "project (shared)",
                Scope::Local => "local (private)",
            };
            self.message = Some(format!("Approved {} -> {}", pattern, scope_name));
        } else {
            self.message = Some(format!("Errors: {}", errors.join(", ")));
        }

        // Refresh groups
        let entries = read_pending(None);
        self.groups = group_pending(entries);

        // Adjust selection if needed
        if self.selected_group >= self.groups.len() {
            self.selected_group = self.groups.len().saturating_sub(1);
        }
        self.selected_pattern = 0;
        self.project_cursor = 0;
        if let Some(group) = self.current_group() {
            self.selected_projects = (0..group.projects.len()).collect();
        } else {
            self.selected_projects.clear();
        }
        self.list_state.select(if self.groups.is_empty() {
            None
        } else {
            Some(self.selected_group)
        });
    }

    pub fn skip(&mut self) {
        let Some(group) = self.groups.get(self.selected_group) else {
            return;
        };

        // Remove all entries in this group
        let ids: Vec<String> = group.entries.iter().map(|e| e.id.clone()).collect();
        let _ = remove_pending_many(&ids);

        self.message = Some("Skipped".to_string());

        // Refresh
        let entries = read_pending(None);
        self.groups = group_pending(entries);

        if self.selected_group >= self.groups.len() {
            self.selected_group = self.groups.len().saturating_sub(1);
        }
        self.selected_pattern = 0;
        self.project_cursor = 0;
        if let Some(group) = self.current_group() {
            self.selected_projects = (0..group.projects.len()).collect();
        } else {
            self.selected_projects.clear();
        }
        self.list_state.select(if self.groups.is_empty() {
            None
        } else {
            Some(self.selected_group)
        });
    }
}

/// Run the review TUI
pub fn run_review() -> io::Result<()> {
    let mut app = App::new();

    if app.groups.is_empty() {
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

    // Always restore terminal
    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    );
    let _ = terminal.show_cursor();

    match result {
        Ok(io_result) => io_result,
        Err(panic_payload) => std::panic::resume_unwind(panic_payload),
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

        if app.groups.is_empty() {
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
                        // Navigation
                        KeyCode::Down | KeyCode::Char('j') => match app.focus {
                            Focus::CommandList => app.next_group(),
                            Focus::PatternList => app.next_pattern(),
                            Focus::ProjectList => {
                                if let Some(group) = app.current_group() {
                                    let count = group.projects.len();
                                    if count > 0 {
                                        app.project_cursor = (app.project_cursor + 1) % count;
                                    }
                                }
                            }
                            _ => {}
                        },
                        KeyCode::Up | KeyCode::Char('k') => match app.focus {
                            Focus::CommandList => app.prev_group(),
                            Focus::PatternList => app.prev_pattern(),
                            Focus::ProjectList => {
                                if let Some(group) = app.current_group() {
                                    let count = group.projects.len();
                                    if count > 0 {
                                        app.project_cursor = if app.project_cursor == 0 {
                                            count - 1
                                        } else {
                                            app.project_cursor - 1
                                        };
                                    }
                                }
                            }
                            _ => {}
                        },
                        // Focus switching
                        KeyCode::Tab => app.next_focus(),
                        // Pattern selection
                        KeyCode::Char('1'..='9') => {
                            if let KeyCode::Char(c) = key.code {
                                let idx = (c as usize) - ('1' as usize);
                                if let Some(group) = app.current_group() {
                                    if idx < group.patterns().len() {
                                        app.selected_pattern = idx;
                                    }
                                }
                            }
                        }
                        // Scope
                        KeyCode::Char('u') => app.scope = Scope::User,
                        KeyCode::Char('p') => app.scope = Scope::Project,
                        KeyCode::Char('l') => app.scope = Scope::Local,
                        KeyCode::Char('s') => app.cycle_scope(),
                        // Project toggle (Space or number)
                        KeyCode::Char(' ') if app.focus == Focus::ProjectList => {
                            let cursor = app.project_cursor;
                            app.toggle_project(cursor);
                        }
                        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            app.select_all_projects();
                        }
                        // Actions
                        KeyCode::Enter => app.approve(),
                        KeyCode::Char('d') | KeyCode::Delete => app.skip(),
                        _ => {}
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
}
