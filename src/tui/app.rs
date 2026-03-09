//! Application state and event handling for the review TUI.

use crate::models::CommandInfo;
use crate::patterns::suggest_patterns;
use crate::pending::{
    PendingApproval, ProjectInfo, category_weight, derive_projects, read_pending,
    remove_pending_many,
};
use crate::settings_writer::{RuleType, Scope, add_rule, add_rule_to_project};
use crate::tracking::CommandPart;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers, MouseButton,
        MouseEventKind,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend, layout::Rect, widgets::ListState};
use std::collections::HashSet;
use std::io;
use std::panic::AssertUnwindSafe;

use super::ui;

/// Which panel has keyboard focus
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    Sidebar,
    CommandList,
    Detail,
}

/// Which row is focused within the detail panel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailRow {
    Segments,
    Pattern,
    Scope,
}

/// Status message type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Success,
    Error,
    Info,
}

/// Rendered layout areas for mouse hit-testing
#[derive(Debug, Clone, Copy, Default)]
pub struct LayoutAreas {
    pub sidebar: Rect,
    pub commands: Rect,
    pub detail: Rect,
}

/// Application state
pub struct App {
    // Data
    pub entries: Vec<PendingApproval>,
    pub projects: Vec<ProjectInfo>,

    // Sidebar
    /// Index into projects; projects.len() means "All"
    pub project_cursor: usize,

    // Command list
    /// Indices into entries for the currently visible (filtered) commands
    pub visible: Vec<usize>,
    pub command_cursor: usize,
    pub multi_selected: HashSet<usize>,

    // Detail panel
    pub selected_segment: usize,
    pub selected_pattern: usize,
    pub scope: Scope,
    pub detail_row: DetailRow,

    // Scroll state
    pub sidebar_state: ListState,
    pub command_state: ListState,

    // UI state
    pub panel: Panel,
    pub should_quit: bool,
    pub message: Option<(String, MessageKind)>,
    pub layout: LayoutAreas,
}

impl App {
    pub fn new(show_all: bool) -> Self {
        let entries = read_pending(None);
        let projects = derive_projects(&entries);

        // Auto-detect current project
        let project_cursor = if show_all || projects.is_empty() {
            projects.len() // "All" position
        } else {
            detect_current_project(&projects).unwrap_or(projects.len())
        };

        // Default scope: project if viewing a specific project, user if "All"
        let scope = if project_cursor < projects.len() {
            Scope::Project
        } else {
            Scope::User
        };

        let sidebar_state = ListState::default();

        let mut app = Self {
            entries,
            projects,
            project_cursor,
            visible: Vec::new(),
            command_cursor: 0,
            multi_selected: HashSet::new(),
            selected_segment: 0,
            selected_pattern: 0,
            scope,
            detail_row: DetailRow::Pattern,
            sidebar_state,
            command_state: ListState::default(),
            panel: Panel::CommandList,
            should_quit: false,
            message: None,
            layout: LayoutAreas::default(),
        };
        app.sync_sidebar_state();
        app.update_visible();
        app
    }

    /// Recompute visible commands based on selected project
    pub fn update_visible(&mut self) {
        let filter_display = if self.project_cursor < self.projects.len() {
            Some(self.projects[self.project_cursor].display_path.clone())
        } else {
            None
        };

        let mut indices: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                filter_display
                    .as_ref()
                    .is_none_or(|dp| crate::pending::display_project_path(e) == *dp)
            })
            .map(|(i, _)| i)
            .collect();

        // Sort: category weight ascending, then count descending
        indices.sort_by(|&a, &b| {
            let ea = &self.entries[a];
            let eb = &self.entries[b];
            let wa = category_weight(&ea.command);
            let wb = category_weight(&eb.command);
            wa.cmp(&wb).then(eb.count.cmp(&ea.count))
        });

        self.visible = indices;
        self.command_cursor = 0;
        self.command_state.select(if self.visible.is_empty() {
            None
        } else {
            Some(0)
        });
        self.multi_selected.clear();
        self.reset_detail();
    }

    fn reset_detail(&mut self) {
        self.selected_segment = 0;
        self.selected_pattern = 0;
        self.detail_row = if self.current_entry().is_some_and(|e| e.breakdown.len() > 1) {
            DetailRow::Segments
        } else {
            DetailRow::Pattern
        };
    }

    pub fn current_entry(&self) -> Option<&PendingApproval> {
        self.visible
            .get(self.command_cursor)
            .and_then(|&idx| self.entries.get(idx))
    }

    pub fn is_all_view(&self) -> bool {
        self.project_cursor >= self.projects.len()
    }

    pub fn total_pending(&self) -> usize {
        self.entries.len()
    }

    /// Get actionable segment indices for the current entry
    pub fn actionable_segments(&self) -> Vec<usize> {
        self.current_entry()
            .map(|e| {
                e.breakdown
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| p.decision == "ask")
                    .map(|(i, _)| i)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get patterns for the currently selected segment/command
    pub fn current_patterns(&self) -> Vec<String> {
        let Some(entry) = self.current_entry() else {
            return Vec::new();
        };

        if entry.breakdown.len() <= 1 {
            return entry.patterns.clone();
        }

        // Compound: get patterns for selected segment
        let actionable = self.actionable_segments();
        if let Some(&seg_idx) = actionable.get(self.selected_segment) {
            if let Some(part) = entry.breakdown.get(seg_idx) {
                return segment_patterns(part);
            }
        }
        entry.patterns.clone()
    }

    /// Get the reason string for the currently focused segment
    pub fn current_reason(&self) -> Option<String> {
        let entry = self.current_entry()?;
        if entry.breakdown.len() <= 1 {
            return entry
                .breakdown
                .first()
                .filter(|p| !p.reason.is_empty())
                .map(|p| p.reason.clone());
        }
        let actionable = self.actionable_segments();
        actionable.get(self.selected_segment).and_then(|&idx| {
            entry
                .breakdown
                .get(idx)
                .filter(|p| !p.reason.is_empty())
                .map(|p| p.reason.clone())
        })
    }

    /// Get the target file path for display
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
                if let Some(entry) = self.current_entry() {
                    let filename = if self.scope == Scope::Project {
                        "settings.json"
                    } else {
                        "settings.local.json"
                    };
                    let display = crate::pending::display_project_path(entry);
                    format!("{}/.claude/{}", display, filename)
                } else {
                    "(no command selected)".to_string()
                }
            }
        }
    }

    /// Contextual tip for compound commands
    pub fn compound_tip(&self) -> Option<String> {
        let entry = self.current_entry()?;
        if entry.breakdown.len() <= 1 {
            return None;
        }
        let allowed_count = entry
            .breakdown
            .iter()
            .filter(|p| p.decision == "allow")
            .count();
        let ask_count = entry
            .breakdown
            .iter()
            .filter(|p| p.decision == "ask")
            .count();
        if ask_count == 1 && allowed_count > 0 {
            let allowed_names: Vec<_> = entry
                .breakdown
                .iter()
                .filter(|p| p.decision == "allow")
                .map(|p| format!("\"{}\"", p.program))
                .collect();
            Some(format!(
                "Approving this covers the full command since {} already allowed.",
                allowed_names.join(", ")
            ))
        } else if ask_count > 1 {
            Some(format!(
                "This command has {} parts needing approval.",
                ask_count
            ))
        } else {
            None
        }
    }

    // === Navigation ===

    pub fn next_panel(&mut self) {
        self.panel = match self.panel {
            Panel::Sidebar => Panel::CommandList,
            Panel::CommandList => Panel::Detail,
            Panel::Detail => Panel::Sidebar,
        };
    }

    pub fn prev_panel(&mut self) {
        self.panel = match self.panel {
            Panel::Sidebar => Panel::Detail,
            Panel::CommandList => Panel::Sidebar,
            Panel::Detail => Panel::CommandList,
        };
    }

    pub fn nav_down(&mut self) {
        match self.panel {
            Panel::Sidebar => {
                let total = self.projects.len() + 1;
                self.project_cursor = (self.project_cursor + 1) % total;
                self.sync_sidebar_state();
                self.on_project_changed();
            }
            Panel::CommandList => {
                if !self.visible.is_empty() {
                    self.command_cursor = (self.command_cursor + 1) % self.visible.len();
                    self.command_state.select(Some(self.command_cursor));
                    self.reset_detail();
                }
            }
            Panel::Detail => {
                let has_segments = self.current_entry().is_some_and(|e| e.breakdown.len() > 1);
                self.detail_row = match self.detail_row {
                    DetailRow::Segments => DetailRow::Pattern,
                    DetailRow::Pattern => DetailRow::Scope,
                    DetailRow::Scope => {
                        if has_segments {
                            DetailRow::Segments
                        } else {
                            DetailRow::Pattern
                        }
                    }
                };
            }
        }
    }

    pub fn nav_up(&mut self) {
        match self.panel {
            Panel::Sidebar => {
                let total = self.projects.len() + 1;
                self.project_cursor = if self.project_cursor == 0 {
                    total - 1
                } else {
                    self.project_cursor - 1
                };
                self.sync_sidebar_state();
                self.on_project_changed();
            }
            Panel::CommandList => {
                if !self.visible.is_empty() {
                    self.command_cursor = if self.command_cursor == 0 {
                        self.visible.len() - 1
                    } else {
                        self.command_cursor - 1
                    };
                    self.command_state.select(Some(self.command_cursor));
                    self.reset_detail();
                }
            }
            Panel::Detail => {
                let has_segments = self.current_entry().is_some_and(|e| e.breakdown.len() > 1);
                self.detail_row = match self.detail_row {
                    DetailRow::Segments => DetailRow::Scope,
                    DetailRow::Pattern => {
                        if has_segments {
                            DetailRow::Segments
                        } else {
                            DetailRow::Scope
                        }
                    }
                    DetailRow::Scope => DetailRow::Pattern,
                };
            }
        }
    }

    pub fn nav_left(&mut self) {
        if self.panel != Panel::Detail {
            return;
        }
        match self.detail_row {
            DetailRow::Segments => {
                let actionable = self.actionable_segments();
                if !actionable.is_empty() {
                    self.selected_segment = if self.selected_segment == 0 {
                        actionable.len() - 1
                    } else {
                        self.selected_segment - 1
                    };
                    self.selected_pattern = 0;
                }
            }
            DetailRow::Pattern => {
                let count = self.current_patterns().len();
                if count > 0 {
                    self.selected_pattern = if self.selected_pattern == 0 {
                        count - 1
                    } else {
                        self.selected_pattern - 1
                    };
                }
            }
            DetailRow::Scope => {
                self.scope = match self.scope {
                    Scope::User => Scope::Local,
                    Scope::Project => Scope::User,
                    Scope::Local => Scope::Project,
                };
            }
        }
    }

    pub fn nav_right(&mut self) {
        if self.panel != Panel::Detail {
            return;
        }
        match self.detail_row {
            DetailRow::Segments => {
                let actionable = self.actionable_segments();
                if !actionable.is_empty() {
                    self.selected_segment = (self.selected_segment + 1) % actionable.len();
                    self.selected_pattern = 0;
                }
            }
            DetailRow::Pattern => {
                let count = self.current_patterns().len();
                if count > 0 {
                    self.selected_pattern = (self.selected_pattern + 1) % count;
                }
            }
            DetailRow::Scope => {
                self.scope = match self.scope {
                    Scope::User => Scope::Project,
                    Scope::Project => Scope::Local,
                    Scope::Local => Scope::User,
                };
            }
        }
    }

    pub fn toggle_select(&mut self) {
        if self.panel == Panel::CommandList && !self.visible.is_empty() {
            let idx = self.command_cursor;
            if self.multi_selected.contains(&idx) {
                self.multi_selected.remove(&idx);
            } else {
                self.multi_selected.insert(idx);
            }
        }
    }

    fn on_project_changed(&mut self) {
        // Update default scope to match view
        self.scope = if self.is_all_view() {
            Scope::User
        } else {
            Scope::Project
        };
        self.update_visible();
    }

    // === Actions ===

    pub fn approve(&mut self) {
        if self.multi_selected.is_empty() {
            self.approve_single(RuleType::Allow);
        } else {
            self.approve_multi();
        }
    }

    pub fn deny(&mut self) {
        if self.multi_selected.is_empty() {
            self.approve_single(RuleType::Deny);
        }
        // Deny doesn't support multi-select (too dangerous)
    }

    pub fn skip(&mut self) {
        let ids: Vec<String> = if self.multi_selected.is_empty() {
            self.current_entry()
                .map(|e| vec![e.id.clone()])
                .unwrap_or_default()
        } else {
            self.multi_selected
                .iter()
                .filter_map(|&idx| {
                    self.visible
                        .get(idx)
                        .and_then(|&ei| self.entries.get(ei))
                        .map(|e| e.id.clone())
                })
                .collect()
        };

        if ids.is_empty() {
            return;
        }

        let count = ids.len();
        if let Err(e) = remove_pending_many(&ids) {
            self.message = Some((
                format!("Failed to remove from queue: {e}"),
                MessageKind::Error,
            ));
            return;
        }
        self.message = Some((format!("Skipped {count} command(s)"), MessageKind::Info));
        self.multi_selected.clear();
        self.refresh();
    }

    fn approve_single(&mut self, rule_type: RuleType) {
        let Some(entry) = self.current_entry().cloned() else {
            return;
        };

        let patterns = self.current_patterns();
        let pattern = patterns
            .get(self.selected_pattern)
            .cloned()
            .unwrap_or_else(|| {
                format!(
                    "{}:*",
                    entry.command.split_whitespace().next().unwrap_or("")
                )
            });

        if let Err(msg) = self.write_rule(&pattern, &entry, rule_type) {
            self.message = Some((msg, MessageKind::Error));
            return;
        }

        if let Err(e) = remove_pending_many(std::slice::from_ref(&entry.id)) {
            self.message = Some((
                format!("Failed to remove from queue: {e}"),
                MessageKind::Error,
            ));
            return;
        }

        let action = if rule_type == RuleType::Allow {
            "Approved"
        } else {
            "Denied"
        };
        let scope_name = scope_label(self.scope);
        self.message = Some((
            format!("{} {} -> {}", action, pattern, scope_name),
            MessageKind::Success,
        ));
        self.refresh();
    }

    fn approve_multi(&mut self) {
        let entries: Vec<PendingApproval> = self
            .multi_selected
            .iter()
            .filter_map(|&idx| {
                self.visible
                    .get(idx)
                    .and_then(|&ei| self.entries.get(ei))
                    .cloned()
            })
            .collect();

        let mut approved_ids = Vec::new();
        let mut errors = Vec::new();

        for entry in &entries {
            let pattern = entry.patterns.first().cloned().unwrap_or_else(|| {
                format!(
                    "{}:*",
                    entry.command.split_whitespace().next().unwrap_or("")
                )
            });

            match self.write_rule(&pattern, entry, RuleType::Allow) {
                Ok(()) => approved_ids.push(entry.id.clone()),
                Err(msg) => errors.push(msg),
            }
        }

        if !approved_ids.is_empty() {
            if let Err(e) = remove_pending_many(&approved_ids) {
                self.message = Some((
                    format!("Failed to remove from queue: {e}"),
                    MessageKind::Error,
                ));
                self.multi_selected.clear();
                self.refresh();
                return;
            }
        }

        let count = approved_ids.len();
        if errors.is_empty() {
            let scope_name = scope_label(self.scope);
            self.message = Some((
                format!("Approved {} command(s) -> {}", count, scope_name),
                MessageKind::Success,
            ));
        } else {
            self.message = Some((
                format!(
                    "Approved {} but {} failed: {}",
                    count,
                    errors.len(),
                    errors.first().map(|s| s.as_str()).unwrap_or("unknown")
                ),
                MessageKind::Error,
            ));
        }

        self.multi_selected.clear();
        self.refresh();
    }

    fn write_rule(
        &self,
        pattern: &str,
        entry: &PendingApproval,
        rule_type: RuleType,
    ) -> Result<(), String> {
        match self.scope {
            Scope::User => {
                add_rule(Scope::User, pattern, rule_type).map_err(|e| format!("User: {e}"))
            }
            scope @ (Scope::Project | Scope::Local) => {
                let cwd = if entry.cwd.is_empty() {
                    &entry.project_id
                } else {
                    &entry.cwd
                };
                add_rule_to_project(scope, cwd, pattern, rule_type)
                    .map_err(|e| format!("{}: {e}", cwd))
            }
        }
    }

    fn refresh(&mut self) {
        let old_project = if self.project_cursor < self.projects.len() {
            Some(self.projects[self.project_cursor].display_path.clone())
        } else {
            None
        };

        self.entries = read_pending(None);
        self.projects = derive_projects(&self.entries);

        // Try to keep the same project selected
        if let Some(old_dp) = old_project {
            self.project_cursor = self
                .projects
                .iter()
                .position(|p| p.display_path == old_dp)
                .unwrap_or(self.projects.len());
        }

        self.update_visible();
    }

    /// Sync sidebar ListState, accounting for the separator row
    fn sync_sidebar_state(&mut self) {
        let list_index = if self.project_cursor >= self.projects.len() && !self.projects.is_empty()
        {
            self.project_cursor + 1 // skip over separator
        } else {
            self.project_cursor
        };
        self.sidebar_state.select(Some(list_index));
    }

    /// Handle mouse click
    pub fn handle_mouse_click(&mut self, col: u16, row: u16) {
        let la = self.layout;

        if in_rect(la.sidebar, col, row) {
            self.panel = Panel::Sidebar;
            let clicked =
                (row.saturating_sub(la.sidebar.y + 1)) as usize + self.sidebar_state.offset();
            let separator_offset = if self.projects.is_empty() { 0 } else { 1 };
            if clicked < self.projects.len() {
                self.project_cursor = clicked;
                self.sync_sidebar_state();
                self.on_project_changed();
            } else if clicked == self.projects.len() + separator_offset {
                self.project_cursor = self.projects.len();
                self.sync_sidebar_state();
                self.on_project_changed();
            }
            // Else: clicked the separator -- ignore
        } else if in_rect(la.commands, col, row) {
            self.panel = Panel::CommandList;
            let clicked =
                (row.saturating_sub(la.commands.y + 1)) as usize + self.command_state.offset();
            if clicked < self.visible.len() {
                self.command_cursor = clicked;
                self.command_state.select(Some(clicked));
                self.reset_detail();
            }
        } else if in_rect(la.detail, col, row) {
            self.panel = Panel::Detail;
        }
    }
}

// === Helpers ===

fn detect_current_project(projects: &[ProjectInfo]) -> Option<usize> {
    let cwd = std::env::current_dir().ok()?;
    let cwd_str = cwd.to_string_lossy();
    projects
        .iter()
        .position(|p| cwd_str == p.cwd.as_str() || cwd_str.starts_with(&format!("{}/", p.cwd)))
}

fn segment_patterns(part: &CommandPart) -> Vec<String> {
    let cmd = CommandInfo {
        raw: if part.args.is_empty() {
            part.program.clone()
        } else {
            format!("{} {}", part.program, part.args.join(" "))
        },
        program: part.program.clone(),
        args: part.args.clone(),
    };
    suggest_patterns(&cmd)
}

fn scope_label(scope: Scope) -> &'static str {
    match scope {
        Scope::User => "global",
        Scope::Project => "project",
        Scope::Local => "local",
    }
}

fn in_rect(rect: Rect, col: u16, row: u16) -> bool {
    col >= rect.x && col < rect.x + rect.width && row >= rect.y && row < rect.y + rect.height
}

/// Describe a pattern in plain language (action-neutral wording)
pub fn describe_pattern(pattern: &str) -> String {
    if let Some(base) = pattern.strip_suffix(":*") {
        format!("All \"{}\" commands", base)
    } else if let Some(rest) = pattern.strip_suffix('*') {
        format!("\"{}...\" commands", rest.trim_end())
    } else {
        format!("\"{}\" exactly", pattern)
    }
}

/// Extract operators from a raw compound command for display.
/// NOTE: Does not respect quoting -- operators inside strings will be matched.
/// This is display-only; the actual parsing uses tree-sitter and is correct.
pub fn extract_operators(raw: &str) -> Vec<&str> {
    let mut ops = Vec::new();
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'&' && bytes[i + 1] == b'&' {
            ops.push("&&");
            i += 2;
        } else if i + 1 < bytes.len() && bytes[i] == b'|' && bytes[i + 1] == b'|' {
            ops.push("||");
            i += 2;
        } else if bytes[i] == b'|' {
            ops.push("|");
            i += 1;
        } else if bytes[i] == b';' {
            ops.push(";");
            i += 1;
        } else {
            i += 1;
        }
    }
    ops
}

// === Entry point ===

/// Run the review TUI
pub fn run_review(show_all: bool) -> io::Result<()> {
    let mut app = App::new(show_all);

    if app.entries.is_empty() {
        eprintln!("No pending approvals to review.");
        return Ok(());
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let size = terminal.size()?;
    if size.width < 60 || size.height < 20 {
        let _ = disable_raw_mode();
        let _ = execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        eprintln!(
            "Terminal too small ({}x{}). Need at least 60x20.",
            size.width, size.height
        );
        return Ok(());
    }

    let result = std::panic::catch_unwind(AssertUnwindSafe(|| run_app(&mut terminal, &mut app)));

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

        if app.visible.is_empty() && app.entries.is_empty() {
            app.should_quit = true;
        }

        if app.should_quit {
            return Ok(());
        }

        if event::poll(std::time::Duration::from_millis(100))? {
            match event::read()? {
                Event::Key(key) if key.kind == event::KeyEventKind::Press => {
                    app.message = None;

                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            app.should_quit = true;
                        }

                        // Panel switching
                        KeyCode::Tab => {
                            if key.modifiers.contains(KeyModifiers::SHIFT) {
                                app.prev_panel();
                            } else {
                                app.next_panel();
                            }
                        }
                        KeyCode::BackTab => app.prev_panel(),

                        // Navigation
                        KeyCode::Down | KeyCode::Char('j') => app.nav_down(),
                        KeyCode::Up | KeyCode::Char('k') => app.nav_up(),
                        KeyCode::Left | KeyCode::Char('h') => app.nav_left(),
                        KeyCode::Right | KeyCode::Char('l') => app.nav_right(),

                        // Multi-select
                        KeyCode::Char(' ') if app.panel == Panel::CommandList => {
                            app.toggle_select();
                        }

                        // Actions (only from command list or detail panel)
                        KeyCode::Enter
                            if app.panel == Panel::CommandList || app.panel == Panel::Detail =>
                        {
                            app.approve();
                        }
                        KeyCode::Char('d')
                            if app.panel == Panel::CommandList || app.panel == Panel::Detail =>
                        {
                            app.skip();
                        }
                        KeyCode::Char('D')
                            if app.panel == Panel::CommandList || app.panel == Panel::Detail =>
                        {
                            app.deny();
                        }

                        _ => {}
                    }
                }
                Event::Mouse(mouse) => {
                    if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
                        app.handle_mouse_click(mouse.column, mouse.row);
                    }
                }
                _ => {}
            }
        }
    }
}
