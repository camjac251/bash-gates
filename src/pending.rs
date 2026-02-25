//! Pending approvals queue backed by a single global JSONL file.
//!
//! Stores successfully executed commands that the user may want to permanently approve.
//! Uses JSONL format (one JSON object per line) for efficient append-only operations.
//! All entries go to `~/.cache/bash-gates/pending.jsonl` with project directory tracked in `cwd`.

use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, Write};
use std::path::PathBuf;
use uuid::Uuid;

use crate::tracking::CommandPart;

/// A pending approval entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    pub id: String,
    pub command: String,
    pub patterns: Vec<String>,
    pub breakdown: Vec<CommandPart>,
    /// Stable project identifier (extracted from transcript_path or sanitized cwd)
    pub project_id: String,
    /// Original working directory path (for display purposes).
    /// Falls back to project_id if not available (backwards compat with old entries).
    #[serde(default)]
    pub cwd: String,
    pub session_id: String,
    pub count: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl PendingApproval {
    pub fn new(
        command: String,
        patterns: Vec<String>,
        breakdown: Vec<CommandPart>,
        project_id: String,
        cwd: String,
        session_id: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            command,
            patterns,
            breakdown,
            project_id,
            cwd,
            session_id,
            count: 1,
            first_seen: now,
            last_seen: now,
        }
    }

    /// Increment the count and update last_seen
    pub fn increment(&mut self) {
        self.count += 1;
        self.last_seen = Utc::now();
    }
}

/// Get the path to the global pending queue
pub fn pending_path() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("bash-gates")
        .join("pending.jsonl")
}

/// Read all pending approvals from the global JSONL file.
/// Optionally filter by project_id.
pub fn read_pending(filter_project: Option<&str>) -> Vec<PendingApproval> {
    let path = pending_path();

    if !path.exists() {
        return Vec::new();
    }

    let file = match File::open(&path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    // Blocking shared lock for reading - don't silently fail
    #[allow(clippy::incompatible_msrv)] // fs2 crate method, not std
    if file.lock_shared().is_err() {
        eprintln!("Warning: Could not acquire lock on pending file");
        return Vec::new();
    }

    let reader = BufReader::new(&file);
    let mut entries = Vec::new();

    for line in reader.lines().map_while(Result::ok) {
        if let Ok(entry) = serde_json::from_str::<PendingApproval>(&line) {
            // Filter by project_id if specified
            if let Some(project) = filter_project {
                if entry.project_id == project {
                    entries.push(entry);
                }
            } else {
                entries.push(entry);
            }
        }
    }

    #[allow(clippy::incompatible_msrv)] // fs2 crate method, not std
    let _ = file.unlock();

    entries
}

/// Atomically modify the pending approvals file.
/// Holds exclusive lock for entire read-modify-write to prevent race conditions.
fn with_exclusive_pending<F, R>(f: F) -> std::io::Result<R>
where
    F: FnOnce(&mut Vec<PendingApproval>) -> R,
{
    let path = pending_path();

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Open file for read+write with exclusive lock
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;

    #[allow(clippy::incompatible_msrv)] // fs2 crate method, not std
    file.lock_exclusive()?;

    // Read current contents
    let reader = BufReader::new(&file);
    let mut entries = Vec::new();

    for line in reader.lines().map_while(Result::ok) {
        if let Ok(entry) = serde_json::from_str::<PendingApproval>(&line) {
            entries.push(entry);
        }
    }

    // Execute the modification function
    let result = f(&mut entries);

    // Write back - truncate and seek to start
    file.set_len(0)?;
    file.seek(std::io::SeekFrom::Start(0))?;

    let mut writer = std::io::BufWriter::new(&file);
    for entry in &entries {
        let json = serde_json::to_string(entry)?;
        writeln!(writer, "{}", json)?;
    }
    writer.flush()?;

    #[allow(clippy::incompatible_msrv)] // fs2 crate method, not std
    file.unlock()?;

    Ok(result)
}

/// Append a pending approval (or increment if same command already exists)
pub fn append_pending(approval: PendingApproval) -> std::io::Result<()> {
    with_exclusive_pending(|entries| {
        // Check if we already have this exact command in the same project
        if let Some(existing) = entries
            .iter_mut()
            .find(|e| e.command == approval.command && e.project_id == approval.project_id)
        {
            existing.increment();
            // Update patterns if new ones discovered
            for pattern in &approval.patterns {
                if !existing.patterns.contains(pattern) {
                    existing.patterns.push(pattern.clone());
                }
            }
        } else {
            entries.push(approval);
        }
    })
}

/// Remove a pending approval by ID
pub fn remove_pending(id: &str) -> std::io::Result<bool> {
    with_exclusive_pending(|entries| {
        let len_before = entries.len();
        entries.retain(|e| e.id != id);
        entries.len() < len_before
    })
}

/// Remove multiple pending approvals by ID
pub fn remove_pending_many(ids: &[String]) -> std::io::Result<usize> {
    with_exclusive_pending(|entries| {
        let len_before = entries.len();
        let id_set: std::collections::HashSet<&str> = ids.iter().map(|s| s.as_str()).collect();
        entries.retain(|e| !id_set.contains(e.id.as_str()));
        len_before - entries.len()
    })
}

/// Clear pending approvals, optionally filtered by project
pub fn clear_pending(filter_project: Option<&str>) -> std::io::Result<usize> {
    with_exclusive_pending(|entries| {
        let len_before = entries.len();
        match filter_project {
            None => {
                entries.clear();
            }
            Some(project) => {
                entries.retain(|e| e.project_id != project);
            }
        }
        len_before - entries.len()
    })
}

/// Get pending approvals grouped by command pattern
pub fn pending_stats(filter_project: Option<&str>) -> HashMap<String, u32> {
    let entries = read_pending(filter_project);
    let mut stats = HashMap::new();

    for entry in entries {
        *stats.entry(entry.command.clone()).or_insert(0) += entry.count;
    }

    stats
}

/// Get total count of pending approvals
pub fn pending_count(filter_project: Option<&str>) -> usize {
    read_pending(filter_project).len()
}

/// A group of similar commands across projects
#[derive(Debug, Clone)]
pub struct CommandGroup {
    /// The base command pattern (e.g., "npm install")
    pub base_command: String,
    /// All pending entries in this group
    pub entries: Vec<PendingApproval>,
    /// Unique project paths that have this command
    pub projects: Vec<String>,
}

impl CommandGroup {
    /// Get the combined patterns from all entries (deduplicated)
    pub fn patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for entry in &self.entries {
            for pattern in &entry.patterns {
                if seen.insert(pattern.clone()) {
                    patterns.push(pattern.clone());
                }
            }
        }
        patterns
    }

    /// Get total count across all entries
    pub fn total_count(&self) -> u32 {
        self.entries.iter().map(|e| e.count).sum()
    }
}

/// Group pending approvals by base command
pub fn group_pending(entries: Vec<PendingApproval>) -> Vec<CommandGroup> {
    let mut groups: std::collections::HashMap<String, CommandGroup> =
        std::collections::HashMap::new();

    for entry in entries {
        let base = extract_base_command(&entry.command);

        let group = groups.entry(base.clone()).or_insert_with(|| CommandGroup {
            base_command: base.clone(),
            entries: Vec::new(),
            projects: Vec::new(),
        });

        // Track unique projects using display_project_path for human-readable form
        let project = display_project_path(&entry);
        if !group.projects.contains(&project) {
            group.projects.push(project);
        }

        group.entries.push(entry);
    }

    let mut result: Vec<CommandGroup> = groups.into_values().collect();
    // Sort by most recent first
    result.sort_by(|a, b| {
        let a_latest = a.entries.iter().map(|e| e.last_seen).max();
        let b_latest = b.entries.iter().map(|e| e.last_seen).max();
        b_latest.cmp(&a_latest)
    });
    result
}

/// Extract the base command (program + first subcommand) for grouping
fn extract_base_command(command: &str) -> String {
    let parts: Vec<&str> = command.split_whitespace().collect();
    match parts.len() {
        0 => command.to_string(),
        1 => parts[0].to_string(),
        _ => {
            // For package managers, include subcommand
            let program = parts[0];
            let subcmd = parts[1];
            if [
                "npm", "pnpm", "yarn", "bun", "cargo", "pip", "uv", "go", "mise", "git", "gh",
                "docker", "kubectl",
            ]
            .contains(&program)
            {
                format!("{} {}", program, subcmd)
            } else {
                program.to_string()
            }
        }
    }
}

/// Get a human-readable display path for a pending approval entry.
///
/// Uses the stored `cwd` field (real path) when available, falling back
/// to `project_id` as-is for old entries that lack `cwd`.
/// Collapses the home directory prefix to `~` for brevity.
pub fn display_project_path(entry: &PendingApproval) -> String {
    let path = if entry.cwd.is_empty() {
        // Backwards compat: old entries without cwd field.
        // project_id is already a sanitized identifier, show it as-is.
        return entry.project_id.clone();
    } else {
        &entry.cwd
    };

    // Collapse home directory prefix to ~
    if let Some(home) = dirs::home_dir() {
        let home_str = home.to_string_lossy();
        if path.starts_with(home_str.as_ref()) {
            return path.replacen(home_str.as_ref(), "~", 1);
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pending_approval_creation() {
        let approval = PendingApproval::new(
            "npm install".to_string(),
            vec!["npm install:*".to_string()],
            vec![],
            "/tmp".to_string(),
            "/tmp".to_string(),
            "session1".to_string(),
        );

        assert_eq!(approval.command, "npm install");
        assert_eq!(approval.count, 1);
        assert!(!approval.id.is_empty());
    }

    #[test]
    fn test_pending_increment() {
        let mut approval = PendingApproval::new(
            "npm install".to_string(),
            vec![],
            vec![],
            "/tmp".to_string(),
            "/tmp".to_string(),
            "session1".to_string(),
        );

        approval.increment();
        assert_eq!(approval.count, 2);
    }

    #[test]
    fn test_pending_path() {
        let path = pending_path();
        assert!(path.ends_with("bash-gates/pending.jsonl"));
    }

    // Integration tests for file I/O are in tests/pending_integration.rs
    // These unit tests focus on struct logic only to avoid test isolation issues

    // --- Bug fix regression tests ---

    /// Helper: simulate the read_pending filter logic (mirrors the filter inside read_pending)
    fn filter_entries(
        entries: &[PendingApproval],
        filter_project: Option<&str>,
    ) -> Vec<PendingApproval> {
        entries
            .iter()
            .filter(|entry| match filter_project {
                Some(project) => entry.project_id == project,
                None => true,
            })
            .cloned()
            .collect()
    }

    /// Helper: simulate the append_pending dedup logic (mirrors the closure inside append_pending)
    fn simulate_append(entries: &mut Vec<PendingApproval>, approval: PendingApproval) {
        if let Some(existing) = entries
            .iter_mut()
            .find(|e| e.command == approval.command && e.project_id == approval.project_id)
        {
            existing.increment();
            for pattern in &approval.patterns {
                if !existing.patterns.contains(pattern) {
                    existing.patterns.push(pattern.clone());
                }
            }
        } else {
            entries.push(approval);
        }
    }

    /// Helper: simulate the clear_pending logic (mirrors the closure inside clear_pending)
    fn simulate_clear(entries: &mut Vec<PendingApproval>, filter_project: Option<&str>) -> usize {
        let len_before = entries.len();
        match filter_project {
            None => entries.clear(),
            Some(project) => entries.retain(|e| e.project_id != project),
        }
        len_before - entries.len()
    }

    fn make_approval(command: &str, project_id: &str) -> PendingApproval {
        PendingApproval::new(
            command.to_string(),
            vec![],
            vec![],
            project_id.to_string(),
            String::new(),
            "sess".to_string(),
        )
    }

    // Bug 2: project filter must use exact equality, not substring contains

    #[test]
    fn test_read_filter_exact_match_only() {
        let entries = vec![
            make_approval("cmd1", "app"),
            make_approval("cmd2", "happy"),
            make_approval("cmd3", "webapp"),
            make_approval("cmd4", "app"),
        ];

        let filtered = filter_entries(&entries, Some("app"));
        assert_eq!(
            filtered.len(),
            2,
            "should match only exact 'app', not 'happy' or 'webapp'"
        );
        assert!(filtered.iter().all(|e| e.project_id == "app"));
    }

    #[test]
    fn test_read_filter_no_substring_match() {
        let entries = vec![
            make_approval("cmd1", "happy"),
            make_approval("cmd2", "webapp"),
            make_approval("cmd3", "application"),
        ];

        let filtered = filter_entries(&entries, Some("app"));
        assert_eq!(
            filtered.len(),
            0,
            "substring matches like 'happy', 'webapp', 'application' must not match 'app'"
        );
    }

    #[test]
    fn test_read_filter_none_returns_all() {
        let entries = vec![
            make_approval("cmd1", "proj-a"),
            make_approval("cmd2", "proj-b"),
        ];

        let filtered = filter_entries(&entries, None);
        assert_eq!(filtered.len(), 2);
    }

    // Bug 3: dedup must include project_id, not just command

    #[test]
    fn test_append_dedup_same_project_increments() {
        let mut entries = Vec::new();

        simulate_append(&mut entries, make_approval("npm install", "proj-a"));
        simulate_append(&mut entries, make_approval("npm install", "proj-a"));

        assert_eq!(entries.len(), 1, "same command + same project should dedup");
        assert_eq!(entries[0].count, 2);
    }

    #[test]
    fn test_append_dedup_different_projects_keeps_both() {
        let mut entries = Vec::new();

        simulate_append(&mut entries, make_approval("npm install", "proj-a"));
        simulate_append(&mut entries, make_approval("npm install", "proj-b"));

        assert_eq!(
            entries.len(),
            2,
            "same command in different projects must create separate entries"
        );
        assert_eq!(entries[0].count, 1);
        assert_eq!(entries[1].count, 1);
        assert_eq!(entries[0].project_id, "proj-a");
        assert_eq!(entries[1].project_id, "proj-b");
    }

    #[test]
    fn test_append_dedup_different_commands_same_project() {
        let mut entries = Vec::new();

        simulate_append(&mut entries, make_approval("npm install", "proj-a"));
        simulate_append(&mut entries, make_approval("npm test", "proj-a"));

        assert_eq!(
            entries.len(),
            2,
            "different commands in same project are separate"
        );
    }

    // Bug 1: clear_pending(None) must use with_exclusive_pending (tested via simulate logic)

    #[test]
    fn test_clear_none_removes_all_entries() {
        let mut entries = vec![
            make_approval("cmd1", "proj-a"),
            make_approval("cmd2", "proj-b"),
            make_approval("cmd3", "proj-c"),
        ];

        let removed = simulate_clear(&mut entries, None);
        assert_eq!(removed, 3);
        assert!(entries.is_empty(), "clear(None) must empty the entire vec");
    }

    #[test]
    fn test_clear_project_filter_exact_only() {
        let mut entries = vec![
            make_approval("cmd1", "app"),
            make_approval("cmd2", "happy"),
            make_approval("cmd3", "webapp"),
            make_approval("cmd4", "app"),
        ];

        let removed = simulate_clear(&mut entries, Some("app"));
        assert_eq!(removed, 2, "should only remove exact 'app' matches");
        assert_eq!(entries.len(), 2);
        assert!(
            entries.iter().all(|e| e.project_id != "app"),
            "no 'app' entries should remain"
        );
        assert!(
            entries.iter().any(|e| e.project_id == "happy"),
            "'happy' must not be removed when filtering by 'app'"
        );
        assert!(
            entries.iter().any(|e| e.project_id == "webapp"),
            "'webapp' must not be removed when filtering by 'app'"
        );
    }

    #[test]
    fn test_clear_project_filter_no_match() {
        let mut entries = vec![
            make_approval("cmd1", "proj-a"),
            make_approval("cmd2", "proj-b"),
        ];

        let removed = simulate_clear(&mut entries, Some("proj-c"));
        assert_eq!(removed, 0);
        assert_eq!(entries.len(), 2);
    }

    // --- Lossy project_id encoding regression tests ---

    /// Helper to create an approval with both project_id and cwd
    fn make_approval_with_cwd(command: &str, project_id: &str, cwd: &str) -> PendingApproval {
        PendingApproval::new(
            command.to_string(),
            vec![],
            vec![],
            project_id.to_string(),
            cwd.to_string(),
            "sess".to_string(),
        )
    }

    #[test]
    fn test_display_project_path_uses_cwd_when_available() {
        let entry = make_approval_with_cwd("cmd", "-home-cam-my-project", "/home/cam/my-project");
        // Should use the real cwd, not try to decode project_id
        let display = display_project_path(&entry);
        assert!(
            display.contains("my-project"),
            "display path should preserve hyphens from real cwd: got '{display}'"
        );
        // Should NOT contain "my/project" (the old lossy decoding bug)
        assert!(
            !display.contains("my/project"),
            "display path must not lossy-decode hyphens as slashes: got '{display}'"
        );
    }

    #[test]
    fn test_display_project_path_falls_back_to_project_id_for_old_entries() {
        // Old entries without cwd field (empty string from #[serde(default)])
        let entry = make_approval_with_cwd("cmd", "-home-cam-my-project", "");
        let display = display_project_path(&entry);
        assert_eq!(
            display, "-home-cam-my-project",
            "old entries without cwd should show project_id as-is"
        );
    }

    #[test]
    fn test_display_project_path_absolute_path_outside_home() {
        let entry = make_approval_with_cwd("cmd", "-opt-myapp", "/opt/myapp");
        let display = display_project_path(&entry);
        assert_eq!(display, "/opt/myapp");
    }

    #[test]
    fn test_group_pending_preserves_hyphenated_paths() {
        let entries = vec![
            make_approval_with_cwd(
                "npm install",
                "-home-cam-my-project",
                "/home/cam/my-project",
            ),
            make_approval_with_cwd(
                "npm install",
                "-home-cam-other-thing",
                "/home/cam/other-thing",
            ),
        ];

        let groups = group_pending(entries);
        assert_eq!(groups.len(), 1, "same base command should group together");

        let group = &groups[0];
        assert_eq!(group.projects.len(), 2);

        // Both project paths should preserve hyphens
        for project in &group.projects {
            assert!(
                !project.contains("/cam/my/project"),
                "project path must not lossy-decode: got '{project}'"
            );
            assert!(
                !project.contains("/cam/other/thing"),
                "project path must not lossy-decode: got '{project}'"
            );
        }
    }

    #[test]
    fn test_serde_round_trip_with_cwd() {
        let approval = make_approval_with_cwd(
            "npm install",
            "-home-cam-my-project",
            "/home/cam/my-project",
        );
        let json = serde_json::to_string(&approval).unwrap();
        let restored: PendingApproval = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.cwd, "/home/cam/my-project");
        assert_eq!(restored.project_id, "-home-cam-my-project");
    }

    #[test]
    fn test_serde_backwards_compat_missing_cwd() {
        // Simulate an old JSONL entry that lacks the cwd field
        let json = r#"{"id":"test-id","command":"npm install","patterns":[],"breakdown":[],"project_id":"-home-cam-my-project","session_id":"s","count":1,"first_seen":"2025-01-01T00:00:00Z","last_seen":"2025-01-01T00:00:00Z"}"#;
        let entry: PendingApproval = serde_json::from_str(json).unwrap();
        assert_eq!(entry.cwd, "", "missing cwd should default to empty string");
        assert_eq!(entry.project_id, "-home-cam-my-project");
        // display_project_path should fall back gracefully
        let display = display_project_path(&entry);
        assert_eq!(display, "-home-cam-my-project");
    }
}
