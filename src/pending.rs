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
        session_id: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            command,
            patterns,
            breakdown,
            project_id,
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
                if entry.project_id == project || entry.project_id.contains(project) {
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
        // Check if we already have this exact command
        if let Some(existing) = entries.iter_mut().find(|e| e.command == approval.command) {
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
    match filter_project {
        None => {
            // Clear entire file
            let path = pending_path();
            let count = read_pending(None).len();
            if path.exists() {
                fs::remove_file(&path)?;
            }
            Ok(count)
        }
        Some(project) => {
            // Remove only entries matching project_id
            with_exclusive_pending(|entries| {
                let len_before = entries.len();
                entries.retain(|e| e.project_id != project && !e.project_id.contains(project));
                len_before - entries.len()
            })
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pending_approval_creation() {
        let approval = PendingApproval::new(
            "npm install".to_string(),
            vec!["npm install*".to_string()],
            vec![],
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
}
