//! Tracking module for PreToolUse→PostToolUse correlation.
//!
//! Tracks commands that return "ask" so PostToolUse can detect when they
//! complete successfully and add them to the pending approval queue.

use chrono::{DateTime, Duration, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::PathBuf;

use crate::models::Decision;

/// Default TTL for tracked commands (15 minutes)
/// Long enough to survive short breaks while still cleaning up stale entries.
const DEFAULT_TTL_SECS: i64 = 900;

/// Information about a command part (for breakdown display)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandPart {
    pub program: String,
    pub args: Vec<String>,
    pub decision: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expansion: Option<Box<CommandPart>>,
}

impl CommandPart {
    pub fn new(program: &str, args: &[String], decision: Decision, reason: &str) -> Self {
        Self {
            program: program.to_string(),
            args: args.to_vec(),
            decision: match decision {
                Decision::Allow => "allow".to_string(),
                Decision::Ask => "ask".to_string(),
                Decision::Block => "block".to_string(),
                Decision::Skip => "skip".to_string(),
            },
            reason: reason.to_string(),
            expansion: None,
        }
    }

    pub fn with_expansion(mut self, expansion: CommandPart) -> Self {
        self.expansion = Some(Box::new(expansion));
        self
    }
}

/// A tracked command awaiting PostToolUse confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedCommand {
    pub command: String,
    pub suggested_patterns: Vec<String>,
    pub breakdown: Vec<CommandPart>,
    /// Stable project identifier (from transcript_path or sanitized cwd)
    pub project_id: String,
    pub session_id: String,
    pub timestamp: DateTime<Utc>,
    pub expires: DateTime<Utc>,
}

impl TrackedCommand {
    pub fn new(
        command: String,
        suggested_patterns: Vec<String>,
        breakdown: Vec<CommandPart>,
        project_id: String,
        session_id: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            command,
            suggested_patterns,
            breakdown,
            project_id,
            session_id,
            timestamp: now,
            expires: now + Duration::seconds(DEFAULT_TTL_SECS),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires
    }
}

/// Tracking store backed by JSON file
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TrackingStore {
    #[serde(flatten)]
    pub entries: HashMap<String, TrackedCommand>,
}

impl TrackingStore {
    /// Get the path to the tracking file
    pub fn path() -> PathBuf {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("bash-gates")
            .join("tracking.json")
    }

    /// Execute a function with exclusive lock on the tracking file.
    /// Holds the lock for the entire read-modify-write operation to prevent race conditions.
    pub fn with_exclusive_lock<F, R>(f: F) -> std::io::Result<R>
    where
        F: FnOnce(&mut TrackingStore) -> R,
    {
        let path = Self::path();

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
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        // Parse (or default if empty/invalid)
        let mut store: TrackingStore = if contents.is_empty() {
            TrackingStore::default()
        } else {
            serde_json::from_str(&contents).unwrap_or_default()
        };

        // Clean expired entries
        store.clean_expired();

        // Execute the modification function
        let result = f(&mut store);

        // Write back - truncate and seek to start
        file.set_len(0)?;
        file.seek(std::io::SeekFrom::Start(0))?;

        let json = serde_json::to_string_pretty(&store)?;
        file.write_all(json.as_bytes())?;
        file.flush()?;

        #[allow(clippy::incompatible_msrv)] // fs2 crate method, not std
        file.unlock()?;

        Ok(result)
    }

    /// Track a command by its tool_use_id
    pub fn track(&mut self, tool_use_id: &str, tracked: TrackedCommand) {
        self.entries.insert(tool_use_id.to_string(), tracked);
    }

    /// Get and remove a tracked command by tool_use_id
    pub fn take(&mut self, tool_use_id: &str) -> Option<TrackedCommand> {
        self.entries.remove(tool_use_id)
    }

    /// Get a tracked command without removing it (for peek-before-remove pattern)
    pub fn get(&self, tool_use_id: &str) -> Option<&TrackedCommand> {
        self.entries.get(tool_use_id)
    }

    /// Check if a tool_use_id is being tracked
    #[allow(dead_code)]
    pub fn contains(&self, tool_use_id: &str) -> bool {
        self.entries.contains_key(tool_use_id)
    }

    /// Clean expired entries
    pub fn clean_expired(&mut self) {
        self.entries.retain(|_, v| !v.is_expired());
    }
}

/// Track a command that returned "ask" for later PostToolUse correlation
pub fn track_ask_command(
    tool_use_id: &str,
    command: &str,
    suggested_patterns: Vec<String>,
    breakdown: Vec<CommandPart>,
    project_id: &str,
    session_id: &str,
) {
    let tracked = TrackedCommand::new(
        command.to_string(),
        suggested_patterns,
        breakdown,
        project_id.to_string(),
        session_id.to_string(),
    );

    let tool_use_id = tool_use_id.to_string();
    if let Err(e) = TrackingStore::with_exclusive_lock(|store| {
        store.track(&tool_use_id, tracked);
    }) {
        eprintln!("Warning: Failed to save tracking file: {e}");
    }
}

/// Get a tracked command without removing it (called from PostToolUse to peek before commit)
pub fn peek_tracked_command(tool_use_id: &str) -> Option<TrackedCommand> {
    let tool_use_id = tool_use_id.to_string();
    match TrackingStore::with_exclusive_lock(|store| store.get(&tool_use_id).cloned()) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Warning: Failed to access tracking file: {e}");
            None
        }
    }
}

/// Get and remove a tracked command (called from PostToolUse after successful append)
pub fn take_tracked_command(tool_use_id: &str) -> Option<TrackedCommand> {
    let tool_use_id = tool_use_id.to_string();
    match TrackingStore::with_exclusive_lock(|store| store.take(&tool_use_id)) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Warning: Failed to access tracking file: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tempfile::TempDir;

    fn with_temp_cache<F>(test: F)
    where
        F: FnOnce(),
    {
        let temp_dir = TempDir::new().unwrap();
        // SAFETY: Test runs single-threaded and doesn't depend on HOME after this
        unsafe { env::set_var("HOME", temp_dir.path()) };
        test();
    }

    #[test]
    fn test_tracked_command_expiry() {
        let cmd = TrackedCommand::new(
            "npm install".to_string(),
            vec!["npm install:*".to_string()],
            vec![],
            "/tmp".to_string(),
            "session1".to_string(),
        );

        assert!(!cmd.is_expired());
    }

    #[test]
    fn test_tracking_store_operations() {
        with_temp_cache(|| {
            let mut store = TrackingStore::default();

            let cmd = TrackedCommand::new(
                "npm install".to_string(),
                vec!["npm install:*".to_string()],
                vec![],
                "/tmp".to_string(),
                "session1".to_string(),
            );

            store.track("toolu_123", cmd);
            assert!(store.contains("toolu_123"));

            let taken = store.take("toolu_123");
            assert!(taken.is_some());
            assert!(!store.contains("toolu_123"));
        });
    }

    #[test]
    fn test_command_part_creation() {
        let part = CommandPart::new(
            "npm",
            &["install".to_string()],
            Decision::Ask,
            "Installing packages",
        );

        assert_eq!(part.program, "npm");
        assert_eq!(part.decision, "ask");
    }
}
