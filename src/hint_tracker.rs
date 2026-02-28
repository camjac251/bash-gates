//! Session-scoped hint dedup tracker.
//!
//! Tracks which hints and approval patterns have been emitted during the current
//! Claude Code session. Each hint fires at most once per session, reducing the
//! context tax from repeated `<system-reminder>` injections.
//!
//! File: `~/.cache/bash-gates/hint-tracker.json`
//! Single-session scope: resets when session_id changes.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// Global tracker -- loaded once per process, mutated in-place.
static TRACKER: OnceLock<Mutex<HintTracker>> = OnceLock::new();

/// Session-scoped hint/approval dedup state.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HintTracker {
    /// Current session ID (resets tracker when session changes)
    pub session_id: String,
    /// Hint keys already emitted (e.g. "cat", "grep", "find")
    #[serde(default)]
    pub hints: HashSet<String>,
    /// Whether the first-ask approval message has been shown this session
    #[serde(default)]
    pub first_ask_shown: bool,
    /// Whether state has changed since load (skip disk write if clean)
    #[serde(skip)]
    dirty: bool,
}

impl HintTracker {
    /// Load tracker from disk, resetting if session_id doesn't match.
    fn load(session_id: &str) -> Self {
        if let Some(tracker) = load_from_disk() {
            if tracker.session_id == session_id {
                return tracker;
            }
        }
        // New session or no file -- start fresh
        HintTracker {
            session_id: session_id.to_string(),
            ..Default::default()
        }
    }

    /// Check if a hint key is new for this session. Records it if so.
    /// Returns `true` if the hint should be emitted (first time).
    pub fn is_hint_new(&mut self, hint_key: &str) -> bool {
        if self.hints.contains(hint_key) {
            return false;
        }
        self.hints.insert(hint_key.to_string());
        self.dirty = true;
        true
    }

    /// Check if this is the first "ask" decision this session.
    /// Returns `true` on first call, `false` thereafter.
    pub fn is_first_ask(&mut self) -> bool {
        if self.first_ask_shown {
            return false;
        }
        self.first_ask_shown = true;
        self.dirty = true;
        true
    }

    /// Save to disk if state changed since load.
    pub fn save_if_dirty(&self) {
        if !self.dirty {
            return;
        }
        let _ = save_to_disk(self);
    }
}

/// Get the cache file path.
fn tracker_path() -> Option<PathBuf> {
    let cache_dir = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .ok()
        .or_else(|| dirs::home_dir().map(|h| h.join(".cache")))?;
    Some(cache_dir.join("bash-gates").join("hint-tracker.json"))
}

/// Load tracker from disk.
fn load_from_disk() -> Option<HintTracker> {
    let path = tracker_path()?;
    let content = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Save tracker to disk.
fn save_to_disk(tracker: &HintTracker) -> Result<(), std::io::Error> {
    let path = tracker_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not determine cache path",
        )
    })?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string(tracker)?;
    fs::write(&path, content)?;
    Ok(())
}

/// Get the global tracker for a session. Initializes on first call.
pub fn get(session_id: &str) -> std::sync::MutexGuard<'static, HintTracker> {
    let mutex = TRACKER.get_or_init(|| Mutex::new(HintTracker::load(session_id)));
    mutex.lock().unwrap()
}

/// Filter hints through the session tracker, saving state to disk.
///
/// Retains only hints that haven't been emitted this session.
/// Saves the tracker to disk if any new hints were recorded.
pub fn filter_hints(session_id: &str, hints: &mut Vec<crate::hints::ModernHint>) {
    if session_id.is_empty() || hints.is_empty() {
        return;
    }
    let mut tracker = get(session_id);
    hints.retain(|h| tracker.is_hint_new(h.legacy_command));
    tracker.save_if_dirty();
}

/// Check if this is the first "ask" decision for the session.
///
/// Returns `true` on first call per session, `false` thereafter.
/// Saves the tracker to disk if state changed.
pub fn is_first_ask(session_id: &str) -> bool {
    if session_id.is_empty() {
        return true; // No session tracking -- always show
    }
    let mut tracker = get(session_id);
    let first = tracker.is_first_ask();
    tracker.save_if_dirty();
    first
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn fresh_tracker(session_id: &str) -> HintTracker {
        HintTracker {
            session_id: session_id.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_hint_first_time_is_new() {
        let mut tracker = fresh_tracker("session-1");
        assert!(tracker.is_hint_new("cat"));
        assert!(tracker.is_hint_new("grep"));
    }

    #[test]
    fn test_hint_second_time_is_not_new() {
        let mut tracker = fresh_tracker("session-1");
        assert!(tracker.is_hint_new("cat"));
        assert!(!tracker.is_hint_new("cat"));
    }

    #[test]
    fn test_first_ask_returns_true_once() {
        let mut tracker = fresh_tracker("session-1");
        assert!(tracker.is_first_ask());
        assert!(!tracker.is_first_ask());
        assert!(!tracker.is_first_ask());
    }

    #[test]
    fn test_session_change_resets() {
        let mut tracker = fresh_tracker("session-1");
        tracker.is_hint_new("cat");
        assert!(!tracker.is_hint_new("cat"));

        // New session resets state
        let mut tracker2 = fresh_tracker("session-2");
        assert!(tracker2.is_hint_new("cat"));
    }

    #[test]
    fn test_dirty_tracking() {
        let mut tracker = fresh_tracker("session-1");
        assert!(!tracker.dirty);

        tracker.is_hint_new("cat");
        assert!(tracker.dirty);
    }

    #[test]
    fn test_not_dirty_on_duplicate() {
        let mut tracker = fresh_tracker("session-1");
        tracker.is_hint_new("cat");
        tracker.dirty = false; // reset

        tracker.is_hint_new("cat"); // already seen
        assert!(!tracker.dirty);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut tracker = fresh_tracker("session-1");
        tracker.is_hint_new("cat");
        tracker.is_hint_new("grep");
        tracker.is_first_ask();

        let json = serde_json::to_string(&tracker).unwrap();
        let loaded: HintTracker = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.session_id, "session-1");
        assert!(loaded.hints.contains("cat"));
        assert!(loaded.hints.contains("grep"));
        assert!(loaded.first_ask_shown);
        assert!(!loaded.dirty); // dirty is skipped in serde
    }

    #[test]
    fn test_save_persists_to_disk() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("hint-tracker.json");

        // Save tracker to disk
        let mut tracker = fresh_tracker("persist-test");
        tracker.is_hint_new("cat");
        tracker.is_hint_new("grep");
        tracker.is_first_ask();
        tracker.dirty = true;

        let content = serde_json::to_string(&tracker).unwrap();
        fs::write(&path, &content).unwrap();

        // Read back and verify
        let loaded_content = fs::read_to_string(&path).unwrap();
        let loaded: HintTracker = serde_json::from_str(&loaded_content).unwrap();
        assert_eq!(loaded.session_id, "persist-test");
        assert!(loaded.hints.contains("cat"));
        assert!(loaded.hints.contains("grep"));
        assert!(loaded.first_ask_shown);
    }

    #[test]
    fn test_load_resets_on_session_mismatch() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("hint-tracker.json");

        // Write a tracker for session-1
        let mut tracker = fresh_tracker("session-1");
        tracker.is_hint_new("cat");
        tracker.is_hint_new("grep");
        tracker.is_first_ask();
        let content = serde_json::to_string(&tracker).unwrap();
        fs::write(&path, &content).unwrap();

        // Load with different session_id -- should start fresh
        let loaded_content = fs::read_to_string(&path).unwrap();
        let loaded: HintTracker = serde_json::from_str(&loaded_content).unwrap();

        // Simulate what HintTracker::load does: check session_id match
        let result = if loaded.session_id == "session-2" {
            loaded
        } else {
            HintTracker {
                session_id: "session-2".to_string(),
                ..Default::default()
            }
        };

        assert_eq!(result.session_id, "session-2");
        assert!(
            result.hints.is_empty(),
            "should be empty after session reset"
        );
        assert!(
            !result.first_ask_shown,
            "should be false after session reset"
        );
    }

    #[test]
    fn test_save_if_dirty_skips_when_clean() {
        let tracker = fresh_tracker("session-1");
        assert!(!tracker.dirty);
        // save_if_dirty should be a no-op (no disk write attempted)
        tracker.save_if_dirty();
        // If it tried to write without a valid path, it would fail silently.
        // The point is it doesn't panic or error.
    }

    #[test]
    fn test_filter_hints_empty_session_id_passes_through() {
        use crate::hints::ModernHint;

        let mut hints = vec![
            ModernHint {
                legacy_command: "cat",
                modern_command: "bat",
                hint: "Use bat".to_string(),
            },
            ModernHint {
                legacy_command: "grep",
                modern_command: "rg",
                hint: "Use rg".to_string(),
            },
        ];

        // Empty session_id should not filter anything
        filter_hints("", &mut hints);
        assert_eq!(
            hints.len(),
            2,
            "empty session_id should pass all hints through"
        );
    }

    #[test]
    fn test_is_first_ask_empty_session_always_true() {
        // Empty session_id means no tracking -- always show
        assert!(is_first_ask(""));
        assert!(is_first_ask(""));
    }
}
