//! PostToolUse hook handler.
//!
//! Detects when commands that returned "ask" complete successfully,
//! and adds them to the pending approval queue.

use crate::models::{PostToolUseInput, PostToolUseOutput};
use crate::pending::{PendingApproval, append_pending};
use crate::tracking::take_tracked_command;

/// Handle a PostToolUse hook event.
///
/// If the tool_use_id was tracked (command returned "ask") and the command
/// succeeded, add it to the pending approval queue.
///
/// Returns `Some(output)` with optional additional context, or `None` to pass through.
pub fn handle_post_tool_use(input: &PostToolUseInput) -> Option<PostToolUseOutput> {
    // Atomically remove-and-return the tracked command in a single lock scope.
    // This avoids the TOCTOU race of peek-then-take (two separate lock acquisitions).
    let tracked = take_tracked_command(&input.tool_use_id)?;

    // Only add to pending if the command succeeded
    if !input.is_success() {
        // Already removed from tracking above — nothing more to do
        return None;
    }

    // Create a pending approval entry
    let approval = PendingApproval::new(
        tracked.command,
        tracked.suggested_patterns,
        tracked.breakdown,
        tracked.project_id,
        tracked.cwd,
        tracked.session_id,
    );

    // Append to global pending queue.
    // If this fails, the entry is already removed from tracking — acceptable
    // since it would have expired via TTL anyway.
    if let Err(e) = append_pending(approval) {
        eprintln!("Warning: Failed to save pending approval: {e}");
    }

    // Silent — avoid cluttering Claude's context
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_is_success_with_exit_code_0() {
        let input = PostToolUseInput {
            tool_response: Some(json!({"exit_code": 0})),
            ..Default::default()
        };
        assert!(input.is_success());
    }

    #[test]
    fn test_is_success_with_exit_code_1() {
        let input = PostToolUseInput {
            tool_response: Some(json!({"exit_code": 1})),
            ..Default::default()
        };
        assert!(!input.is_success());
    }

    #[test]
    fn test_is_success_with_no_response() {
        // PostToolUse only fires for successful calls, so missing
        // tool_response should default to success
        let input = PostToolUseInput {
            tool_response: None,
            ..Default::default()
        };
        assert!(input.is_success());
    }

    #[test]
    fn test_is_success_with_string_response() {
        // Bash tool_response may be a plain string (stdout), not a JSON object
        let input = PostToolUseInput {
            tool_response: Some(json!("some command output")),
            ..Default::default()
        };
        assert!(input.is_success());
    }

    #[test]
    fn test_handle_untracked_command_returns_none() {
        let input = PostToolUseInput {
            tool_use_id: "untracked_id".to_string(),
            tool_response: Some(json!({"exit_code": 0})),
            ..Default::default()
        };

        // Should return None since this ID wasn't tracked
        assert!(handle_post_tool_use(&input).is_none());
    }
}
