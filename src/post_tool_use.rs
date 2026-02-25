//! PostToolUse hook handler.
//!
//! Detects when commands that returned "ask" complete successfully,
//! and adds them to the pending approval queue.

use crate::models::{PostToolUseInput, PostToolUseOutput};
use crate::pending::{PendingApproval, append_pending};
use crate::tracking::{peek_tracked_command, take_tracked_command};

/// Handle a PostToolUse hook event.
///
/// If the tool_use_id was tracked (command returned "ask") and the command
/// succeeded, add it to the pending approval queue.
///
/// Returns `Some(output)` with optional additional context, or `None` to pass through.
pub fn handle_post_tool_use(input: &PostToolUseInput) -> Option<PostToolUseOutput> {
    // Peek at the tracked command without removing it
    // This way if append fails, we don't lose the data
    let tracked = peek_tracked_command(&input.tool_use_id)?;

    // Only add to pending if the command succeeded
    if !input.is_success() {
        // Remove failed commands from tracking (don't queue them)
        let _ = take_tracked_command(&input.tool_use_id);
        return None;
    }

    // Create a pending approval entry
    let approval = PendingApproval::new(
        tracked.command.clone(),
        tracked.suggested_patterns.clone(),
        tracked.breakdown.clone(),
        tracked.project_id.clone(),
        tracked.session_id.clone(),
    );

    // Append to global pending queue
    if let Err(e) = append_pending(approval) {
        eprintln!("Warning: Failed to save pending approval: {e}");
        // Keep in tracking - will be retried or expire naturally
        return None;
    }

    // Only remove from tracking after successful append
    let _ = take_tracked_command(&input.tool_use_id);

    // Optionally include a hint about the pending approval
    // For now, we'll be silent to avoid cluttering Claude's context
    // Could add frequency hints in the future
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
