//! PermissionRequest hook handler.
//!
//! This module handles the PermissionRequest hook, which runs when Claude Code's
//! internal permission checks decide to ask the user. This is particularly important
//! for subagents, where PreToolUse's `allow` decision is ignored.
//!
//! The PermissionRequest hook can:
//! - Approve commands that our gates already deem safe
//! - Deny commands that should be blocked
//! - Pass through to show the normal permission prompt
//!
//! Key insight: PermissionRequest's `allow` IS respected for subagents, unlike PreToolUse.

use crate::models::{Decision, PermissionRequestInput, PermissionRequestOutput};
use crate::router::check_command_result;

/// Reasons that indicate a path-based permission check (safe to override if command is safe)
const PATH_BASED_REASONS: &[&str] = &[
    "Path is outside allowed working directories",
    "outside cwd",
    "outside allowed",
    "path outside",
    "working director",
];

/// Check if the decision reason indicates a path-based permission check
fn is_path_based_reason(reason: &Option<String>) -> bool {
    match reason {
        Some(r) => {
            let lower = r.to_lowercase();
            PATH_BASED_REASONS
                .iter()
                .any(|pattern| lower.contains(&pattern.to_lowercase()))
        }
        None => false,
    }
}

/// Handle a PermissionRequest hook.
///
/// Strategy:
/// 1. If not a Bash tool, pass through (return None)
/// 2. Re-check the command with our gates
/// 3. If our gates say "allow" AND the reason is path-based, approve it
/// 4. If our gates say "deny", deny it
/// 5. Otherwise, pass through (return None to let normal prompt show)
pub fn handle_permission_request(
    input: &PermissionRequestInput,
) -> Option<PermissionRequestOutput> {
    // Only handle Bash tools
    if input.tool_name != "Bash" {
        return None;
    }

    let command = input.get_command();
    if command.is_empty() {
        return None;
    }

    // Re-check the command with our gates
    let gate_result = check_command_result(&command);

    match gate_result.decision {
        Decision::Allow => {
            // Our gates say it's safe. Check if this is a path-based restriction.
            if is_path_based_reason(&input.decision_reason) {
                // Path-based restriction on a safe command - approve it
                // Optionally add the blocked path to session permissions
                if let Some(ref blocked_path) = input.blocked_path {
                    // Add the parent directory to session permissions
                    let dir = std::path::Path::new(blocked_path)
                        .parent()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| blocked_path.clone());
                    return Some(PermissionRequestOutput::allow_with_directories(vec![dir]));
                }
                return Some(PermissionRequestOutput::allow());
            }

            // Non-path reason but command is safe - still approve
            // This handles cases where internal checks are overly cautious
            Some(PermissionRequestOutput::allow())
        }
        Decision::Block => {
            // Our gates say it's dangerous - deny it
            let reason = gate_result
                .reason
                .unwrap_or_else(|| "Blocked by bash-gates".to_string());
            Some(PermissionRequestOutput::deny(&reason))
        }
        Decision::Ask => {
            // Our gates want to ask - let the normal prompt show
            // This respects our gate's judgment that user approval is needed
            None
        }
        Decision::Skip => {
            // Unknown command - let the normal prompt show
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ToolInputVariant;

    fn make_input(command: &str, decision_reason: Option<&str>) -> PermissionRequestInput {
        PermissionRequestInput {
            hook_event_name: "PermissionRequest".to_string(),
            tool_name: "Bash".to_string(),
            tool_input: ToolInputVariant::Map({
                let mut map = serde_json::Map::new();
                map.insert(
                    "command".to_string(),
                    serde_json::Value::String(command.to_string()),
                );
                map
            }),
            decision_reason: decision_reason.map(String::from),
            blocked_path: Some("/outside/path".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn test_safe_command_with_path_reason_approves() {
        let input = make_input(
            "rg pattern /outside/path",
            Some("Path is outside allowed working directories"),
        );
        let result = handle_permission_request(&input);
        assert!(
            result.is_some(),
            "Should approve safe command with path reason"
        );
    }

    #[test]
    fn test_safe_command_with_other_reason_approves() {
        let input = make_input("git status", Some("Some other reason"));
        let result = handle_permission_request(&input);
        assert!(result.is_some(), "Should approve safe command");
    }

    #[test]
    fn test_dangerous_command_denies() {
        let input = make_input(
            "rm -rf /",
            Some("Path is outside allowed working directories"),
        );
        let result = handle_permission_request(&input);
        assert!(result.is_some(), "Should return a result");
        // The result should be a deny
        let json = serde_json::to_string(&result.unwrap()).unwrap();
        assert!(json.contains("deny"), "Should deny dangerous command");
    }

    #[test]
    fn test_ask_command_passes_through() {
        let input = make_input(
            "npm install",
            Some("Path is outside allowed working directories"),
        );
        let result = handle_permission_request(&input);
        // npm install returns Ask from our gates, so we pass through
        assert!(result.is_none(), "Should pass through for ask commands");
    }

    #[test]
    fn test_non_bash_passes_through() {
        let mut input = make_input("anything", None);
        input.tool_name = "Write".to_string();
        let result = handle_permission_request(&input);
        assert!(result.is_none(), "Should pass through for non-Bash tools");
    }

    #[test]
    fn test_is_path_based_reason() {
        assert!(is_path_based_reason(&Some(
            "Path is outside allowed working directories".to_string()
        )));
        assert!(is_path_based_reason(&Some("path outside cwd".to_string())));
        assert!(is_path_based_reason(&Some(
            "File is outside allowed working directory".to_string()
        )));
        assert!(!is_path_based_reason(&Some(
            "Permission denied by user".to_string()
        )));
        assert!(!is_path_based_reason(&None));
    }
}
