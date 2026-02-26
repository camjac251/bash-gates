//! Bash Gates CLI permission gate.
//!
//! Fully declarative - add commands to rules/bash_gates.toml.

use crate::generated::rules::check_bash_gates_gate;
use crate::models::{CommandInfo, GateResult};

/// Check bash-gates CLI commands.
pub fn check_bash_gates(cmd: &CommandInfo) -> GateResult {
    check_bash_gates_gate(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;

    // === Read-only commands (allow) ===

    #[test]
    fn test_pending_list_allows() {
        let result = check_bash_gates(&cmd("bash-gates", &["pending", "list"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_pending_list_with_flags_allows() {
        let result = check_bash_gates(&cmd("bash-gates", &["pending", "list", "--project"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_pending_count_allows() {
        let result = check_bash_gates(&cmd("bash-gates", &["pending", "count"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_rules_list_allows() {
        let result = check_bash_gates(&cmd("bash-gates", &["rules", "list"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_hooks_status_allows() {
        let result = check_bash_gates(&cmd("bash-gates", &["hooks", "status"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_help_flag_allows() {
        let result = check_bash_gates(&cmd("bash-gates", &["--help"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_version_flag_allows() {
        let result = check_bash_gates(&cmd("bash-gates", &["--version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_tools_status_allows() {
        let result = check_bash_gates(&cmd("bash-gates", &["--tools-status"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_export_toml_allows() {
        let result = check_bash_gates(&cmd("bash-gates", &["--export-toml"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === Write commands (ask) ===

    #[test]
    fn test_approve_asks() {
        let result = check_bash_gates(&cmd("bash-gates", &["approve", "npm:*", "-s", "local"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("permission rule"));
    }

    #[test]
    fn test_rules_remove_asks() {
        let result = check_bash_gates(&cmd("bash-gates", &["rules", "remove", "npm:*"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Removing"));
    }

    #[test]
    fn test_pending_clear_asks() {
        let result = check_bash_gates(&cmd("bash-gates", &["pending", "clear"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Clearing"));
    }

    #[test]
    fn test_hooks_add_asks() {
        let result = check_bash_gates(&cmd("bash-gates", &["hooks", "add", "-s", "user"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Installing"));
    }

    #[test]
    fn test_review_asks() {
        let result = check_bash_gates(&cmd("bash-gates", &["review"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("TUI"));
    }

    #[test]
    fn test_refresh_tools_asks() {
        let result = check_bash_gates(&cmd("bash-gates", &["--refresh-tools"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Refreshing"));
    }

    // === Unknown commands (ask) ===

    #[test]
    fn test_unknown_subcommand_asks() {
        let result = check_bash_gates(&cmd("bash-gates", &["something-new"]));
        assert_eq!(result.decision, Decision::Ask);
    }
}
