//! Beads issue tracker permission gate.
//!
//! Fully declarative - add commands to rules/beads.toml.

use crate::generated::rules::check_beads_gate;
use crate::models::{CommandInfo, GateResult};

/// Check beads issue tracker commands.
pub fn check_beads(cmd: &CommandInfo) -> GateResult {
    check_beads_gate(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;

    // === Read-only commands (allow) ===

    #[test]
    fn test_bd_list_allows() {
        let result = check_beads(&cmd("bd", &["list"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bd_list_with_flags_allows() {
        let result = check_beads(&cmd("bd", &["list", "--status", "open", "--json"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bd_show_allows() {
        let result = check_beads(&cmd("bd", &["show", "bd-42"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bd_ready_allows() {
        let result = check_beads(&cmd("bd", &["ready"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bd_blocked_allows() {
        let result = check_beads(&cmd("bd", &["blocked"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bd_info_allows() {
        let result = check_beads(&cmd("bd", &["info"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bd_version_allows() {
        let result = check_beads(&cmd("bd", &["version"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bd_doctor_allows() {
        let result = check_beads(&cmd("bd", &["doctor"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bd_stats_allows() {
        let result = check_beads(&cmd("bd", &["stats"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bd_prime_allows() {
        let result = check_beads(&cmd("bd", &["prime"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bd_dep_tree_allows() {
        let result = check_beads(&cmd("bd", &["dep", "tree", "bd-42"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bd_dep_cycles_allows() {
        let result = check_beads(&cmd("bd", &["dep", "cycles"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bd_duplicates_allows() {
        let result = check_beads(&cmd("bd", &["duplicates"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bd_cleanup_dry_run_allows() {
        let result = check_beads(&cmd("bd", &["cleanup", "--dry-run"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === Write commands (ask) ===

    #[test]
    fn test_bd_create_asks() {
        let result = check_beads(&cmd("bd", &["create", "New issue", "-t", "task"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Creating"));
    }

    #[test]
    fn test_bd_update_asks() {
        let result = check_beads(&cmd("bd", &["update", "bd-42", "--status", "in_progress"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Updating"));
    }

    #[test]
    fn test_bd_close_asks() {
        let result = check_beads(&cmd("bd", &["close", "bd-42"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Closing"));
    }

    #[test]
    fn test_bd_delete_asks() {
        let result = check_beads(&cmd("bd", &["delete", "bd-42", "--force"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Deleting"));
    }

    #[test]
    fn test_bd_sync_asks() {
        let result = check_beads(&cmd("bd", &["sync"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Syncing"));
    }

    #[test]
    fn test_bd_init_asks() {
        let result = check_beads(&cmd("bd", &["init"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Initializing"));
    }

    #[test]
    fn test_bd_dep_add_asks() {
        let result = check_beads(&cmd("bd", &["dep", "add", "bd-42", "bd-43"]));
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_ref().unwrap();
        assert!(reason.contains("dependency") || reason.contains("dependencies"));
    }

    #[test]
    fn test_bd_duplicates_auto_merge_asks() {
        let result = check_beads(&cmd("bd", &["duplicates", "--auto-merge"]));
        assert_eq!(result.decision, Decision::Ask);
        let reason = result.reason.as_ref().unwrap();
        assert!(reason.contains("merging") || reason.contains("duplicates"));
    }

    #[test]
    fn test_bd_cleanup_asks() {
        let result = check_beads(&cmd("bd", &["cleanup", "--force"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Cleaning"));
    }

    #[test]
    fn test_bd_compact_asks() {
        let result = check_beads(&cmd("bd", &["compact"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Compacting"));
    }

    #[test]
    fn test_bd_export_asks() {
        let result = check_beads(&cmd("bd", &["export"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Exporting"));
    }

    #[test]
    fn test_bd_import_asks() {
        let result = check_beads(&cmd("bd", &["import", "-i", "issues.jsonl"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Importing"));
    }

    // === Beads alias ===

    #[test]
    fn test_beads_list_allows() {
        let result = check_beads(&cmd("beads", &["list"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_beads_create_asks() {
        let result = check_beads(&cmd("beads", &["create", "Issue"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Unknown commands (ask due to unknown_action) ===

    #[test]
    fn test_bd_unknown_asks() {
        let result = check_beads(&cmd("bd", &["unknowncommand"]));
        assert_eq!(result.decision, Decision::Ask);
    }
}
