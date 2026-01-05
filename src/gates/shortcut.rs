//! Shortcut.com CLI permission gate.
//!
//! Handles the community `short` CLI for Shortcut.com project management.
//! https://github.com/shortcut-cli/shortcut-cli

use crate::generated::rules::check_short_declarative;
use crate::models::{CommandInfo, Decision, GateResult};

/// Normalize shortcut CLI aliases to canonical subcommand names.
fn normalize_alias(subcmd: &str) -> &str {
    match subcmd {
        "s" => "search",
        "st" => "story",
        "c" => "create",
        "m" => "members",
        "wf" => "workflows",
        "e" => "epics",
        "p" => "projects",
        "w" => "workspace",
        other => other,
    }
}

pub fn check_shortcut(cmd: &CommandInfo) -> GateResult {
    // Only handle `short` command
    if cmd.program != "short" {
        return GateResult::skip();
    }

    // Normalize aliases before checking rules
    let normalized_cmd = if let Some(first_arg) = cmd.args.first() {
        let canonical = normalize_alias(first_arg);
        if canonical != first_arg {
            let mut new_args = cmd.args.clone();
            new_args[0] = canonical.to_string();
            CommandInfo {
                raw: cmd.raw.clone(),
                program: cmd.program.clone(),
                args: new_args,
            }
        } else {
            cmd.clone()
        }
    } else {
        cmd.clone()
    };

    // First try custom handler for `api` subcommand
    let api_result = check_short_api(&normalized_cmd);
    if api_result.decision != Decision::Skip {
        return api_result;
    }

    // Fall back to declarative rules
    check_short_declarative(&normalized_cmd)
        .unwrap_or_else(|| GateResult::ask("Unknown shortcut command"))
}

/// Custom handler for `short api` subcommand.
/// GET requests are allowed, POST/PUT/PATCH/DELETE require approval.
pub fn check_short_api(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Only handle `api` subcommand
    if args.first().is_none_or(|a| a != "api") {
        return GateResult::skip();
    }

    // Find the HTTP method: look for -X or --method flag followed by method
    let method = args
        .windows(2)
        .find(|w| w[0] == "-X" || w[0] == "--method")
        .map(|w| w[1].to_uppercase())
        .unwrap_or_else(|| "GET".to_string()); // Default is GET

    match method.as_str() {
        "GET" | "HEAD" | "OPTIONS" => GateResult::allow_with_reason("Reading from API"),
        "POST" | "PUT" | "PATCH" | "DELETE" => GateResult::ask("Making write API request"),
        _ => GateResult::ask(format!("Unknown HTTP method: {}", method)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;

    // ========================================================================
    // SEARCH / FIND - Read-only
    // ========================================================================

    #[test]
    fn test_search_allows() {
        let result = check_shortcut(&cmd("short", &["search"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_search_with_options_allows() {
        let result = check_shortcut(&cmd(
            "short",
            &["search", "-o", "mike", "-s", "In Progress", "-t", "bug"],
        ));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_find_allows() {
        let result = check_shortcut(&cmd("short", &["find", "owner:mike"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_search_save_asks() {
        let result = check_shortcut(&cmd("short", &["search", "-o", "me", "-S", "mywork"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Saving"));
    }

    // ========================================================================
    // STORY - View (allow) vs Update (ask)
    // ========================================================================

    #[test]
    fn test_story_view_allows() {
        let result = check_shortcut(&cmd("short", &["story", "12345"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_story_with_format_allows() {
        let result = check_shortcut(&cmd("short", &["story", "12345", "-f", "%t"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_story_open_allows() {
        let result = check_shortcut(&cmd("short", &["story", "12345", "-O"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_story_comment_asks() {
        let result = check_shortcut(&cmd("short", &["story", "12345", "-c", "Great work!"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("comment"));
    }

    #[test]
    fn test_story_update_state_asks() {
        let result = check_shortcut(&cmd("short", &["story", "12345", "-s", "Done"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("state"));
    }

    #[test]
    fn test_story_update_title_asks() {
        let result = check_shortcut(&cmd("short", &["story", "12345", "-t", "New Title"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("title"));
    }

    #[test]
    fn test_story_update_owners_asks() {
        let result = check_shortcut(&cmd("short", &["story", "12345", "-o", "mike,jane"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("owners"));
    }

    #[test]
    fn test_story_move_asks() {
        let result = check_shortcut(&cmd("short", &["story", "12345", "--move-up", "2"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("position"));
    }

    #[test]
    fn test_story_task_asks() {
        let result = check_shortcut(&cmd("short", &["story", "12345", "--task", "New task"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("task"));
    }

    #[test]
    fn test_story_archive_asks() {
        let result = check_shortcut(&cmd("short", &["story", "12345", "-a"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("rchiv"));
    }

    #[test]
    fn test_story_git_branch_asks() {
        let result = check_shortcut(&cmd("short", &["story", "12345", "--git-branch"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("git branch"));
    }

    #[test]
    fn test_story_download_asks() {
        let result = check_shortcut(&cmd("short", &["story", "12345", "-D"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("ownload"));
    }

    // ========================================================================
    // CREATE - Always asks
    // ========================================================================

    #[test]
    fn test_create_asks() {
        let result = check_shortcut(&cmd(
            "short",
            &["create", "-t", "New Story", "-p", "myproject"],
        ));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Creating"));
    }

    // ========================================================================
    // INSTALL - Configuration
    // ========================================================================

    #[test]
    fn test_install_asks() {
        let result = check_shortcut(&cmd("short", &["install"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("API token"));
    }

    #[test]
    fn test_install_force_asks() {
        let result = check_shortcut(&cmd("short", &["install", "--force"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // ========================================================================
    // LIST COMMANDS - Read-only
    // ========================================================================

    #[test]
    fn test_members_allows() {
        let result = check_shortcut(&cmd("short", &["members"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_epics_allows() {
        let result = check_shortcut(&cmd("short", &["epics"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_workflows_allows() {
        let result = check_shortcut(&cmd("short", &["workflows"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_projects_allows() {
        let result = check_shortcut(&cmd("short", &["projects"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // ========================================================================
    // WORKSPACE - List (allow) vs Unset (ask)
    // ========================================================================

    #[test]
    fn test_workspace_list_allows() {
        let result = check_shortcut(&cmd("short", &["workspace", "--list"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_workspace_load_allows() {
        let result = check_shortcut(&cmd("short", &["workspace", "myworkspace"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_workspace_unset_asks() {
        let result = check_shortcut(&cmd("short", &["workspace", "--unset", "myworkspace"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Removing"));
    }

    // ========================================================================
    // API - GET (allow) vs POST/PUT/DELETE (ask)
    // ========================================================================

    #[test]
    fn test_api_get_allows() {
        let result = check_shortcut(&cmd("short", &["api", "/stories/12345"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_api_explicit_get_allows() {
        let result = check_shortcut(&cmd("short", &["api", "-X", "GET", "/stories/12345"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_api_post_asks() {
        let result = check_shortcut(&cmd(
            "short",
            &["api", "-X", "POST", "/stories", "-f", "name=Test"],
        ));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("write"));
    }

    #[test]
    fn test_api_delete_asks() {
        let result = check_shortcut(&cmd("short", &["api", "-X", "DELETE", "/stories/12345"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // ========================================================================
    // HELP - Always safe
    // ========================================================================

    #[test]
    fn test_help_allows() {
        let result = check_shortcut(&cmd("short", &["help"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_help_subcommand_allows() {
        let result = check_shortcut(&cmd("short", &["help", "story"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // ========================================================================
    // UNKNOWN - Asks by default
    // ========================================================================

    #[test]
    fn test_unknown_subcommand_asks() {
        let result = check_shortcut(&cmd("short", &["unknowncmd"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // ========================================================================
    // ALIASES - Subcommand shortcuts
    // ========================================================================

    #[test]
    fn test_alias_s_for_search() {
        let result = check_shortcut(&cmd("short", &["s", "-o", "me"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_alias_st_for_story_view() {
        let result = check_shortcut(&cmd("short", &["st", "12345"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_alias_st_for_story_update() {
        let result = check_shortcut(&cmd("short", &["st", "12345", "-s", "Done"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_alias_c_for_create() {
        let result = check_shortcut(&cmd("short", &["c", "-t", "New Story"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_alias_m_for_members() {
        let result = check_shortcut(&cmd("short", &["m"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_alias_w_for_workspace() {
        let result = check_shortcut(&cmd("short", &["w", "--list"]));
        assert_eq!(result.decision, Decision::Allow);
    }
}
