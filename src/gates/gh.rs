//! GitHub CLI (gh) permission gate.

use crate::models::{CommandInfo, GateResult};
use std::sync::LazyLock;
use std::collections::{HashMap, HashSet};

/// Commands that are always blocked
static BLOCKED_COMMANDS: LazyLock<HashMap<(&str, &str), &str>> = LazyLock::new(|| {
    [
        (("repo", "delete"), "Deleting repositories is blocked"),
        (("auth", "logout"), "Logging out is blocked"),
    ]
    .into_iter()
    .collect()
});

/// Read-only commands (auto-allow)
static READ_COMMANDS: LazyLock<HashSet<Vec<&str>>> = LazyLock::new(|| {
    [
        // Issue/PR viewing
        vec!["issue", "view"],
        vec!["issue", "list"],
        vec!["issue", "status"],
        vec!["pr", "view"],
        vec!["pr", "list"],
        vec!["pr", "status"],
        vec!["pr", "diff"],
        vec!["pr", "checks"],
        vec!["pr", "develop"],
        // Repo info
        vec!["repo", "view"],
        vec!["repo", "list"],
        vec!["repo", "clone"],
        // Search
        vec!["search", "issues"],
        vec!["search", "prs"],
        vec!["search", "repos"],
        vec!["search", "commits"],
        vec!["search", "code"],
        // Status/auth info
        vec!["status"],
        vec!["auth", "status"],
        vec!["auth", "token"],
        // Config reading
        vec!["config", "get"],
        vec!["config", "list"],
        // Run/workflow viewing
        vec!["run", "list"],
        vec!["run", "view"],
        vec!["run", "download"],
        vec!["workflow", "list"],
        vec!["workflow", "view"],
        // Release/gist viewing
        vec!["release", "list"],
        vec!["release", "view"],
        vec!["release", "download"],
        vec!["gist", "list"],
        vec!["gist", "view"],
        vec!["gist", "clone"],
        // Labels/milestones
        vec!["label", "list"],
        // Codespace
        vec!["codespace", "list"],
        vec!["cs", "list"],
        // Keys
        vec!["ssh-key", "list"],
        vec!["gpg-key", "list"],
        // Extensions
        vec!["extension", "list"],
        // Browse (opens browser)
        vec!["browse"],
        // Alias
        vec!["alias", "list"],
        // Cache
        vec!["cache", "list"],
        // Variables/secrets listing (doesn't show values)
        vec!["variable", "list"],
        vec!["secret", "list"],
        // Ruleset
        vec!["ruleset", "list"],
        vec!["ruleset", "view"],
        // Project viewing
        vec!["project", "list"],
        vec!["project", "view"],
    ]
    .into_iter()
    .collect()
});

/// Write commands (ask permission)
static WRITE_COMMANDS: LazyLock<HashMap<Vec<&str>, &str>> = LazyLock::new(|| {
    [
        // Issue/PR mutations
        (vec!["issue", "create"], "Creating issue"),
        (vec!["issue", "close"], "Closing issue"),
        (vec!["issue", "reopen"], "Reopening issue"),
        (vec!["issue", "edit"], "Editing issue"),
        (vec!["issue", "comment"], "Adding comment"),
        (vec!["issue", "delete"], "Deleting issue"),
        (vec!["issue", "transfer"], "Transferring issue"),
        (vec!["issue", "pin"], "Pinning issue"),
        (vec!["issue", "unpin"], "Unpinning issue"),
        (vec!["issue", "lock"], "Locking issue"),
        (vec!["issue", "unlock"], "Unlocking issue"),
        (vec!["pr", "create"], "Creating PR"),
        (vec!["pr", "close"], "Closing PR"),
        (vec!["pr", "reopen"], "Reopening PR"),
        (vec!["pr", "edit"], "Editing PR"),
        (vec!["pr", "comment"], "Adding comment"),
        (vec!["pr", "merge"], "Merging PR"),
        (vec!["pr", "ready"], "Marking PR ready"),
        (vec!["pr", "review"], "Submitting review"),
        (vec!["pr", "checkout"], "Checking out PR"),
        // Repo mutations
        (vec!["repo", "create"], "Creating repository"),
        (vec!["repo", "rename"], "Renaming repository"),
        (vec!["repo", "edit"], "Editing repository"),
        (vec!["repo", "fork"], "Forking repository"),
        (vec!["repo", "archive"], "Archiving repository"),
        (vec!["repo", "unarchive"], "Unarchiving repository"),
        (vec!["repo", "sync"], "Syncing repository"),
        (vec!["repo", "set-default"], "Setting default repo"),
        // Release mutations
        (vec!["release", "create"], "Creating release"),
        (vec!["release", "delete"], "Deleting release"),
        (vec!["release", "edit"], "Editing release"),
        (vec!["release", "upload"], "Uploading asset"),
        (vec!["release", "delete-asset"], "Deleting asset"),
        // Gist mutations
        (vec!["gist", "create"], "Creating gist"),
        (vec!["gist", "delete"], "Deleting gist"),
        (vec!["gist", "edit"], "Editing gist"),
        (vec!["gist", "rename"], "Renaming gist"),
        // Label mutations
        (vec!["label", "create"], "Creating label"),
        (vec!["label", "delete"], "Deleting label"),
        (vec!["label", "edit"], "Editing label"),
        (vec!["label", "clone"], "Cloning labels"),
        // Workflow mutations
        (vec!["workflow", "run"], "Running workflow"),
        (vec!["workflow", "enable"], "Enabling workflow"),
        (vec!["workflow", "disable"], "Disabling workflow"),
        (vec!["run", "cancel"], "Canceling run"),
        (vec!["run", "rerun"], "Rerunning"),
        (vec!["run", "delete"], "Deleting run"),
        (vec!["run", "watch"], "Watching run"),
        // Codespace mutations
        (vec!["codespace", "create"], "Creating codespace"),
        (vec!["codespace", "delete"], "Deleting codespace"),
        (vec!["codespace", "edit"], "Editing codespace"),
        (vec!["codespace", "stop"], "Stopping codespace"),
        (vec!["codespace", "rebuild"], "Rebuilding codespace"),
        (vec!["cs", "create"], "Creating codespace"),
        (vec!["cs", "delete"], "Deleting codespace"),
        // Key mutations
        (vec!["ssh-key", "add"], "Adding SSH key"),
        (vec!["ssh-key", "delete"], "Deleting SSH key"),
        (vec!["gpg-key", "add"], "Adding GPG key"),
        (vec!["gpg-key", "delete"], "Deleting GPG key"),
        // Config mutations
        (vec!["config", "set"], "Setting config"),
        (vec!["config", "clear-cache"], "Clearing cache"),
        // Secret/variable mutations
        (vec!["secret", "set"], "Setting secret"),
        (vec!["secret", "delete"], "Deleting secret"),
        (vec!["variable", "set"], "Setting variable"),
        (vec!["variable", "delete"], "Deleting variable"),
        // Cache mutations
        (vec!["cache", "delete"], "Deleting cache"),
        // Extension mutations
        (vec!["extension", "install"], "Installing extension"),
        (vec!["extension", "upgrade"], "Upgrading extension"),
        (vec!["extension", "remove"], "Removing extension"),
        // Alias mutations
        (vec!["alias", "set"], "Setting alias"),
        (vec!["alias", "delete"], "Deleting alias"),
        (vec!["alias", "import"], "Importing aliases"),
        // Project mutations
        (vec!["project", "create"], "Creating project"),
        (vec!["project", "delete"], "Deleting project"),
        (vec!["project", "edit"], "Editing project"),
        (vec!["project", "close"], "Closing project"),
        (vec!["project", "copy"], "Copying project"),
        (vec!["project", "item-add"], "Adding project item"),
        (vec!["project", "item-archive"], "Archiving item"),
        (vec!["project", "item-create"], "Creating item"),
        (vec!["project", "item-delete"], "Deleting item"),
        (vec!["project", "item-edit"], "Editing item"),
        (vec!["project", "field-create"], "Creating field"),
        (vec!["project", "field-delete"], "Deleting field"),
    ]
    .into_iter()
    .collect()
});

/// Check a gh command for permission requirements.
pub fn check_gh(cmd: &CommandInfo) -> GateResult {
    if cmd.program != "gh" {
        return GateResult::skip();
    }

    let args = &cmd.args;

    // Handle `gh api` specially
    if !args.is_empty() && args[0] == "api" {
        return check_gh_api(&args[1..]);
    }

    // Build command tuple for lookup
    let cmd_key: Vec<&str> = args.iter().take(2).map(std::string::String::as_str).collect();

    // Check blocked commands
    if cmd_key.len() >= 2 {
        if let Some(reason) = BLOCKED_COMMANDS.get(&(cmd_key[0], cmd_key[1])) {
            return GateResult::block(*reason);
        }
    }

    // Check read commands (1 or 2 parts)
    for read_cmd in READ_COMMANDS.iter() {
        let check_len = read_cmd.len().min(cmd_key.len());
        if check_len > 0 && cmd_key[..check_len] == read_cmd[..] {
            return GateResult::allow();
        }
    }

    // Check write commands (1 or 2 parts)
    for (write_cmd, reason) in WRITE_COMMANDS.iter() {
        let check_len = write_cmd.len().min(cmd_key.len());
        if check_len > 0 && cmd_key[..check_len] == write_cmd[..] {
            return GateResult::ask(format!("gh: {reason}"));
        }
    }

    // Unknown gh command - ask to be safe
    let cmd_desc = if cmd_key.len() >= 2 {
        format!("{} {}", cmd_key[0], cmd_key[1])
    } else if !cmd_key.is_empty() {
        cmd_key[0].to_string()
    } else {
        "unknown".to_string()
    };
    GateResult::ask(format!("gh: Unknown command '{cmd_desc}'"))
}

/// Check gh api command for HTTP method.
fn check_gh_api(api_args: &[String]) -> GateResult {
    let mut method = "GET";

    let mut i = 0;
    while i < api_args.len() {
        let arg = &api_args[i];
        if arg == "-X" || arg == "--method" {
            if i + 1 < api_args.len() {
                method = &api_args[i + 1];
            }
            break;
        } else if let Some(m) = arg.strip_prefix("-X") {
            method = m;
            break;
        } else if let Some(m) = arg.strip_prefix("--method=") {
            method = m;
            break;
        }
        i += 1;
    }

    let method_upper = method.to_uppercase();
    if method_upper == "GET" {
        GateResult::allow()
    } else {
        GateResult::ask(format!("gh api: {method_upper} request"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Decision;

    fn cmd(args: &[&str]) -> CommandInfo {
        CommandInfo {
            raw: format!("gh {}", args.join(" ")),
            program: "gh".to_string(),
            args: args.iter().map(std::string::ToString::to_string).collect(),
            is_subshell: false,
            is_pipeline: false,
            pipeline_position: 0,
        }
    }

    // === Read Commands ===

    #[test]
    fn test_read_commands_allow() {
        let read_cmds = [
            &["pr", "list"][..],
            &["pr", "view", "123"],
            &["pr", "status"],
            &["pr", "diff", "123"],
            &["pr", "checks", "123"],
            &["issue", "list"],
            &["issue", "view", "456"],
            &["issue", "status"],
            &["repo", "view"],
            &["repo", "list"],
            &["repo", "clone", "owner/repo"],
            &["search", "issues", "bug"],
            &["search", "prs", "feature"],
            &["status"],
            &["auth", "status"],
            &["auth", "token"],
            &["run", "list"],
            &["run", "view", "123"],
            &["release", "list"],
            &["release", "view", "v1.0"],
            &["gist", "list"],
            &["gist", "view", "abc123"],
            &["label", "list"],
            &["browse"],
        ];

        for args in read_cmds {
            let result = check_gh(&cmd(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    // === Write Commands ===

    #[test]
    fn test_write_commands_ask() {
        let write_cmds = [
            (&["pr", "create"][..], "Creating PR"),
            (&["pr", "close", "123"], "Closing PR"),
            (&["pr", "merge", "123"], "Merging PR"),
            (&["pr", "comment", "123", "-b", "LGTM"], "Adding comment"),
            (&["issue", "create", "--title", "Bug"], "Creating issue"),
            (&["issue", "close", "456"], "Closing issue"),
            (&["issue", "comment", "456"], "Adding comment"),
            (&["repo", "create", "new-repo"], "Creating repository"),
            (&["repo", "fork", "owner/repo"], "Forking repository"),
            (&["release", "create", "v1.0"], "Creating release"),
            (&["gist", "create", "file.txt"], "Creating gist"),
            (&["workflow", "run", "build.yml"], "Running workflow"),
            (&["run", "rerun", "123"], "Rerunning"),
        ];

        for (args, expected_reason) in write_cmds {
            let result = check_gh(&cmd(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
            assert!(
                result.reason.as_ref().unwrap().contains(expected_reason),
                "Expected '{}' in reason for {:?}, got: {:?}",
                expected_reason,
                args,
                result.reason
            );
        }
    }

    // === Blocked Commands ===

    #[test]
    fn test_blocked_commands() {
        let blocked_cmds = [
            (&["repo", "delete", "owner/repo"][..], "Deleting repositories"),
            (&["auth", "logout"], "Logging out"),
        ];

        for (args, expected_reason) in blocked_cmds {
            let result = check_gh(&cmd(args));
            assert_eq!(result.decision, Decision::Block, "Failed for: {args:?}");
            assert!(
                result.reason.as_ref().unwrap().contains(expected_reason),
                "Failed for: {args:?}"
            );
        }
    }

    // === API Commands ===

    #[test]
    fn test_api_get_allows() {
        let result = check_gh(&cmd(&["api", "repos/owner/repo"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_api_get_explicit_allows() {
        let result = check_gh(&cmd(&["api", "-X", "GET", "repos/owner/repo"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_api_mutating_asks() {
        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            let result = check_gh(&cmd(&["api", "-X", method, "repos/owner/repo/issues"]));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {method}");
            assert!(
                result.reason.as_ref().unwrap().contains(method),
                "Failed for: {method}"
            );
        }
    }

    // === Non-gh Commands ===

    #[test]
    fn test_non_gh_skips() {
        let result = check_gh(&CommandInfo {
            raw: "git status".to_string(),
            program: "git".to_string(),
            args: vec!["status".to_string()],
            is_subshell: false,
            is_pipeline: false,
            pipeline_position: 0,
        });
        assert_eq!(result.decision, Decision::Skip);
    }
}
