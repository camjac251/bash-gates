//! GitHub CLI (gh) permission gate.
//!
//! Uses generated declarative rules for command matching.

use crate::generated::rules::check_gh_declarative;
use crate::models::{CommandInfo, GateResult};

/// Check a gh command for permission requirements.
///
/// Delegates to generated declarative rules which handle:
/// - Read-only commands (allow)
/// - Write commands (ask with description)
/// - Blocked commands (deny)
/// - API method detection for `gh api`
pub fn check_gh(cmd: &CommandInfo) -> GateResult {
    if cmd.program != "gh" {
        return GateResult::skip();
    }

    // Use declarative rules - they handle all gh cases
    check_gh_declarative(cmd).unwrap_or_else(|| {
        // Fallback for any unhandled case (shouldn't happen)
        let cmd_desc = if cmd.args.len() >= 2 {
            format!("{} {}", cmd.args[0], cmd.args[1])
        } else if !cmd.args.is_empty() {
            cmd.args[0].clone()
        } else {
            "unknown".to_string()
        };
        GateResult::ask(format!("gh: {cmd_desc}"))
    })
}

// === Exports for toml_export (backwards compatibility) ===

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

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
        vec!["issue", "view"],
        vec!["issue", "list"],
        vec!["issue", "status"],
        vec!["pr", "view"],
        vec!["pr", "list"],
        vec!["pr", "status"],
        vec!["pr", "diff"],
        vec!["pr", "checks"],
        vec!["pr", "develop"],
        vec!["repo", "view"],
        vec!["repo", "list"],
        vec!["repo", "clone"],
        vec!["search", "issues"],
        vec!["search", "prs"],
        vec!["search", "repos"],
        vec!["search", "commits"],
        vec!["search", "code"],
        vec!["status"],
        vec!["auth", "status"],
        vec!["auth", "token"],
        vec!["config", "get"],
        vec!["config", "list"],
        vec!["run", "list"],
        vec!["run", "view"],
        vec!["run", "download"],
        vec!["workflow", "list"],
        vec!["workflow", "view"],
        vec!["release", "list"],
        vec!["release", "view"],
        vec!["release", "download"],
        vec!["gist", "list"],
        vec!["gist", "view"],
        vec!["gist", "clone"],
        vec!["label", "list"],
        vec!["codespace", "list"],
        vec!["cs", "list"],
        vec!["ssh-key", "list"],
        vec!["gpg-key", "list"],
        vec!["extension", "list"],
        vec!["browse"],
        vec!["alias", "list"],
        vec!["cache", "list"],
        vec!["variable", "list"],
        vec!["secret", "list"],
        vec!["ruleset", "list"],
        vec!["ruleset", "view"],
        vec!["project", "list"],
        vec!["project", "view"],
    ]
    .into_iter()
    .collect()
});

/// Write commands (ask permission)
static WRITE_COMMANDS: LazyLock<HashMap<Vec<&str>, &str>> = LazyLock::new(|| {
    [
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
        (vec!["repo", "create"], "Creating repository"),
        (vec!["repo", "rename"], "Renaming repository"),
        (vec!["repo", "edit"], "Editing repository"),
        (vec!["repo", "fork"], "Forking repository"),
        (vec!["repo", "archive"], "Archiving repository"),
        (vec!["repo", "unarchive"], "Unarchiving repository"),
        (vec!["repo", "sync"], "Syncing repository"),
        (vec!["repo", "set-default"], "Setting default repo"),
        (vec!["release", "create"], "Creating release"),
        (vec!["release", "delete"], "Deleting release"),
        (vec!["release", "edit"], "Editing release"),
        (vec!["release", "upload"], "Uploading asset"),
        (vec!["release", "delete-asset"], "Deleting asset"),
        (vec!["gist", "create"], "Creating gist"),
        (vec!["gist", "delete"], "Deleting gist"),
        (vec!["gist", "edit"], "Editing gist"),
        (vec!["gist", "rename"], "Renaming gist"),
        (vec!["label", "create"], "Creating label"),
        (vec!["label", "delete"], "Deleting label"),
        (vec!["label", "edit"], "Editing label"),
        (vec!["label", "clone"], "Cloning labels"),
        (vec!["workflow", "run"], "Running workflow"),
        (vec!["workflow", "enable"], "Enabling workflow"),
        (vec!["workflow", "disable"], "Disabling workflow"),
        (vec!["run", "cancel"], "Canceling run"),
        (vec!["run", "rerun"], "Rerunning"),
        (vec!["run", "delete"], "Deleting run"),
        (vec!["run", "watch"], "Watching run"),
        (vec!["codespace", "create"], "Creating codespace"),
        (vec!["codespace", "delete"], "Deleting codespace"),
        (vec!["codespace", "edit"], "Editing codespace"),
        (vec!["codespace", "stop"], "Stopping codespace"),
        (vec!["codespace", "rebuild"], "Rebuilding codespace"),
        (vec!["cs", "create"], "Creating codespace"),
        (vec!["cs", "delete"], "Deleting codespace"),
        (vec!["ssh-key", "add"], "Adding SSH key"),
        (vec!["ssh-key", "delete"], "Deleting SSH key"),
        (vec!["gpg-key", "add"], "Adding GPG key"),
        (vec!["gpg-key", "delete"], "Deleting GPG key"),
        (vec!["config", "set"], "Setting config"),
        (vec!["config", "clear-cache"], "Clearing cache"),
        (vec!["secret", "set"], "Setting secret"),
        (vec!["secret", "delete"], "Deleting secret"),
        (vec!["variable", "set"], "Setting variable"),
        (vec!["variable", "delete"], "Deleting variable"),
        (vec!["cache", "delete"], "Deleting cache"),
        (vec!["extension", "install"], "Installing extension"),
        (vec!["extension", "upgrade"], "Upgrading extension"),
        (vec!["extension", "remove"], "Removing extension"),
        (vec!["alias", "set"], "Setting alias"),
        (vec!["alias", "delete"], "Deleting alias"),
        (vec!["alias", "import"], "Importing aliases"),
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

/// Get blocked gh commands as (subcommands, reason)
pub fn blocked_commands() -> impl Iterator<Item = ((&'static str, &'static str), &'static str)> {
    BLOCKED_COMMANDS.iter().map(|(k, v)| (*k, *v))
}

/// Get read-only gh command prefixes (e.g., "pr list", "issue view")
pub fn read_command_prefixes() -> impl Iterator<Item = String> {
    READ_COMMANDS.iter().map(|parts| parts.join(" "))
}

/// Get write gh command prefixes with descriptions
pub fn write_command_prefixes() -> impl Iterator<Item = (String, &'static str)> {
    WRITE_COMMANDS
        .iter()
        .map(|(parts, desc)| (parts.join(" "), *desc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd as make_cmd;
    use crate::models::Decision;

    fn cmd(args: &[&str]) -> CommandInfo {
        make_cmd("gh", args)
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
            (
                &["repo", "delete", "owner/repo"][..],
                "Deleting repositories",
            ),
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
