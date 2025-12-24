//! GitHub CLI (gh) permission gate.
//!
//! Fully declarative - all rules in rules/gh.toml.

use crate::generated::rules::check_gh_gate;
use crate::models::{CommandInfo, GateResult};

/// Check a gh command for permission requirements.
pub fn check_gh(cmd: &CommandInfo) -> GateResult {
    check_gh_gate(cmd)
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

    #[test]
    fn test_api_implicit_post_with_field_flag_asks() {
        // -f flag implies POST (adds field to request body)
        let result = check_gh(&cmd(&[
            "api",
            "repos/owner/repo/pulls/123/comments/456/replies",
            "-f",
            "body=test",
        ]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("POST"));
    }

    #[test]
    fn test_api_implicit_post_with_field_equals_asks() {
        // -f=value syntax also implies POST
        let result = check_gh(&cmd(&[
            "api",
            "repos/owner/repo/issues",
            "-f=title=Bug",
        ]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("POST"));
    }

    #[test]
    fn test_api_implicit_post_flags() {
        // All these flags imply POST
        for flag in ["-f", "-F", "--field", "--raw-field", "--input"] {
            let result = check_gh(&cmd(&["api", "repos/owner/repo/issues", flag, "data"]));
            assert_eq!(
                result.decision,
                Decision::Ask,
                "Failed for flag: {flag}"
            );
            assert!(
                result.reason.as_ref().unwrap().contains("POST"),
                "Expected POST in reason for {flag}, got: {:?}",
                result.reason
            );
        }
    }

    #[test]
    fn test_api_explicit_method_overrides_implicit() {
        // Explicit -X GET should still allow even with -f flag
        let result = check_gh(&cmd(&[
            "api",
            "-X",
            "GET",
            "repos/owner/repo",
            "-f",
            "per_page=100",
        ]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === Non-gh Commands ===

    #[test]
    fn test_non_gh_skips() {
        let result = check_gh(&make_cmd("git", &["status"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}
