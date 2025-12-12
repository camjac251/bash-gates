//! Git command permission gate.

use crate::models::{CommandInfo, GateResult};
use std::sync::LazyLock;
use std::collections::{HashMap, HashSet};

/// Git global options that take a value (must skip arg + value)
static GIT_GLOBAL_OPTS_WITH_VALUE: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "-C",
        "-c",
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--super-prefix",
        "--config-env",
        "--exec-path",
        "--list-cmds",
    ]
    .into_iter()
    .collect()
});

/// Git global flags (single flags, no value)
static GIT_GLOBAL_FLAGS: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "--bare",
        "--no-replace-objects",
        "--literal-pathspecs",
        "--glob-pathspecs",
        "--noglob-pathspecs",
        "--icase-pathspecs",
        "--no-optional-locks",
        "--paginate",
        "-p",
        "--no-pager",
        "-P",
        "--html-path",
        "--man-path",
        "--info-path",
    ]
    .into_iter()
    .collect()
});

/// Read-only git commands
static GIT_READ: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "status",
        "log",
        "diff",
        "show",
        "tag",
        "remote",
        "stash",
        "describe",
        "rev-parse",
        "ls-files",
        "blame",
        "reflog",
        "shortlog",
        "whatchanged",
        "ls-tree",
        "cat-file",
        "rev-list",
        "name-rev",
        "for-each-ref",
        "symbolic-ref",
        "verify-commit",
        "verify-tag",
        "fsck",
        "count-objects",
        "gc",
        "prune",
        "help",
        "version",
        "--version",
        "-h",
        "--help",
    ]
    .into_iter()
    .collect()
});

/// Commands that need subcommand checking
static GIT_SUBCOMMAND_CHECK: LazyLock<HashMap<&str, HashMap<&str, &str>>> = LazyLock::new(|| {
    [
        (
            "config",
            [
                ("get", "allow"),
                ("list", "allow"),
                ("--get", "allow"),
                ("--list", "allow"),
                ("set", "ask"),
                ("--add", "ask"),
                ("--unset", "ask"),
            ]
            .into_iter()
            .collect(),
        ),
        (
            "stash",
            [
                ("list", "allow"),
                ("show", "allow"),
                ("drop", "ask"),
                ("pop", "ask"),
                ("clear", "ask"),
                ("push", "ask"),
                ("apply", "ask"),
            ]
            .into_iter()
            .collect(),
        ),
        (
            "worktree",
            [
                ("list", "allow"),
                ("add", "ask"),
                ("remove", "ask"),
                ("prune", "ask"),
            ]
            .into_iter()
            .collect(),
        ),
        (
            "submodule",
            [
                ("status", "allow"),
                ("foreach", "allow"),
                ("init", "ask"),
                ("update", "ask"),
                ("add", "ask"),
                ("deinit", "ask"),
            ]
            .into_iter()
            .collect(),
        ),
        (
            "remote",
            [
                ("show", "allow"),
                ("-v", "allow"),
                ("get-url", "allow"),
                ("add", "ask"),
                ("remove", "ask"),
                ("rename", "ask"),
                ("set-url", "ask"),
            ]
            .into_iter()
            .collect(),
        ),
    ]
    .into_iter()
    .collect()
});

/// Write commands (require approval)
static GIT_WRITE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("add", "Staging files"),
        ("commit", "Committing changes"),
        ("push", "Pushing to remote"),
        ("pull", "Pulling from remote"),
        ("merge", "Merging branches"),
        ("rebase", "Rebasing"),
        ("checkout", "Checking out"),
        ("switch", "Switching branches"),
        ("branch", "Branch operation"),
        ("reset", "Resetting"),
        ("restore", "Restoring files"),
        ("clean", "Cleaning working tree"),
        ("cherry-pick", "Cherry-picking"),
        ("revert", "Reverting commits"),
        ("am", "Applying patches"),
        ("apply", "Applying patches"),
        ("format-patch", "Creating patches"),
        ("init", "Initializing repo"),
        ("clone", "Cloning repo"),
        ("fetch", "Fetching"),
        ("mv", "Moving files"),
        ("rm", "Removing files"),
    ]
    .into_iter()
    .collect()
});

/// High-risk patterns (ask with warning)
static GIT_HIGH_RISK: &[(&[&str], &str)] = &[
    (
        &["push", "--force"],
        "Force push (safer: --force-with-lease)",
    ),
    (&["push", "-f"], "Force push (safer: --force-with-lease)"),
    (&["reset", "--hard"], "Hard reset (can lose uncommitted work)"),
    (
        &["clean", "-fd"],
        "Clean (deletes untracked files permanently)",
    ),
    (
        &["clean", "-fdx"],
        "Clean (deletes untracked + ignored files)",
    ),
];

/// Skip git global options to find the actual subcommand.
/// Returns (index, subcommand) where index is the position in args.
fn extract_subcommand(args: &[String]) -> (Option<usize>, Option<&str>) {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();

        // Options that take a value: -C <path>, -c <key=value>, etc.
        if GIT_GLOBAL_OPTS_WITH_VALUE.contains(arg) {
            i += 2;
            continue;
        }

        // Combined form: --git-dir=<path>
        if GIT_GLOBAL_OPTS_WITH_VALUE
            .iter()
            .any(|opt| arg.starts_with(&format!("{opt}=")))
        {
            i += 1;
            continue;
        }

        // Short form combined: -C/path (without space)
        if arg.starts_with("-C") && arg.len() > 2 {
            i += 1;
            continue;
        }

        // Single flags without values
        if GIT_GLOBAL_FLAGS.contains(arg) {
            i += 1;
            continue;
        }

        // Unknown flag starting with -
        if arg.starts_with('-') {
            if arg == "--version" || arg == "-v" || arg == "--help" || arg == "-h" {
                return (Some(i), Some(arg));
            }
            i += 1;
            continue;
        }

        // Found non-flag argument - this is the subcommand
        return (Some(i), Some(arg));
    }

    (None, None)
}

/// Check git command.
pub fn check_git(cmd: &CommandInfo) -> GateResult {
    if cmd.program != "git" {
        return GateResult::skip();
    }

    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    // Extract the actual subcommand, skipping global options
    let (subcmd_idx, subcommand) = extract_subcommand(args);

    let Some(subcommand) = subcommand else {
        return GateResult::allow();
    };

    // Get args after the subcommand
    let subcmd_args: Vec<&str> = subcmd_idx.map_or_else(Vec::new, |idx| {
        args.iter()
            .skip(idx + 1)
            .map(std::string::String::as_str)
            .collect()
    });

    // Check for dry-run flags FIRST (makes commands safe)
    if args.iter().any(|a| a == "--dry-run" || a == "-n") {
        return GateResult::allow();
    }

    // Build effective args for pattern matching
    let mut effective_args: Vec<&str> = vec![subcommand];
    effective_args.extend(subcmd_args.iter());

    // Check high-risk patterns
    // Note: --force-with-lease is the SAFE alternative, so exclude it from --force check
    for (pattern, reason) in GIT_HIGH_RISK {
        if matches_pattern(&effective_args, pattern) {
            // Special case: --force-with-lease should NOT trigger the --force warning
            if pattern.contains(&"--force")
                && args.iter().any(|a| a == "--force-with-lease")
            {
                continue;
            }
            return GateResult::ask(format!("git: {reason}"));
        }
    }

    // Check subcommand-specific handling
    if let Some(sub_checks) = GIT_SUBCOMMAND_CHECK.get(subcommand) {
        if !subcmd_args.is_empty() {
            if let Some(&decision) = sub_checks.get(subcmd_args[0]) {
                if decision == "allow" {
                    return GateResult::allow();
                }
                return GateResult::ask(format!("git {} {}", subcommand, subcmd_args[0]));
            }
        }
    }

    // Pure read commands
    if GIT_READ.contains(subcommand) {
        return GateResult::allow();
    }

    // Write commands
    if let Some(&reason) = GIT_WRITE.get(subcommand) {
        // Special handling for some commands
        match subcommand {
            "add" => return check_git_add(&effective_args),
            "checkout" => return check_git_checkout(&effective_args),
            "branch" => return check_git_branch(&effective_args),
            _ => return GateResult::ask(format!("git: {reason}")),
        }
    }

    // Unknown git command - ask
    GateResult::ask(format!("git: {subcommand}"))
}

/// Check if args match a pattern (prefix match)
fn matches_pattern(args: &[&str], pattern: &[&str]) -> bool {
    if args.len() < pattern.len() {
        return false;
    }

    for (i, p) in pattern.iter().enumerate() {
        if !args[i].starts_with(p) {
            return false;
        }
    }
    true
}

/// Check git add for dangerous patterns.
fn check_git_add(args: &[&str]) -> GateResult {
    let dangerous = ["-A", "--all", "-a"];
    if args.iter().any(|a| dangerous.contains(a)) {
        return GateResult::ask("git add --all (stages everything)");
    }

    if args.contains(&".") {
        return GateResult::ask("git add . (stages all in directory)");
    }

    if args.iter().skip(1).any(|a| a.contains('*')) {
        return GateResult::ask("git add with wildcard");
    }

    GateResult::ask("git: Staging files")
}

/// Check git checkout.
fn check_git_checkout(args: &[&str]) -> GateResult {
    if args.contains(&"-b") || args.contains(&"-B") {
        return GateResult::ask("git: Creating branch");
    }

    if args.contains(&"--") {
        return GateResult::ask("git: Discarding changes");
    }

    GateResult::ask("git: Checking out")
}

/// Check git branch command.
fn check_git_branch(args: &[&str]) -> GateResult {
    // Just listing branches
    if args.len() == 1 {
        return GateResult::allow();
    }

    // Listing flags
    let listing_flags = ["-a", "--all", "-r", "--remotes", "-v", "-vv", "--list"];
    if args.iter().any(|a| listing_flags.contains(a)) {
        return GateResult::allow();
    }

    // Delete flags
    if args.iter().any(|a| *a == "-d" || *a == "-D" || *a == "--delete") {
        return GateResult::ask("git: Deleting branch");
    }

    // Move/rename
    if args.iter().any(|a| *a == "-m" || *a == "-M" || *a == "--move") {
        return GateResult::ask("git: Renaming branch");
    }

    GateResult::ask("git: Branch operation")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Decision;

    fn cmd(args: &[&str]) -> CommandInfo {
        CommandInfo {
            raw: format!("git {}", args.join(" ")),
            program: "git".to_string(),
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
            &["status"][..],
            &["log"],
            &["log", "--oneline", "-10"],
            &["diff"],
            &["diff", "HEAD~1"],
            &["diff", "--staged"],
            &["show", "HEAD"],
            &["branch"],
            &["branch", "-a"],
            &["branch", "-v"],
            &["branch", "--list"],
            &["tag"],
            &["tag", "-l"],
            &["remote", "-v"],
            &["remote", "show", "origin"],
            &["stash", "list"],
            &["stash", "show"],
            &["describe"],
            &["rev-parse", "HEAD"],
            &["ls-files"],
            &["blame", "file.txt"],
            &["reflog"],
            &["--version"],
            &["help"],
        ];

        for args in read_cmds {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    // === Write Commands ===

    #[test]
    fn test_write_commands_ask() {
        let write_cmds = [
            (&["add", "file.txt"][..], "Staging"),
            (&["add", "."], "stages all"),
            (&["add", "-A"], "stages everything"),
            (&["commit", "-m", "message"], "Committing"),
            (&["push", "origin", "main"], "Pushing"),
            (&["pull", "origin", "main"], "Pulling"),
            (&["merge", "feature"], "Merging"),
            (&["rebase", "main"], "Rebasing"),
            (&["checkout", "feature"], "Checking out"),
            (&["checkout", "-b", "new-branch"], "Creating branch"),
            (&["switch", "main"], "Switching"),
            (&["reset", "HEAD~1"], "Resetting"),
            (&["restore", "file.txt"], "Restoring"),
            (&["cherry-pick", "abc123"], "Cherry-picking"),
            (&["revert", "abc123"], "Reverting"),
            (&["fetch", "origin"], "Fetching"),
            (&["clone", "https://github.com/user/repo"], "Cloning"),
            (&["mv", "old.txt", "new.txt"], "Moving"),
            (&["rm", "file.txt"], "Removing"),
            (&["branch", "-d", "old-branch"], "Deleting branch"),
            (&["branch", "-m", "old", "new"], "Renaming branch"),
        ];

        for (args, expected_in_reason) in write_cmds {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
            assert!(
                result.reason.as_ref().unwrap().to_lowercase().contains(&expected_in_reason.to_lowercase()),
                "Expected '{}' in reason for {:?}, got: {:?}",
                expected_in_reason,
                args,
                result.reason
            );
        }
    }

    // === High Risk Commands ===

    #[test]
    fn test_high_risk_asks_with_warning() {
        let high_risk_cmds = [
            (&["push", "--force", "origin", "main"][..], "Force push"),
            (&["push", "-f", "origin", "main"], "Force push"),
            (&["reset", "--hard", "HEAD~1"], "Hard reset"),
            (&["clean", "-fd"], "Clean"),
            (&["clean", "-fdx"], "Clean"),
        ];

        for (args, expected_in_reason) in high_risk_cmds {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
            assert!(
                result.reason.as_ref().unwrap().contains(expected_in_reason),
                "Expected '{}' in reason for {:?}, got: {:?}",
                expected_in_reason,
                args,
                result.reason
            );
        }
    }

    // === Force with Lease (Safe Alternative) ===

    #[test]
    fn test_force_with_lease_not_flagged_as_force() {
        // --force-with-lease is the SAFE alternative, shouldn't trigger "Force push" warning
        let safe_force_cmds = [
            &["push", "--force-with-lease"][..],
            &["push", "--force-with-lease", "origin", "main"],
            &["push", "origin", "main", "--force-with-lease"],
            &["-C", "/path", "push", "--force-with-lease"],
        ];

        for args in safe_force_cmds {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
            let reason = result.reason.as_ref().unwrap();
            // Should NOT contain "Force push" warning since --force-with-lease is safer
            assert!(
                !reason.contains("Force push"),
                "Should not warn about force push for {:?}, got: {}",
                args,
                reason
            );
            // Should still ask for push (it's a write operation)
            assert!(reason.contains("Pushing"), "Should mention pushing for {:?}", args);
        }
    }

    // === Dry Run ===

    #[test]
    fn test_dry_run_allows() {
        let dry_run_cmds = [
            &["push", "--dry-run", "origin", "main"][..],
            &["clean", "-fd", "--dry-run"],
            &["add", "--dry-run", "."],
        ];

        for args in dry_run_cmds {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    // === Config Subcommand ===

    #[test]
    fn test_config_read_allows() {
        let config_read = [
            &["config", "--get", "user.name"][..],
            &["config", "--list"],
            &["config", "get", "user.email"],
            &["config", "list"],
        ];

        for args in config_read {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_config_write_asks() {
        let config_write = [
            &["config", "set", "user.name", "Test"][..],
            &["config", "--add", "alias.st", "status"],
            &["config", "--unset", "alias.st"],
        ];

        for args in config_write {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
        }
    }

    // === Global Options ===

    #[test]
    fn test_global_opts_with_read_allows() {
        let global_read = [
            &["-C", "/path/to/repo", "status"][..],
            &["-C", "/home/user/project", "log"],
            &["-C", "/tmp", "log", "--oneline", "-10"],
            &["-C", "/path", "diff"],
            &["-C", "/path", "branch", "-a"],
            &["-C", "/path", "remote", "-v"],
            &["--git-dir=/path/.git", "status"],
            &["--git-dir", "/path/.git", "log"],
            &["--work-tree=/path", "status"],
            &["--work-tree", "/path", "diff"],
            &["-C", "/path", "--git-dir=/path/.git", "status"],
            &["--bare", "log"],
            &["-c", "user.name=Test", "status"],
            &["-C", "/tmp/project", "status"],
            &["-C", "/tmp/project", "log", "--oneline"],
        ];

        for args in global_read {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_global_opts_with_write_asks() {
        let global_write = [
            (&["-C", "/path", "commit", "-m", "msg"][..], "Committing"),
            (&["-C", "/path", "push", "origin", "main"], "Pushing"),
            (&["-C", "/path", "add", "file.txt"], "Staging"),
            (&["-C", "/path", "checkout", "branch"], "Checking out"),
            (&["--git-dir=/path/.git", "commit", "-m", "msg"], "Committing"),
            (&["--git-dir", "/path/.git", "push"], "Pushing"),
            (&["-C", "/path", "push", "--force"], "Force push"),
            (&["-C", "/path", "reset", "--hard"], "Hard reset"),
            (&["-C", "/home/user/project", "add", "."], "stages all"),
            (&["-C", "/home/user/project", "branch", "-d", "old"], "Deleting branch"),
        ];

        for (args, expected_in_reason) in global_write {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
            assert!(
                result.reason.as_ref().unwrap().to_lowercase().contains(&expected_in_reason.to_lowercase()),
                "Expected '{}' in reason for {:?}, got: {:?}",
                expected_in_reason,
                args,
                result.reason
            );
        }
    }

    #[test]
    fn test_global_opts_with_dry_run_allows() {
        let dry_run = [
            &["-C", "/path", "push", "--dry-run"][..],
            &["-C", "/path", "add", "--dry-run", "."],
            &["--git-dir=/path/.git", "clean", "-fd", "--dry-run"],
        ];

        for args in dry_run {
            let result = check_git(&cmd(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_only_global_opts_no_subcommand_allows() {
        let result = check_git(&cmd(&["-C", "/path"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === Non-git Commands ===

    #[test]
    fn test_non_git_skips() {
        let result = check_git(&CommandInfo {
            raw: "gh pr list".to_string(),
            program: "gh".to_string(),
            args: vec!["pr".to_string(), "list".to_string()],
            is_subshell: false,
            is_pipeline: false,
            pipeline_position: 0,
        });
        assert_eq!(result.decision, Decision::Skip);
    }
}
