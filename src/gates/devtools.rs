//! Developer tools permission gate.
//!
//! Almost entirely declarative - add tools to rules/devtools.toml.
//! Only `ruff` needs custom logic (format vs check detection).

use crate::generated::rules::{check_devtools_gate, check_ruff_declarative};
use crate::models::{CommandInfo, Decision, GateResult};

/// Check developer tools that can modify files.
pub fn check_devtools(cmd: &CommandInfo) -> GateResult {
    // Try the generated gate first
    let result = check_devtools_gate(cmd);

    // Generated gate returns Skip for programs with custom handlers
    if matches!(result.decision, Decision::Skip) && cmd.program == "ruff" {
        return check_ruff(cmd);
    }

    result
}

/// Custom handler for ruff - format subcommand needs special logic
fn check_ruff(cmd: &CommandInfo) -> GateResult {
    // Declarative handles most cases
    if let Some(result) = check_ruff_declarative(cmd) {
        // If declarative says ask/block, use that
        if !matches!(result.decision, Decision::Allow) {
            return result;
        }
    }

    // ruff format without --check/--diff asks
    if cmd.args.first().map(String::as_str) == Some("format")
        && !cmd.args.iter().any(|a| a == "--check" || a == "--diff")
    {
        return GateResult::ask("ruff: Formatting files");
    }

    GateResult::allow()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;

    // === sd (always asks - in-place editor) ===

    #[test]
    fn test_sd_asks() {
        let result = check_devtools(&cmd("sd", &["old", "new", "file"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Tools with unknown_action = "allow" ===

    #[test]
    fn test_jq_allows() {
        let result = check_devtools(&cmd("jq", &[".key", "file.json"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_shellcheck_allows() {
        let result = check_devtools(&cmd("shellcheck", &["script.sh"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_shellcheck_with_flags_allows() {
        let result = check_devtools(&cmd(
            "shellcheck",
            &["-f", "json", "-s", "bash", "script.sh"],
        ));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === Tools with flag-conditional behavior ===

    #[test]
    fn test_sad_preview_allows() {
        let result = check_devtools(&cmd("sad", &["old", "new", "file"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_sad_commit_asks() {
        let result = check_devtools(&cmd("sad", &["old", "new", "--commit", "file"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_ast_grep_search_allows() {
        let result = check_devtools(&cmd("ast-grep", &["-p", "pattern", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_ast_grep_update_asks() {
        let result = check_devtools(&cmd("ast-grep", &["-p", "old", "-r", "new", "-U", "src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_yq_read_allows() {
        let result = check_devtools(&cmd("yq", &[".key", "file.yaml"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_yq_inplace_asks() {
        let result = check_devtools(&cmd("yq", &["-i", ".key = \"val\"", "file.yaml"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_prettier_check_allows() {
        let result = check_devtools(&cmd("prettier", &["--check", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_prettier_write_asks() {
        let result = check_devtools(&cmd("prettier", &["--write", "src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === semgrep ===

    #[test]
    fn test_semgrep_scan_allows() {
        let result = check_devtools(&cmd("semgrep", &["--config", "auto", "."]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_semgrep_fix_asks() {
        let result = check_devtools(&cmd("semgrep", &["--config", "auto", "--autofix", "."]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === eslint ===

    #[test]
    fn test_eslint_check_allows() {
        let result = check_devtools(&cmd("eslint", &["src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_eslint_fix_asks() {
        let result = check_devtools(&cmd("eslint", &["--fix", "src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === black ===

    #[test]
    fn test_black_check_allows() {
        let result = check_devtools(&cmd("black", &["--check", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_black_format_asks() {
        let result = check_devtools(&cmd("black", &["src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === ruff (custom handler) ===

    #[test]
    fn test_ruff_check_allows() {
        let result = check_devtools(&cmd("ruff", &["check", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_ruff_check_fix_asks() {
        let result = check_devtools(&cmd("ruff", &["check", "--fix", "src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_ruff_format_asks() {
        let result = check_devtools(&cmd("ruff", &["format", "src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_ruff_format_check_allows() {
        let result = check_devtools(&cmd("ruff", &["format", "--check", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === Non-devtools ===

    #[test]
    fn test_non_devtools_skips() {
        let result = check_devtools(&cmd("git", &["status"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}
