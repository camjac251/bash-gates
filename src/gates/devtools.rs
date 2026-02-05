//! Developer tools permission gate.
//!
//! Mostly declarative via rules/devtools.toml.
//!
//! Custom handler for `sd`: without file args it's a stdin→stdout pipe
//! filter (safe), with file args it modifies files in-place (ask).

use crate::generated::rules::check_devtools_gate;
use crate::models::{CommandInfo, Decision, GateResult};

/// Check if `sd` is being used as a pipe filter (no file args) or in-place editor.
///
/// Note: tree-sitter-bash drops bare numbers from args (e.g., `sd -n 5 old new`
/// becomes args=["-n", "old", "new"]), so we can't reliably track value-consuming
/// flags. Instead we simply skip all dash-prefixed args and count the rest.
fn check_sd(cmd: &CommandInfo) -> GateResult {
    // --preview/-p is always safe (dry run)
    if cmd.args.iter().any(|a| a == "-p" || a == "--preview") {
        return GateResult::allow();
    }

    // Count positional args, skipping flags.
    // After "--", all remaining args are positional.
    let mut positional = 0;
    let mut seen_double_dash = false;
    for arg in &cmd.args {
        if !seen_double_dash && arg == "--" {
            seen_double_dash = true;
            continue;
        }
        if !seen_double_dash && arg.starts_with('-') {
            continue;
        }
        positional += 1;
    }

    // sd FIND REPLACE [FILES...] — 2 positional = pipe mode, 3+ = file mode
    if positional <= 2 {
        GateResult::allow()
    } else {
        GateResult::ask("sd: In-place text replacement")
    }
}

/// Check developer tools that can modify files.
pub fn check_devtools(cmd: &CommandInfo) -> GateResult {
    let result = check_devtools_gate(cmd);
    if result.decision == Decision::Skip && cmd.program == "sd" {
        return check_sd(cmd);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;
    // === sd (pipe mode vs in-place) ===

    #[test]
    fn test_sd_with_file_asks() {
        let result = check_devtools(&cmd("sd", &["old", "new", "file"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_sd_pipe_mode_allows() {
        // No file args = stdin→stdout filter
        let result = check_devtools(&cmd("sd", &["old", "new"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_sd_pipe_mode_with_flags_allows() {
        let result = check_devtools(&cmd("sd", &["-F", "old", "new"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_sd_preview_allows() {
        let result = check_devtools(&cmd("sd", &["-p", "old", "new", "file"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_sd_multiple_files_asks() {
        let result = check_devtools(&cmd("sd", &["old", "new", "a.txt", "b.txt"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_sd_long_value_flag_with_file_asks() {
        // tree-sitter drops bare "5", so args = ["--max-replacements", "old", "new", "file.txt"]
        let result = check_devtools(&cmd(
            "sd",
            &["--max-replacements", "old", "new", "file.txt"],
        ));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_sd_double_dash_with_file_asks() {
        // After --, all args are positional: -old, new, file.txt = 3
        let result = check_devtools(&cmd("sd", &["--", "-old", "new", "file.txt"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_sd_double_dash_pipe_mode_allows() {
        // After --, -old and new = 2 positional (pipe mode)
        let result = check_devtools(&cmd("sd", &["--", "-old", "new"]));
        assert_eq!(result.decision, Decision::Allow);
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
