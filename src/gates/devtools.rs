//! Developer tools permission gate (sd, sad, ast-grep, yq, semgrep, etc.).
//!
//! Uses declarative rules for flag-based conditional behavior.

use crate::generated::rules::{
    check_ast_grep_declarative, check_biome_declarative, check_black_declarative,
    check_comby_declarative, check_eslint_declarative, check_grit_declarative,
    check_isort_declarative, check_jq_declarative, check_prettier_declarative,
    check_ruff_declarative, check_sad_declarative, check_sd_declarative, check_semgrep_declarative,
    check_yq_declarative,
};
use crate::models::{CommandInfo, Decision, GateResult};

/// Check developer tools that can modify files.
pub fn check_devtools(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "sd" => check_sd_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("sd: In-place text replacement")),
        "sad" => check_sad(cmd),
        "ast-grep" => check_ast_grep(cmd),
        "yq" => check_yq(cmd),
        "jq" => check_jq_declarative(cmd).unwrap_or_else(GateResult::allow),
        "semgrep" => check_semgrep(cmd),
        "comby" => check_comby(cmd),
        "grit" => check_grit(cmd),
        "watchexec" => GateResult::ask("watchexec: Runs commands on file changes"),
        "biome" => check_biome(cmd),
        "prettier" => check_prettier(cmd),
        "eslint" => check_eslint(cmd),
        "ruff" => check_ruff(cmd),
        "black" => check_black(cmd),
        "isort" => check_isort(cmd),
        _ => GateResult::skip(),
    }
}

fn check_sad(cmd: &CommandInfo) -> GateResult {
    // Declarative handles --commit detection
    if let Some(result) = check_sad_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow) {
            return result;
        }
    }
    // Default: preview mode is safe
    GateResult::allow()
}

fn check_ast_grep(cmd: &CommandInfo) -> GateResult {
    if let Some(result) = check_ast_grep_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow) {
            return result;
        }
    }
    GateResult::allow()
}

fn check_yq(cmd: &CommandInfo) -> GateResult {
    if let Some(result) = check_yq_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow) {
            return result;
        }
    }
    GateResult::allow()
}

fn check_semgrep(cmd: &CommandInfo) -> GateResult {
    if let Some(result) = check_semgrep_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow) {
            return result;
        }
    }
    GateResult::allow()
}

fn check_comby(cmd: &CommandInfo) -> GateResult {
    if let Some(result) = check_comby_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow) {
            return result;
        }
    }
    GateResult::allow()
}

fn check_grit(cmd: &CommandInfo) -> GateResult {
    if let Some(result) = check_grit_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow) {
            return result;
        }
    }
    GateResult::allow()
}

fn check_biome(cmd: &CommandInfo) -> GateResult {
    if let Some(result) = check_biome_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow) {
            return result;
        }
    }
    GateResult::allow()
}

fn check_prettier(cmd: &CommandInfo) -> GateResult {
    if let Some(result) = check_prettier_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow) {
            return result;
        }
    }
    GateResult::allow()
}

fn check_eslint(cmd: &CommandInfo) -> GateResult {
    if let Some(result) = check_eslint_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow) {
            return result;
        }
    }
    GateResult::allow()
}

fn check_ruff(cmd: &CommandInfo) -> GateResult {
    if let Some(result) = check_ruff_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow) {
            return result;
        }
    }
    GateResult::allow()
}

fn check_black(cmd: &CommandInfo) -> GateResult {
    // Declarative handles --check/--diff detection
    check_black_declarative(cmd).unwrap_or_else(|| GateResult::ask("black: Formatting files"))
}

fn check_isort(cmd: &CommandInfo) -> GateResult {
    // Declarative handles --check/--check-only/--diff detection
    check_isort_declarative(cmd).unwrap_or_else(|| GateResult::ask("isort: Sorting imports"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;

    // === sd (always ask) ===

    #[test]
    fn test_sd_asks() {
        let result = check_devtools(&cmd("sd", &["old", "new", "file"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === sad ===

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

    // === ast-grep ===

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

    // === yq ===

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

    // === jq ===

    #[test]
    fn test_jq_allows() {
        let result = check_devtools(&cmd("jq", &[".key", "file.json"]));
        assert_eq!(result.decision, Decision::Allow);
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

    // === prettier ===

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

    // === ruff ===

    #[test]
    fn test_ruff_check_allows() {
        let result = check_devtools(&cmd("ruff", &["check", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_ruff_fix_asks() {
        let result = check_devtools(&cmd("ruff", &["check", "--fix", "src/"]));
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

    // === Non-devtools ===

    #[test]
    fn test_non_devtools_skips() {
        let result = check_devtools(&cmd("git", &["status"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}
