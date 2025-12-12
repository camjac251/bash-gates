//! Developer tools permission gate (sd, sad, ast-grep, yq, semgrep, etc.).

use crate::models::{CommandInfo, GateResult};

/// Check developer tools that can modify files.
pub fn check_devtools(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "sd" => GateResult::ask("sd: In-place text replacement"),
        "sad" => check_sad(cmd),
        "ast-grep" => check_ast_grep(cmd),
        "yq" => check_yq(cmd),
        "jq" => GateResult::allow(),
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
    if cmd.args.iter().any(|a| a == "--commit") {
        GateResult::ask("sad: Applying replacements")
    } else {
        GateResult::allow()
    }
}

fn check_ast_grep(cmd: &CommandInfo) -> GateResult {
    if cmd.args.iter().any(|a| a == "-U" || a == "--update-all") {
        GateResult::ask("ast-grep: Rewriting code")
    } else {
        GateResult::allow()
    }
}

fn check_yq(cmd: &CommandInfo) -> GateResult {
    if cmd.args.iter().any(|a| a == "-i" || a == "--inplace") {
        GateResult::ask("yq: In-place YAML edit")
    } else {
        GateResult::allow()
    }
}

fn check_semgrep(cmd: &CommandInfo) -> GateResult {
    if cmd.args.iter().any(|a| a == "--autofix" || a == "--fix") {
        GateResult::ask("semgrep: Auto-fixing code")
    } else {
        GateResult::allow()
    }
}

fn check_comby(cmd: &CommandInfo) -> GateResult {
    if cmd.args.iter().any(|a| a == "-in-place" || a == "-i") {
        GateResult::ask("comby: In-place replacement")
    } else {
        GateResult::allow()
    }
}

fn check_grit(cmd: &CommandInfo) -> GateResult {
    if cmd.args.first().map(std::string::String::as_str) == Some("apply") {
        GateResult::ask("grit: Applying migrations")
    } else {
        GateResult::allow()
    }
}

fn check_biome(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    let has_check = args.iter().any(|a| a == "check");
    let has_format = args.iter().any(|a| a == "format");
    let has_write = args.iter().any(|a| a == "--write");

    if has_check && has_write {
        GateResult::ask("biome: Writing fixes")
    } else if has_format && has_write {
        GateResult::ask("biome: Formatting files")
    } else {
        GateResult::allow()
    }
}

fn check_prettier(cmd: &CommandInfo) -> GateResult {
    if cmd.args.iter().any(|a| a == "--write" || a == "-w") {
        GateResult::ask("prettier: Writing formatted files")
    } else {
        GateResult::allow()
    }
}

fn check_eslint(cmd: &CommandInfo) -> GateResult {
    if cmd.args.iter().any(|a| a == "--fix") {
        GateResult::ask("eslint: Auto-fixing")
    } else {
        GateResult::allow()
    }
}

fn check_ruff(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    let has_check = args.iter().any(|a| a == "check");
    let has_format = args.iter().any(|a| a == "format");
    let has_fix = args.iter().any(|a| a == "--fix");
    let has_check_only = args.iter().any(|a| a == "--check" || a == "--diff");

    if has_check && has_fix {
        GateResult::ask("ruff: Auto-fixing")
    } else if has_format && !has_check_only {
        let non_flag_count = args.iter().filter(|a| !a.starts_with('-')).count();
        if non_flag_count > 1 {
            GateResult::ask("ruff: Formatting files")
        } else {
            GateResult::allow()
        }
    } else {
        GateResult::allow()
    }
}

fn check_black(cmd: &CommandInfo) -> GateResult {
    if cmd.args.iter().any(|a| a == "--check" || a == "--diff") {
        GateResult::allow()
    } else {
        GateResult::ask("black: Formatting files")
    }
}

fn check_isort(cmd: &CommandInfo) -> GateResult {
    if cmd
        .args
        .iter()
        .any(|a| a == "--check" || a == "--check-only" || a == "--diff")
    {
        GateResult::allow()
    } else {
        GateResult::ask("isort: Sorting imports")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Decision;

    fn cmd(program: &str, args: &[&str]) -> CommandInfo {
        CommandInfo {
            raw: format!("{} {}", program, args.join(" ")),
            program: program.to_string(),
            args: args.iter().map(std::string::ToString::to_string).collect(),
            is_subshell: false,
            is_pipeline: false,
            pipeline_position: 0,
        }
    }

    // === sd ===

    #[test]
    fn test_sd_always_asks() {
        let result = check_devtools(&cmd("sd", &["old", "new", "file.txt"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("In-place"));
    }

    // === sad ===

    #[test]
    fn test_sad_preview_allows() {
        let result = check_devtools(&cmd("sad", &["old", "new", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_sad_commit_asks() {
        let result = check_devtools(&cmd("sad", &["old", "new", "src/", "--commit"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Applying"));
    }

    // === ast-grep ===

    #[test]
    fn test_ast_grep_search_allows() {
        for args in [
            &["-p", "console.log", "src/"][..],
            &["scan", "--rule", "rules.yml"],
            &["-p", "function $NAME", "."],
        ] {
            let result = check_devtools(&cmd("ast-grep", args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_ast_grep_rewrite_asks() {
        for args in [
            &["-p", "old", "-r", "new", "-U", "src/"][..],
            &["-p", "console.log", "-r", "", "--update-all", "src/"],
        ] {
            let result = check_devtools(&cmd("ast-grep", args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
            assert!(result.reason.as_ref().unwrap().contains("Rewriting"));
        }
    }

    // === yq ===

    #[test]
    fn test_yq_query_allows() {
        let result = check_devtools(&cmd("yq", &[".version", "chart.yaml"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_yq_inplace_asks() {
        for args in [
            &["-i", ".version = \"2.0\"", "chart.yaml"][..],
            &["--inplace", ".replicas = 3", "deployment.yaml"],
        ] {
            let result = check_devtools(&cmd("yq", args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
            assert!(result.reason.as_ref().unwrap().contains("In-place"));
        }
    }

    // === jq ===

    #[test]
    fn test_jq_always_allows() {
        let result = check_devtools(&cmd("jq", &[".name", "package.json"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === semgrep ===

    #[test]
    fn test_semgrep_scan_allows() {
        for args in [
            &["--config", "auto", "."][..],
            &["scan", "--config", "p/security-audit"],
            &["--config", "p/python", "src/"],
        ] {
            let result = check_devtools(&cmd("semgrep", args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_semgrep_autofix_asks() {
        for args in [
            &["--config", "auto", "--autofix", "."][..],
            &["--config", "p/python", "--fix", "src/"],
        ] {
            let result = check_devtools(&cmd("semgrep", args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
            assert!(result.reason.as_ref().unwrap().contains("Auto-fixing"));
        }
    }

    // === comby ===

    #[test]
    fn test_comby_match_allows() {
        let result = check_devtools(&cmd("comby", &[":[x]", ":[x]", ".go"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_comby_inplace_asks() {
        for flag in ["-in-place", "-i"] {
            let result = check_devtools(&cmd("comby", &["old", "new", flag, ".go"]));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {flag}");
        }
    }

    // === grit ===

    #[test]
    fn test_grit_check_allows() {
        let result = check_devtools(&cmd("grit", &["check"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_grit_apply_asks() {
        let result = check_devtools(&cmd("grit", &["apply", "migration"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Applying"));
    }

    // === watchexec ===

    #[test]
    fn test_watchexec_asks() {
        let result = check_devtools(&cmd("watchexec", &["-e", "rs", "cargo", "test"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().to_lowercase().contains("commands"));
    }

    // === biome ===

    #[test]
    fn test_biome_check_allows() {
        for args in [
            &["check", "src/"][..],
            &["lint", "src/"],
            &["format", "--check", "src/"],
        ] {
            let result = check_devtools(&cmd("biome", args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_biome_write_asks() {
        for args in [
            &["check", "--write", "src/"][..],
            &["format", "--write", "src/"],
        ] {
            let result = check_devtools(&cmd("biome", args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
        }
    }

    // === prettier ===

    #[test]
    fn test_prettier_check_allows() {
        let result = check_devtools(&cmd("prettier", &["--check", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_prettier_write_asks() {
        for flag in ["--write", "-w"] {
            let result = check_devtools(&cmd("prettier", &[flag, "src/"]));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {flag}");
        }
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
        assert!(result.reason.as_ref().unwrap().contains("Auto-fixing"));
    }

    // === ruff ===

    #[test]
    fn test_ruff_check_allows() {
        for args in [
            &["check", "src/"][..],
            &["format", "--check", "src/"],
            &["format", "--diff", "src/"],
        ] {
            let result = check_devtools(&cmd("ruff", args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_ruff_fix_asks() {
        let result = check_devtools(&cmd("ruff", &["check", "--fix", "src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === black ===

    #[test]
    fn test_black_check_allows() {
        for args in [&["--check", "src/"][..], &["--diff", "src/"]] {
            let result = check_devtools(&cmd("black", args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_black_format_asks() {
        let result = check_devtools(&cmd("black", &["src/"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Formatting"));
    }

    // === isort ===

    #[test]
    fn test_isort_check_allows() {
        for args in [
            &["--check", "src/"][..],
            &["--check-only", "src/"],
            &["--diff", "src/"],
        ] {
            let result = check_devtools(&cmd("isort", args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_isort_sort_asks() {
        let result = check_devtools(&cmd("isort", &["src/"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Sorting"));
    }
}
