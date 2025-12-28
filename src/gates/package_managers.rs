//! Package manager permission gates (npm, pnpm, yarn, pip, uv, cargo, go, conda).
//!
//! Uses declarative rules for most commands.
//! Also handles package managers invoking dev tools (pnpm biome, npm eslint, etc.)

use crate::gates::devtools::check_devtools;
use crate::generated::rules::{
    check_bun_declarative, check_cargo_declarative, check_conda_declarative, check_go_declarative,
    check_mise_declarative, check_npm_declarative, check_pip_declarative, check_pipx_declarative,
    check_pnpm_declarative, check_poetry_declarative, check_uv_declarative, check_yarn_declarative,
};
use crate::models::{CommandInfo, Decision, GateResult};

/// Check package manager commands.
pub fn check_package_managers(cmd: &CommandInfo) -> GateResult {
    // Strip path prefix to handle /usr/bin/npm etc.
    let program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);
    match program {
        "npm" => check_npm(cmd),
        "pnpm" => check_pnpm(cmd),
        "yarn" => check_yarn(cmd),
        "pip" | "pip3" => check_pip(cmd),
        "uv" => check_uv(cmd),
        "cargo" => check_cargo(cmd),
        "go" => check_go(cmd),
        "bun" => check_bun(cmd),
        "conda" | "mamba" | "micromamba" => check_conda(cmd),
        "poetry" => check_poetry(cmd),
        "pipx" => check_pipx(cmd),
        "pdm" => check_pdm(cmd),
        "hatch" => check_hatch(cmd),
        "mise" => check_mise(cmd),
        _ => GateResult::skip(),
    }
}

fn check_npm(cmd: &CommandInfo) -> GateResult {
    // Check if npm is invoking a known dev tool (npm eslint, npm prettier, etc.)
    if let Some(result) = check_invoked_devtool(cmd, "npm") {
        return result;
    }

    if let Some(result) = check_npm_declarative(cmd) {
        // Don't auto-allow unknown commands
        if !matches!(result.decision, Decision::Allow)
            || has_known_subcommand(
                cmd,
                &[
                    "list",
                    "ls",
                    "outdated",
                    "audit",
                    "run",
                    "test",
                    "start",
                    "build",
                    "--version",
                    "-v",
                    "--help",
                    "-h",
                ],
            )
        {
            return result;
        }
    }
    GateResult::ask(format!(
        "npm: {}",
        cmd.args.first().unwrap_or(&"unknown".to_string())
    ))
}

fn check_pnpm(cmd: &CommandInfo) -> GateResult {
    // Check if pnpm is invoking a known dev tool (pnpm biome, pnpm eslint, etc.)
    if let Some(result) = check_invoked_devtool(cmd, "pnpm") {
        return result;
    }

    if let Some(result) = check_pnpm_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow)
            || has_known_subcommand(
                cmd,
                &[
                    "list",
                    "ls",
                    "outdated",
                    "audit",
                    "run",
                    "test",
                    "start",
                    "build",
                    "dev",
                    "--version",
                    "-v",
                    "--help",
                    "-h",
                ],
            )
        {
            return result;
        }
    }
    GateResult::ask(format!(
        "pnpm: {}",
        cmd.args.first().unwrap_or(&"unknown".to_string())
    ))
}

fn check_yarn(cmd: &CommandInfo) -> GateResult {
    // Check if yarn is invoking a known dev tool (yarn eslint, yarn prettier, etc.)
    if let Some(result) = check_invoked_devtool(cmd, "yarn") {
        return result;
    }

    if let Some(result) = check_yarn_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow)
            || has_known_subcommand(
                cmd,
                &[
                    "list",
                    "info",
                    "outdated",
                    "audit",
                    "run",
                    "test",
                    "start",
                    "build",
                    "--version",
                    "-v",
                    "--help",
                    "-h",
                ],
            )
        {
            return result;
        }
    }
    GateResult::ask(format!(
        "yarn: {}",
        cmd.args.first().unwrap_or(&"unknown".to_string())
    ))
}

fn check_pip(cmd: &CommandInfo) -> GateResult {
    // --dry-run is safe
    if cmd.args.iter().any(|a| a == "--dry-run") {
        return GateResult::allow();
    }

    if let Some(result) = check_pip_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow)
            || has_known_subcommand(
                cmd,
                &[
                    "list",
                    "show",
                    "freeze",
                    "check",
                    "--version",
                    "-V",
                    "--help",
                    "-h",
                ],
            )
        {
            return result;
        }
    }
    GateResult::ask(format!(
        "pip: {}",
        cmd.args.first().unwrap_or(&"unknown".to_string())
    ))
}

fn check_uv(cmd: &CommandInfo) -> GateResult {
    // Check if uv is running a command (uv run pytest, etc.)
    if let Some(result) = check_python_run_command(cmd, "uv") {
        return result;
    }

    if let Some(result) = check_uv_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow)
            || has_known_subcommand(
                cmd,
                &[
                    "pip list",
                    "pip show",
                    "pip freeze",
                    "pip check",
                    "run",
                    "sync",
                    "--version",
                    "-V",
                    "--help",
                    "-h",
                ],
            )
        {
            return result;
        }
    }
    GateResult::ask(format!(
        "uv: {}",
        cmd.args.first().unwrap_or(&"unknown".to_string())
    ))
}

fn check_cargo(cmd: &CommandInfo) -> GateResult {
    if let Some(result) = check_cargo_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow)
            || has_known_subcommand(
                cmd,
                &[
                    "check",
                    "test",
                    "build",
                    "run",
                    "clippy",
                    "fmt",
                    "doc",
                    "tree",
                    "metadata",
                    "--version",
                    "-V",
                    "--help",
                    "-h",
                ],
            )
        {
            return result;
        }
    }
    GateResult::ask(format!(
        "cargo: {}",
        cmd.args.first().unwrap_or(&"unknown".to_string())
    ))
}

fn check_go(cmd: &CommandInfo) -> GateResult {
    if let Some(result) = check_go_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow)
            || has_known_subcommand(
                cmd,
                &[
                    "build", "test", "run", "fmt", "vet", "list", "mod tidy", "version", "doc",
                    "env", "--help", "-h",
                ],
            )
        {
            return result;
        }
    }
    GateResult::ask(format!(
        "go: {}",
        cmd.args.first().unwrap_or(&"unknown".to_string())
    ))
}

fn check_bun(cmd: &CommandInfo) -> GateResult {
    if let Some(result) = check_bun_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow)
            || has_known_subcommand(
                cmd,
                &["run", "test", "build", "--version", "-v", "--help", "-h"],
            )
        {
            return result;
        }
    }
    GateResult::ask(format!(
        "bun: {}",
        cmd.args.first().unwrap_or(&"unknown".to_string())
    ))
}

fn check_conda(cmd: &CommandInfo) -> GateResult {
    if let Some(result) = check_conda_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow)
            || has_known_subcommand(
                cmd,
                &[
                    "list",
                    "info",
                    "search",
                    "env list",
                    "--version",
                    "-V",
                    "--help",
                    "-h",
                ],
            )
        {
            return result;
        }
    }
    GateResult::ask(format!(
        "conda: {}",
        cmd.args.first().unwrap_or(&"unknown".to_string())
    ))
}

fn check_poetry(cmd: &CommandInfo) -> GateResult {
    // Check if poetry is running a command (poetry run pytest, etc.)
    if let Some(result) = check_python_run_command(cmd, "poetry") {
        return result;
    }

    if let Some(result) = check_poetry_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow)
            || has_known_subcommand(
                cmd,
                &[
                    "show",
                    "check",
                    "run",
                    "shell",
                    "env list",
                    "env info",
                    "env activate",
                    "--version",
                    "-V",
                    "--help",
                    "-h",
                ],
            )
        {
            return result;
        }
    }
    GateResult::ask(format!(
        "poetry: {}",
        cmd.args.first().unwrap_or(&"unknown".to_string())
    ))
}

fn check_pipx(cmd: &CommandInfo) -> GateResult {
    // Check if pipx is running a command (pipx run ruff, etc.)
    if let Some(result) = check_python_run_command(cmd, "pipx") {
        return result;
    }

    if let Some(result) = check_pipx_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow)
            || has_known_subcommand(cmd, &["list", "run", "--version", "--help"])
        {
            return result;
        }
    }
    GateResult::ask(format!(
        "pipx: {}",
        cmd.args.first().unwrap_or(&"unknown".to_string())
    ))
}

fn check_pdm(cmd: &CommandInfo) -> GateResult {
    // Check if pdm is running a command (pdm run pytest, etc.)
    if let Some(result) = check_python_run_command(cmd, "pdm") {
        return result;
    }

    // PDM subcommands
    if cmd.args.is_empty() {
        return GateResult::ask("pdm: No subcommand");
    }

    match cmd.args[0].as_str() {
        // Read-only
        "list" | "show" | "info" | "search" | "config" | "self" | "--version" | "-V" | "--help"
        | "-h" => GateResult::allow(),
        // Package operations
        "add" | "remove" | "update" | "sync" | "install" => {
            GateResult::ask(format!("pdm: {}", cmd.args[0]))
        }
        // Build/publish
        "build" => GateResult::allow(),
        "publish" => GateResult::ask("pdm: Publishing package"),
        // Run is handled above
        "run" => GateResult::allow(),
        _ => GateResult::ask(format!("pdm: {}", cmd.args[0])),
    }
}

fn check_hatch(cmd: &CommandInfo) -> GateResult {
    // Check if hatch is running a command (hatch run pytest, etc.)
    if let Some(result) = check_python_run_command(cmd, "hatch") {
        return result;
    }

    // Hatch subcommands
    if cmd.args.is_empty() {
        return GateResult::ask("hatch: No subcommand");
    }

    match cmd.args[0].as_str() {
        // Read-only
        "version" | "status" | "env" | "config" | "--version" | "-V" | "--help" | "-h" => {
            GateResult::allow()
        }
        // Build/test - generally safe
        "build" | "test" | "fmt" | "clean" => GateResult::allow(),
        // Publish
        "publish" => GateResult::ask("hatch: Publishing package"),
        // Run is handled above
        "run" => GateResult::allow(),
        // Shell opens an interactive shell
        "shell" => GateResult::ask("hatch: Opening shell"),
        _ => GateResult::ask(format!("hatch: {}", cmd.args[0])),
    }
}

fn check_mise(cmd: &CommandInfo) -> GateResult {
    // mise exec <command> - check the underlying command
    if !cmd.args.is_empty() && (cmd.args[0] == "exec" || cmd.args[0] == "x") {
        if cmd.args.len() >= 2 {
            // Find where the command starts (after exec and any flags)
            let mut cmd_start = 1;
            while cmd_start < cmd.args.len() {
                let arg = &cmd.args[cmd_start];
                // Skip flags (but -- ends flag processing)
                if arg == "--" {
                    cmd_start += 1;
                    break;
                }
                if arg.starts_with('-') {
                    cmd_start += 1;
                    continue;
                }
                break;
            }

            if cmd_start < cmd.args.len() {
                // Check if executing a known dev tool
                let tool_cmd = CommandInfo {
                    program: cmd.args[cmd_start].clone(),
                    args: cmd.args[cmd_start + 1..].to_vec(),
                    raw: cmd.raw.clone(),
                };
                let result = check_devtools(&tool_cmd);
                if !matches!(result.decision, Decision::Skip) {
                    return result;
                }
            }
        }
        return GateResult::allow();
    }

    // Use declarative rules for other mise commands
    if let Some(result) = check_mise_declarative(cmd) {
        if !matches!(result.decision, Decision::Allow)
            || has_known_subcommand(
                cmd,
                &[
                    "ls",
                    "list",
                    "current",
                    "where",
                    "which",
                    "env",
                    "version",
                    "doctor",
                    "reshim",
                    "trust",
                    "exec",
                    "--version",
                    "-V",
                    "--help",
                    "-h",
                ],
            )
        {
            return result;
        }
    }

    GateResult::ask(format!(
        "mise: {}",
        cmd.args.first().unwrap_or(&"".to_string())
    ))
}

/// Check if command has a known subcommand
fn has_known_subcommand(cmd: &CommandInfo, known: &[&str]) -> bool {
    if cmd.args.is_empty() {
        return false;
    }
    let first = cmd.args[0].as_str();
    let two_word = if cmd.args.len() >= 2 {
        format!("{} {}", cmd.args[0], cmd.args[1])
    } else {
        String::new()
    };
    known.contains(&first) || known.contains(&two_word.as_str())
}

/// Check if a Python tool is running a command via "run" subcommand.
/// Extracts the underlying command and checks it through devtools gate.
/// Works for: uv run, poetry run, pdm run, pipx run, hatch run
fn check_python_run_command(cmd: &CommandInfo, pm_name: &str) -> Option<GateResult> {
    // Must have at least: <pm> run <command>
    if cmd.args.len() < 2 {
        return None;
    }

    // Check if first arg is "run"
    if cmd.args[0] != "run" {
        return None;
    }

    // Skip any flags before the actual command (e.g., uv run --quiet pytest)
    let mut cmd_start_idx = 1;
    while cmd_start_idx < cmd.args.len() && cmd.args[cmd_start_idx].starts_with('-') {
        cmd_start_idx += 1;
        // Handle flags with values like --python 3.11
        if cmd_start_idx < cmd.args.len() && !cmd.args[cmd_start_idx].starts_with('-') {
            // Check if previous flag takes a value
            let prev_flag = &cmd.args[cmd_start_idx - 1];
            if matches!(
                prev_flag.as_str(),
                "--python" | "-p" | "--with" | "--env" | "-e"
            ) {
                cmd_start_idx += 1;
            }
        }
    }

    if cmd_start_idx >= cmd.args.len() {
        return None;
    }

    let run_cmd = &cmd.args[cmd_start_idx];
    let run_args = &cmd.args[cmd_start_idx + 1..];

    // Build a synthetic command for the devtools gate
    let tool_cmd = CommandInfo {
        raw: cmd.raw.clone(),
        program: run_cmd.to_string(),
        args: run_args.to_vec(),
    };

    // Try devtools gate first
    let result = check_devtools(&tool_cmd);

    if result.decision != Decision::Skip {
        return Some(GateResult {
            decision: result.decision,
            reason: result
                .reason
                .map(|r| format!("{pm_name} run {run_cmd}: {r}")),
        });
    }

    // For Python-specific tools not in devtools, check common patterns
    match run_cmd.as_str() {
        // Test runners - safe
        "pytest" | "py.test" | "unittest" | "nose" | "nose2" | "ward" | "hypothesis" => {
            Some(GateResult::allow())
        }
        // Type checkers - safe
        "mypy" | "pyright" | "pytype" | "pyre" => Some(GateResult::allow()),
        // Build tools - safe
        "build" | "flit" | "hatchling" | "maturin" | "setuptools" => Some(GateResult::allow()),
        // Documentation - safe
        "sphinx-build" | "mkdocs" | "pdoc" => Some(GateResult::allow()),
        // Unknown - let it through (will be caught by basics gate or ask)
        _ => None,
    }
}

/// Known dev tools that can be invoked via package managers (pnpm biome, npm eslint, etc.)
const DEV_TOOLS: &[&str] = &[
    "biome",
    "eslint",
    "prettier",
    "tsc",
    "typescript",
    "tsup",
    "vite",
    "vitest",
    "jest",
    "mocha",
    "ava",
    "esbuild",
    "rollup",
    "webpack",
    "turbo",
    "nx",
    "stylelint",
    "oxlint",
    "knip",
    "depcheck",
    "madge",
    "size-limit",
];

/// Check if package manager is invoking a known dev tool.
/// If so, delegate to devtools gate to determine if it's safe.
fn check_invoked_devtool(cmd: &CommandInfo, pm_name: &str) -> Option<GateResult> {
    if cmd.args.is_empty() {
        return None;
    }

    let tool = cmd.args[0].as_str();
    if !DEV_TOOLS.contains(&tool) {
        return None;
    }

    // Build a synthetic command for the devtools gate
    let tool_cmd = CommandInfo {
        raw: cmd.raw.clone(),
        program: tool.to_string(),
        args: cmd.args[1..].to_vec(),
    };

    let result = check_devtools(&tool_cmd);

    // If devtools gate handles it (not Skip), use that result
    if result.decision != Decision::Skip {
        // Prefix the reason with the package manager name
        return Some(GateResult {
            decision: result.decision,
            reason: result.reason.map(|r| format!("{pm_name} {tool}: {r}")),
        });
    }

    // For tools devtools doesn't handle, allow by default (read-only tools)
    Some(GateResult::allow())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;

    // === npm ===

    #[test]
    fn test_npm_read_allows() {
        let allow_cmds = [&["list"][..], &["ls"], &["outdated"], &["--version"]];
        for args in allow_cmds {
            let result = check_package_managers(&cmd("npm", args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_npm_run_asks() {
        let result = check_package_managers(&cmd("npm", &["run", "build"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_npm_install_asks() {
        let result = check_package_managers(&cmd("npm", &["install"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === devtool invocation (pnpm biome, npm eslint, etc.) ===

    #[test]
    fn test_pnpm_biome_check_allows() {
        let result = check_package_managers(&cmd("pnpm", &["biome", "check", "."]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_pnpm_biome_format_write_asks() {
        let result = check_package_managers(&cmd("pnpm", &["biome", "format", "--write", "."]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.unwrap().contains("Formatting"));
    }

    #[test]
    fn test_pnpm_eslint_allows() {
        let result = check_package_managers(&cmd("pnpm", &["eslint", "src/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_pnpm_eslint_fix_asks() {
        let result = check_package_managers(&cmd("pnpm", &["eslint", "--fix", "src/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_npm_prettier_check_allows() {
        let result = check_package_managers(&cmd("npm", &["prettier", "--check", "."]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_yarn_tsc_allows() {
        let result = check_package_managers(&cmd("yarn", &["tsc", "--noEmit"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === cargo ===

    #[test]
    fn test_cargo_build_allows() {
        let allow_cmds = [&["build"][..], &["test"], &["check"], &["clippy"], &["run"]];
        for args in allow_cmds {
            let result = check_package_managers(&cmd("cargo", args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_cargo_install_asks() {
        let result = check_package_managers(&cmd("cargo", &["install", "ripgrep"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === pip ===

    #[test]
    fn test_pip_list_allows() {
        let allow_cmds = [
            &["list"][..],
            &["show", "requests"],
            &["freeze"],
            &["--version"],
        ];
        for args in allow_cmds {
            let result = check_package_managers(&cmd("pip", args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_pip_install_asks() {
        let result = check_package_managers(&cmd("pip", &["install", "requests"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_pip_dry_run_allows() {
        let result = check_package_managers(&cmd("pip", &["install", "--dry-run", "requests"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === uv ===

    #[test]
    fn test_uv_run_python_asks() {
        // Running arbitrary Python scripts asks
        let result = check_package_managers(&cmd("uv", &["run", "python", "script.py"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_uv_run_pytest_allows() {
        let result = check_package_managers(&cmd("uv", &["run", "pytest"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_uv_run_ruff_check_allows() {
        let result = check_package_managers(&cmd("uv", &["run", "ruff", "check", "."]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_uv_run_ruff_fix_asks() {
        let result = check_package_managers(&cmd("uv", &["run", "ruff", "check", "--fix", "."]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_uv_pip_install_asks() {
        let result = check_package_managers(&cmd("uv", &["pip", "install", "requests"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === poetry ===

    #[test]
    fn test_poetry_run_pytest_allows() {
        let result = check_package_managers(&cmd("poetry", &["run", "pytest"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_poetry_run_black_check_allows() {
        let result = check_package_managers(&cmd("poetry", &["run", "black", "--check", "."]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_poetry_run_black_asks() {
        let result = check_package_managers(&cmd("poetry", &["run", "black", "."]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === pdm ===

    #[test]
    fn test_pdm_run_pytest_allows() {
        let result = check_package_managers(&cmd("pdm", &["run", "pytest"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_pdm_list_allows() {
        let result = check_package_managers(&cmd("pdm", &["list"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === hatch ===

    #[test]
    fn test_hatch_run_pytest_allows() {
        let result = check_package_managers(&cmd("hatch", &["run", "pytest"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_hatch_test_allows() {
        let result = check_package_managers(&cmd("hatch", &["test"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    // === Non-package-manager ===

    #[test]
    fn test_non_pm_skips() {
        let result = check_package_managers(&cmd("git", &["status"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}
