//! Package manager permission gates (npm, pnpm, yarn, pip, uv, cargo, go, conda).
//!
//! Uses declarative rules for most commands.

use crate::generated::rules::{
    check_bun_declarative, check_cargo_declarative, check_conda_declarative, check_go_declarative,
    check_npm_declarative, check_pip_declarative, check_pipx_declarative, check_pnpm_declarative,
    check_poetry_declarative, check_uv_declarative, check_yarn_declarative,
};
use crate::models::{CommandInfo, Decision, GateResult};

/// Check package manager commands.
pub fn check_package_managers(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
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
        _ => GateResult::skip(),
    }
}

fn check_npm(cmd: &CommandInfo) -> GateResult {
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
    fn test_uv_run_asks() {
        let result = check_package_managers(&cmd("uv", &["run", "python", "script.py"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_uv_pip_install_asks() {
        let result = check_package_managers(&cmd("uv", &["pip", "install", "requests"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Non-package-manager ===

    #[test]
    fn test_non_pm_skips() {
        let result = check_package_managers(&cmd("git", &["status"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}
