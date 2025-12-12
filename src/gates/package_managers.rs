//! Package manager permission gates (npm, pnpm, yarn, pip, uv, cargo, go, conda).

use crate::models::{CommandInfo, GateResult};
use std::sync::LazyLock;
use std::collections::{HashMap, HashSet};

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

// === NPM ===

static NPM_READ: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list", "ls", "ll", "la", "view", "show", "info", "search", "help", "config", "get",
        "prefix", "root", "bin", "whoami", "token", "team", "outdated", "doctor", "explain", "why",
        "fund", "audit", "query", "-v", "--version", "-h", "--help",
    ]
    .into_iter()
    .collect()
});

static NPM_SAFE_LOCAL: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "run",
        "run-script",
        "start",
        "test",
        "build",
        "dev",
        "lint",
        "check",
        "typecheck",
        "format",
        "prettier",
        "eslint",
        "tsc",
    ]
    .into_iter()
    .collect()
});

static NPM_RISKY: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing packages"),
        ("i", "Installing packages"),
        ("add", "Installing packages"),
        ("ci", "Clean install"),
        ("uninstall", "Uninstalling packages"),
        ("remove", "Uninstalling packages"),
        ("rm", "Uninstalling packages"),
        ("un", "Uninstalling packages"),
        ("update", "Updating packages"),
        ("up", "Updating packages"),
        ("upgrade", "Updating packages"),
        ("link", "Linking package"),
        ("unlink", "Unlinking package"),
        ("publish", "Publishing package"),
        ("unpublish", "Unpublishing package"),
        ("deprecate", "Deprecating package"),
        ("init", "Initializing package"),
        ("create", "Creating package"),
        ("exec", "Executing package"),
        ("npx", "Executing package"),
        ("prune", "Pruning packages"),
        ("dedupe", "Deduplicating"),
        ("shrinkwrap", "Locking dependencies"),
        ("cache", "Cache operation"),
        ("pack", "Creating tarball"),
        ("set", "Setting config"),
    ]
    .into_iter()
    .collect()
});

fn check_npm(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    if NPM_READ.contains(subcmd) || NPM_SAFE_LOCAL.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = NPM_RISKY.get(subcmd) {
        return GateResult::ask(format!("npm: {reason}"));
    }

    GateResult::allow()
}

// === PNPM ===

fn check_pnpm(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    let read_cmds: HashSet<&str> = ["list", "ls", "ll", "why", "outdated", "audit", "-v", "--version", "-h", "--help"]
        .into_iter()
        .collect();

    let safe_local: HashSet<&str> = [
        "run", "start", "test", "build", "dev", "lint", "check", "typecheck", "format", "tsc",
        "exec",
    ]
    .into_iter()
    .collect();

    let risky_cmds: HashMap<&str, &str> = [
        ("install", "Installing packages"),
        ("i", "Installing packages"),
        ("add", "Adding packages"),
        ("remove", "Removing packages"),
        ("rm", "Removing packages"),
        ("uninstall", "Removing packages"),
        ("update", "Updating packages"),
        ("up", "Updating packages"),
        ("link", "Linking package"),
        ("unlink", "Unlinking package"),
        ("publish", "Publishing package"),
        ("init", "Initializing package"),
        ("create", "Creating package"),
        ("dlx", "Executing package"),
        ("prune", "Pruning packages"),
        ("store", "Store operation"),
        ("patch", "Patching package"),
    ]
    .into_iter()
    .collect();

    if read_cmds.contains(subcmd) || safe_local.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = risky_cmds.get(subcmd) {
        return GateResult::ask(format!("pnpm: {reason}"));
    }

    GateResult::allow()
}

// === YARN ===

fn check_yarn(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        // bare yarn = install
        return GateResult::ask("yarn: Installing packages");
    }

    let subcmd = args[0].as_str();

    let read_cmds: HashSet<&str> = ["list", "info", "why", "outdated", "audit", "config", "-v", "--version", "-h", "--help"]
        .into_iter()
        .collect();

    let safe_local: HashSet<&str> = [
        "run", "start", "test", "build", "dev", "lint", "check", "typecheck", "format", "exec",
    ]
    .into_iter()
    .collect();

    let risky_cmds: HashMap<&str, &str> = [
        ("install", "Installing packages"),
        ("add", "Adding packages"),
        ("remove", "Removing packages"),
        ("upgrade", "Upgrading packages"),
        ("upgrade-interactive", "Upgrading packages"),
        ("link", "Linking package"),
        ("unlink", "Unlinking package"),
        ("publish", "Publishing package"),
        ("init", "Initializing package"),
        ("create", "Creating package"),
        ("dlx", "Executing package"),
        ("cache", "Cache operation"),
        ("global", "Global operation"),
        ("set", "Setting config"),
    ]
    .into_iter()
    .collect();

    if read_cmds.contains(subcmd) || safe_local.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = risky_cmds.get(subcmd) {
        return GateResult::ask(format!("yarn: {reason}"));
    }

    GateResult::allow()
}

// === PIP ===

fn check_pip(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    let read_cmds: HashSet<&str> = [
        "list", "show", "freeze", "check", "search", "index", "config", "cache", "debug", "-V",
        "--version", "-h", "--help",
    ]
    .into_iter()
    .collect();

    let write_cmds: HashMap<&str, &str> = [
        ("install", "Installing packages"),
        ("uninstall", "Uninstalling packages"),
        ("download", "Downloading packages"),
        ("wheel", "Building wheel"),
    ]
    .into_iter()
    .collect();

    // pip install with --dry-run is safe
    if subcmd == "install" && args.iter().any(|a| a == "--dry-run" || a == "-n") {
        return GateResult::allow();
    }

    if read_cmds.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = write_cmds.get(subcmd) {
        return GateResult::ask(format!("pip: {reason}"));
    }

    GateResult::ask(format!("pip: {subcmd}"))
}

// === UV ===

fn check_uv(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    let read_cmds: HashSet<&str> = ["version", "help", "tree", "--version", "-V", "-h", "--help"]
        .into_iter()
        .collect();

    let safe_local: HashSet<&str> = ["run", "sync", "lock", "venv"].into_iter().collect();

    let risky_cmds: HashMap<&str, &str> = [
        ("add", "Adding dependency"),
        ("remove", "Removing dependency"),
        ("tool", "Tool operation"),
        ("python", "Python operation"),
        ("cache", "Cache operation"),
        ("init", "Initializing project"),
        ("build", "Building package"),
        ("publish", "Publishing package"),
    ]
    .into_iter()
    .collect();

    if read_cmds.contains(subcmd) || safe_local.contains(subcmd) {
        return GateResult::allow();
    }

    // uv pip subcommands
    if subcmd == "pip" && args.len() > 1 {
        let pip_subcmd = args[1].as_str();
        let safe_pip: HashSet<&str> = ["list", "show", "freeze", "check"].into_iter().collect();
        if safe_pip.contains(pip_subcmd) {
            return GateResult::allow();
        }
        return GateResult::ask(format!("uv pip: {pip_subcmd}"));
    }

    if let Some(reason) = risky_cmds.get(subcmd) {
        return GateResult::ask(format!("uv: {reason}"));
    }

    GateResult::allow()
}

// === CARGO ===

fn check_cargo(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    let read_cmds: HashSet<&str> = [
        "check",
        "clippy",
        "doc",
        "tree",
        "metadata",
        "pkgid",
        "verify-project",
        "search",
        "info",
        "locate-project",
        "read-manifest",
        "version",
        "-V",
        "--version",
        "-h",
        "--help",
        "help",
    ]
    .into_iter()
    .collect();

    let safe_local: HashSet<&str> = ["build", "run", "test", "bench", "fmt", "clean"]
        .into_iter()
        .collect();

    let risky_cmds: HashMap<&str, &str> = [
        ("install", "Installing"),
        ("uninstall", "Uninstalling"),
        ("new", "Creating project"),
        ("init", "Initializing project"),
        ("add", "Adding dependency"),
        ("remove", "Removing dependency"),
        ("update", "Updating dependencies"),
        ("publish", "Publishing crate"),
        ("yank", "Yanking version"),
        ("fix", "Auto-fixing code"),
        ("generate-lockfile", "Generating lockfile"),
    ]
    .into_iter()
    .collect();

    if read_cmds.contains(subcmd) || safe_local.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = risky_cmds.get(subcmd) {
        return GateResult::ask(format!("cargo: {reason}"));
    }

    GateResult::allow()
}

// === GO ===

fn check_go(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    let read_cmds: HashSet<&str> = ["list", "doc", "env", "version", "vet", "help", "-h", "--help"]
        .into_iter()
        .collect();

    let safe_local: HashSet<&str> = ["build", "run", "test", "fmt", "clean"]
        .into_iter()
        .collect();

    let risky_cmds: HashMap<&str, &str> = [
        ("install", "Installing"),
        ("get", "Getting packages"),
        ("generate", "Generating code"),
        ("fix", "Fixing code"),
        ("work", "Workspace operation"),
    ]
    .into_iter()
    .collect();

    if read_cmds.contains(subcmd) || safe_local.contains(subcmd) {
        return GateResult::allow();
    }

    // go mod subcommands
    if subcmd == "mod" && args.len() > 1 {
        let mod_subcmd = args[1].as_str();
        let safe_mod: HashSet<&str> = ["graph", "verify", "why", "tidy", "download"]
            .into_iter()
            .collect();
        if safe_mod.contains(mod_subcmd) {
            return GateResult::allow();
        }
        return GateResult::ask(format!("go mod: {mod_subcmd}"));
    }

    if let Some(reason) = risky_cmds.get(subcmd) {
        return GateResult::ask(format!("go: {reason}"));
    }

    GateResult::allow()
}

// === BUN ===

fn check_bun(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    let read_cmds: HashSet<&str> = ["pm", "-v", "--version", "-h", "--help"]
        .into_iter()
        .collect();

    let safe_local: HashSet<&str> = [
        "run", "test", "build", "dev", "start", "lint", "check", "typecheck", "format",
    ]
    .into_iter()
    .collect();

    let risky_cmds: HashMap<&str, &str> = [
        ("install", "Installing packages"),
        ("i", "Installing packages"),
        ("add", "Adding packages"),
        ("remove", "Removing packages"),
        ("rm", "Removing packages"),
        ("update", "Updating packages"),
        ("link", "Linking package"),
        ("unlink", "Unlinking package"),
        ("x", "Executing package"),
        ("init", "Initializing project"),
        ("create", "Creating project"),
        ("publish", "Publishing"),
    ]
    .into_iter()
    .collect();

    if read_cmds.contains(subcmd) || safe_local.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = risky_cmds.get(subcmd) {
        return GateResult::ask(format!("bun: {reason}"));
    }

    GateResult::allow()
}

// === CONDA / MAMBA ===

/// Conda/Mamba read-only commands
static CONDA_READ: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "info", "list", "search", "config", "env", "package", "--version", "-V",
        "--help", "-h", "doctor", "notices", "compare",
    ]
    .into_iter()
    .collect()
});

/// Conda/Mamba write commands
static CONDA_WRITE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing packages"),
        ("remove", "Removing packages"),
        ("uninstall", "Uninstalling packages"),
        ("update", "Updating packages"),
        ("upgrade", "Upgrading packages"),
        ("create", "Creating environment"),
        ("activate", "Activating environment"),
        ("deactivate", "Deactivating environment"),
        ("clean", "Cleaning cache"),
        ("build", "Building package"),
        ("init", "Initializing conda"),
        ("run", "Running in environment"),
    ]
    .into_iter()
    .collect()
});

fn check_conda(cmd: &CommandInfo) -> GateResult {
    let program = cmd.program.as_str();
    let args = &cmd.args;

    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    // env list is read-only
    if subcmd == "env" && args.get(1).map(String::as_str) == Some("list") {
        return GateResult::allow();
    }

    // env create/remove need approval
    if subcmd == "env" {
        let action = args.get(1).map(String::as_str).unwrap_or("operation");
        return GateResult::ask(format!("{program}: env {action}"));
    }

    if CONDA_READ.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = CONDA_WRITE.get(subcmd) {
        return GateResult::ask(format!("{program}: {reason}"));
    }

    GateResult::ask(format!("{program}: {subcmd}"))
}

// === POETRY ===

fn check_poetry(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    let read_cmds: HashSet<&str> = [
        "show", "search", "check", "config", "env", "version", "about",
        "--version", "-V", "--help", "-h",
    ]
    .into_iter()
    .collect();

    let safe_local: HashSet<&str> = ["run", "shell", "build", "lock"]
        .into_iter()
        .collect();

    let write_cmds: HashMap<&str, &str> = [
        ("install", "Installing dependencies"),
        ("add", "Adding dependency"),
        ("remove", "Removing dependency"),
        ("update", "Updating dependencies"),
        ("init", "Initializing project"),
        ("new", "Creating project"),
        ("publish", "Publishing package"),
        ("cache", "Cache operation"),
        ("export", "Exporting dependencies"),
        ("self", "Self operation"),
        ("source", "Source operation"),
    ]
    .into_iter()
    .collect();

    if read_cmds.contains(subcmd) || safe_local.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = write_cmds.get(subcmd) {
        return GateResult::ask(format!("poetry: {reason}"));
    }

    GateResult::allow()
}

// === PIPX ===

fn check_pipx(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    let read_cmds: HashSet<&str> = [
        "list", "environment", "--version", "--help",
    ]
    .into_iter()
    .collect();

    let write_cmds: HashMap<&str, &str> = [
        ("install", "Installing application"),
        ("uninstall", "Uninstalling application"),
        ("upgrade", "Upgrading application"),
        ("upgrade-all", "Upgrading all applications"),
        ("reinstall", "Reinstalling application"),
        ("reinstall-all", "Reinstalling all"),
        ("inject", "Injecting package"),
        ("uninject", "Uninjecting package"),
        ("ensurepath", "Modifying PATH"),
        ("run", "Running application"),
    ]
    .into_iter()
    .collect();

    if read_cmds.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = write_cmds.get(subcmd) {
        return GateResult::ask(format!("pipx: {reason}"));
    }

    GateResult::ask(format!("pipx: {subcmd}"))
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

    // === npm ===

    mod npm {
        use super::*;

        #[test]
        fn test_safe_commands_allow() {
            for args in [
                &["list"][..],
                &["ls"],
                &["view", "lodash"],
                &["search", "react"],
                &["outdated"],
                &["audit"],
                &["--version"],
                &["run", "test"],
                &["run", "build"],
                &["run", "dev"],
                &["run", "lint"],
                &["test"],
                &["start"],
            ] {
                let result = check_package_managers(&cmd("npm", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_risky_commands_ask() {
            let risky_cmds = [
                (&["install"][..], "Installing"),
                (&["install", "lodash"], "Installing"),
                (&["i", "react"], "Installing"),
                (&["uninstall", "lodash"], "Uninstalling"),
                (&["update"], "Updating"),
                (&["publish"], "Publishing"),
                (&["init"], "Initializing"),
                (&["link"], "Linking"),
            ];

            for (args, expected) in risky_cmds {
                let result = check_package_managers(&cmd("npm", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(result.reason.as_ref().unwrap().contains(expected), "Failed for: {args:?}");
            }
        }
    }

    // === pnpm ===

    mod pnpm {
        use super::*;

        #[test]
        fn test_safe_commands_allow() {
            for args in [
                &["list"][..],
                &["why", "lodash"],
                &["outdated"],
                &["--version"],
                &["run", "test"],
                &["test"],
                &["build"],
                &["dev"],
            ] {
                let result = check_package_managers(&cmd("pnpm", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_risky_commands_ask() {
            let risky_cmds = [
                (&["install"][..], "Installing"),
                (&["add", "lodash"], "Adding"),
                (&["remove", "lodash"], "Removing"),
                (&["update"], "Updating"),
                (&["publish"], "Publishing"),
            ];

            for (args, expected) in risky_cmds {
                let result = check_package_managers(&cmd("pnpm", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(result.reason.as_ref().unwrap().contains(expected), "Failed for: {args:?}");
            }
        }
    }

    // === yarn ===

    mod yarn {
        use super::*;

        #[test]
        fn test_bare_yarn_asks() {
            let result = check_package_managers(&cmd("yarn", &[]));
            assert_eq!(result.decision, Decision::Ask);
        }

        #[test]
        fn test_safe_commands_allow() {
            for args in [
                &["list"][..],
                &["info", "lodash"],
                &["why", "react"],
                &["--version"],
                &["run", "test"],
                &["test"],
                &["build"],
            ] {
                let result = check_package_managers(&cmd("yarn", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }
    }

    // === pip ===

    mod pip {
        use super::*;

        #[test]
        fn test_safe_commands_allow() {
            for args in [
                &["list"][..],
                &["show", "requests"],
                &["freeze"],
                &["check"],
                &["--version"],
            ] {
                let result = check_package_managers(&cmd("pip", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_install_dry_run_allows() {
            let result = check_package_managers(&cmd("pip", &["install", "--dry-run", "requests"]));
            assert_eq!(result.decision, Decision::Allow);
        }

        #[test]
        fn test_risky_commands_ask() {
            let risky_cmds = [
                (&["install", "requests"][..], "Installing"),
                (&["uninstall", "requests"], "Uninstalling"),
            ];

            for (args, expected) in risky_cmds {
                let result = check_package_managers(&cmd("pip", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(result.reason.as_ref().unwrap().contains(expected), "Failed for: {args:?}");
            }
        }
    }

    // === uv ===

    mod uv {
        use super::*;

        #[test]
        fn test_safe_commands_allow() {
            for args in [
                &["run", "pytest"][..],
                &["run", "python", "script.py"],
                &["sync"],
                &["lock"],
                &["venv"],
                &["version"],
                &["pip", "list"],
                &["pip", "show", "requests"],
            ] {
                let result = check_package_managers(&cmd("uv", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_risky_commands_ask() {
            let risky_cmds = [
                (&["add", "requests"][..], "Adding"),
                (&["remove", "requests"], "Removing"),
                (&["publish"], "Publishing"),
                (&["pip", "install", "requests"], "pip: install"),
            ];

            for (args, expected) in risky_cmds {
                let result = check_package_managers(&cmd("uv", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(result.reason.as_ref().unwrap().contains(expected), "Failed for: {args:?}");
            }
        }
    }

    // === cargo ===

    mod cargo {
        use super::*;

        #[test]
        fn test_safe_commands_allow() {
            for args in [
                &["check"][..],
                &["clippy"],
                &["doc"],
                &["tree"],
                &["build"],
                &["run"],
                &["test"],
                &["bench"],
                &["fmt"],
                &["--version"],
            ] {
                let result = check_package_managers(&cmd("cargo", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_risky_commands_ask() {
            let risky_cmds = [
                (&["install", "ripgrep"][..], "Installing"),
                (&["add", "serde"], "Adding"),
                (&["publish"], "Publishing"),
            ];

            for (args, expected) in risky_cmds {
                let result = check_package_managers(&cmd("cargo", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(result.reason.as_ref().unwrap().contains(expected), "Failed for: {args:?}");
            }
        }
    }

    // === go ===

    mod go {
        use super::*;

        #[test]
        fn test_safe_commands_allow() {
            for args in [
                &["build"][..],
                &["run", "main.go"],
                &["test", "./..."],
                &["fmt", "./..."],
                &["vet", "./..."],
                &["list", "./..."],
                &["doc"],
                &["version"],
                &["mod", "tidy"],
                &["mod", "download"],
            ] {
                let result = check_package_managers(&cmd("go", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_risky_commands_ask() {
            let risky_cmds = [
                (&["install", "golang.org/x/tools/..."][..], "Installing"),
                (&["get", "github.com/pkg/errors"], "Getting"),
                (&["generate", "./..."], "Generating"),
            ];

            for (args, expected) in risky_cmds {
                let result = check_package_managers(&cmd("go", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(result.reason.as_ref().unwrap().contains(expected), "Failed for: {args:?}");
            }
        }
    }

    // === bun ===

    mod bun {
        use super::*;

        #[test]
        fn test_safe_commands_allow() {
            for args in [
                &["run", "test"][..],
                &["test"],
                &["build"],
                &["dev"],
                &["--version"],
            ] {
                let result = check_package_managers(&cmd("bun", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_risky_commands_ask() {
            let risky_cmds = [
                (&["install"][..], "Installing"),
                (&["add", "lodash"], "Adding"),
                (&["remove", "lodash"], "Removing"),
                (&["publish"], "Publishing"),
            ];

            for (args, expected) in risky_cmds {
                let result = check_package_managers(&cmd("bun", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(result.reason.as_ref().unwrap().contains(expected), "Failed for: {args:?}");
            }
        }
    }
}
