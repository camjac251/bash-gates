//! System command permission gates (database, process, build, sudo, OS packages).

use crate::models::{CommandInfo, GateResult};
use std::sync::LazyLock;
use std::collections::{HashMap, HashSet};

/// Check system-level commands.
pub fn check_system(cmd: &CommandInfo) -> GateResult {
    let program = cmd.program.as_str();

    match program {
        // Database CLIs
        "psql" | "mysql" | "sqlite3" | "mongosh" | "mongo" | "redis-cli" => check_database(cmd),

        // Process management
        "kill" | "pkill" | "killall" | "xkill" => check_process(cmd),

        // Build tools
        "make" => check_make(cmd),

        // System management
        "sudo" | "doas" => check_sudo(cmd),
        "systemctl" => check_systemctl(cmd),
        "service" => check_service(cmd),

        // OS Package managers
        "apt" | "apt-get" | "apt-cache" => check_apt(cmd),
        "dnf" | "yum" => check_dnf(cmd),
        "pacman" | "yay" | "paru" => check_pacman(cmd),
        "brew" => check_brew(cmd),
        "zypper" => check_zypper(cmd),
        "apk" => check_apk(cmd),
        "nix" | "nix-env" | "nix-shell" => check_nix(cmd),
        "flatpak" | "snap" => check_flatpak_snap(cmd),

        // Dangerous system commands
        "shutdown" | "reboot" | "poweroff" | "halt" | "init" => {
            GateResult::block(format!("{program}: System power command blocked"))
        }

        "dd" => GateResult::ask("dd: Low-level disk operation"),

        "mkfs" | "fdisk" | "parted" | "gdisk" => {
            GateResult::block(format!("{program}: Disk partitioning blocked"))
        }

        "crontab" => check_crontab(cmd),

        _ => GateResult::skip(),
    }
}

/// Check database CLI commands.
fn check_database(cmd: &CommandInfo) -> GateResult {
    let program = cmd.program.as_str();
    let args = &cmd.args;

    match program {
        "psql" => {
            // List databases/tables is read-only
            if args.iter().any(|a| a == "-l" || a == "--list") {
                return GateResult::allow();
            }
            // File execution - could contain any SQL
            if args.iter().any(|a| a == "-f" || a == "--file") {
                return GateResult::ask("psql: Executing SQL file (may contain writes)");
            }
            // Command execution
            if args.iter().any(|a| a == "-c" || a == "--command") {
                // Try to detect read vs write
                if let Some(idx) = args.iter().position(|a| a == "-c" || a == "--command") {
                    if idx + 1 < args.len() {
                        let query = args[idx + 1].to_uppercase();
                        if query.starts_with("SELECT")
                            || query.starts_with("\\D")
                            || query.starts_with("\\L")
                            || query.starts_with("\\DT")
                            || query.starts_with("\\DI")
                            || query.starts_with("\\DN")
                        {
                            return GateResult::allow();
                        }
                    }
                }
                return GateResult::ask("psql: Executing query");
            }
            GateResult::ask("psql: Database session")
        }

        "mysql" => {
            if args.iter().any(|a| a == "-e" || a == "--execute") {
                if let Some(idx) = args.iter().position(|a| a == "-e" || a == "--execute") {
                    if idx + 1 < args.len() {
                        let query = args[idx + 1].to_uppercase();
                        if query.starts_with("SELECT")
                            || query.starts_with("SHOW")
                            || query.starts_with("DESCRIBE")
                            || query.starts_with("DESC")
                            || query.starts_with("EXPLAIN")
                        {
                            return GateResult::allow();
                        }
                    }
                }
                return GateResult::ask("mysql: Executing query");
            }
            GateResult::ask("mysql: Database session")
        }

        "sqlite3" => {
            // Read-only mode
            if args.iter().any(|a| a == "-readonly") {
                return GateResult::allow();
            }
            // Schema/tables listing
            if args
                .iter()
                .any(|a| a == ".tables" || a == ".schema" || a == ".databases")
            {
                return GateResult::allow();
            }
            GateResult::ask("sqlite3: Database access")
        }

        "mongosh" | "mongo" => {
            if args.iter().any(|a| a == "--eval") {
                return GateResult::ask("mongosh: Executing command");
            }
            GateResult::ask("mongosh: Database session")
        }

        "redis-cli" => {
            if !args.is_empty() {
                let cmd_name = args[0].to_uppercase();
                let read_cmds: HashSet<&str> = [
                    "GET", "MGET", "HGET", "HGETALL", "KEYS", "SCAN", "TYPE", "TTL", "EXISTS",
                    "INFO", "DBSIZE", "PING",
                ]
                .into_iter()
                .collect();
                if read_cmds.contains(cmd_name.as_str()) {
                    return GateResult::allow();
                }
            }
            GateResult::ask("redis-cli: Redis command")
        }

        _ => GateResult::ask(format!("{program}: Database access")),
    }
}

/// Check process management commands.
fn check_process(cmd: &CommandInfo) -> GateResult {
    let program = cmd.program.as_str();
    let args = &cmd.args;

    // kill with signal 0 is just a check
    if program == "kill" && args.iter().any(|a| a == "-0") {
        return GateResult::allow();
    }

    GateResult::ask(format!("{program}: Terminating process(es)"))
}

/// Check make command.
fn check_make(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Dry run is safe
    if args.iter().any(|a| {
        a == "-n" || a == "--dry-run" || a == "--just-print" || a == "--recon"
    }) {
        return GateResult::allow();
    }

    // Print database/targets is safe
    if args.iter().any(|a| a == "-p" || a == "--print-data-base") {
        return GateResult::allow();
    }

    // Query mode is safe
    if args.iter().any(|a| a == "-q" || a == "--question") {
        return GateResult::allow();
    }

    // Common safe targets
    let safe_targets: HashSet<&str> = [
        "test", "tests", "check", "lint", "build", "all", "clean", "format", "fmt", "typecheck",
        "dev", "run", "help",
    ]
    .into_iter()
    .collect();

    // Get target (first non-flag arg)
    let target = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map_or("default", std::string::String::as_str);

    if safe_targets.contains(target) {
        return GateResult::allow();
    }

    GateResult::ask(format!("make: Running target '{target}'"))
}

/// Sudo flags that take a value (skip flag + value to find command)
static SUDO_FLAGS_WITH_VALUE: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    ["-u", "-g", "-p", "-r", "-t", "-C", "-D", "-h", "-U"].into_iter().collect()
});

/// Extract the underlying command from sudo args
fn extract_sudo_command(args: &[String]) -> Option<(&str, &[String])> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();

        // Flags that take a value
        if SUDO_FLAGS_WITH_VALUE.contains(arg) {
            i += 2;
            continue;
        }

        // Combined form like -u=root
        if SUDO_FLAGS_WITH_VALUE.iter().any(|f| arg.starts_with(&format!("{f}="))) {
            i += 1;
            continue;
        }

        // Single flags
        if arg.starts_with('-') {
            i += 1;
            continue;
        }

        // Found the command
        return Some((arg, &args[i + 1..]));
    }
    None
}

/// Describe what a sudo command is doing
fn describe_sudo_command(program: &str, args: &[String]) -> String {
    match program {
        "apt" | "apt-get" => {
            let action = args.first().map(String::as_str).unwrap_or("operation");
            match action {
                "install" => "Installing packages (apt)".to_string(),
                "remove" | "purge" => "Removing packages (apt)".to_string(),
                "update" => "Updating package lists (apt)".to_string(),
                "upgrade" | "dist-upgrade" | "full-upgrade" => "Upgrading packages (apt)".to_string(),
                "autoremove" => "Removing unused packages (apt)".to_string(),
                _ => format!("apt {action}"),
            }
        }
        "dnf" | "yum" => {
            let action = args.first().map(String::as_str).unwrap_or("operation");
            match action {
                "install" => "Installing packages (dnf)".to_string(),
                "remove" | "erase" => "Removing packages (dnf)".to_string(),
                "update" | "upgrade" => "Upgrading packages (dnf)".to_string(),
                _ => format!("dnf {action}"),
            }
        }
        "pacman" => {
            let action = args.first().map(String::as_str).unwrap_or("");
            if action.contains('S') { "Installing/syncing packages (pacman)".to_string() }
            else if action.contains('R') { "Removing packages (pacman)".to_string() }
            else if action.contains('U') { "Upgrading packages (pacman)".to_string() }
            else { format!("pacman {action}") }
        }
        "systemctl" => {
            let action = args.first().map(String::as_str).unwrap_or("operation");
            format!("systemctl {action}")
        }
        "rm" => "Removing files".to_string(),
        "cp" => "Copying files".to_string(),
        "mv" => "Moving files".to_string(),
        "chmod" => "Changing permissions".to_string(),
        "chown" => "Changing ownership".to_string(),
        "mkdir" => "Creating directory".to_string(),
        "service" => {
            let svc = args.first().map(String::as_str).unwrap_or("service");
            let action = args.get(1).map(String::as_str).unwrap_or("operation");
            format!("service {svc} {action}")
        }
        _ => format!("Running '{program}'"),
    }
}

/// Check sudo command.
fn check_sudo(cmd: &CommandInfo) -> GateResult {
    let program = cmd.program.as_str();
    let args = &cmd.args;

    // sudo -l (list permissions) is safe
    if args.iter().any(|a| a == "-l" || a == "--list") {
        return GateResult::allow();
    }

    // sudo -v (validate) is safe
    if args.iter().any(|a| a == "-v" || a == "--validate") {
        return GateResult::allow();
    }

    // sudo -k (invalidate) is safe
    if args.iter().any(|a| a == "-k" || a == "--reset-timestamp") {
        return GateResult::allow();
    }

    // Extract and describe the underlying command
    if let Some((underlying_cmd, underlying_args)) = extract_sudo_command(args) {
        let description = describe_sudo_command(underlying_cmd, underlying_args);
        return GateResult::ask(format!("{program}: {description}"));
    }

    GateResult::ask(format!("{program}: Elevated privileges"))
}

// === OS Package Managers ===

/// APT read-only commands
static APT_READ: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list", "search", "show", "showpkg", "depends", "rdepends", "policy",
        "madison", "pkgnames", "dotty", "xvcg", "stats", "dump", "dumpavail",
        "showsrc", "changelog", "download", "--version", "-v", "--help", "-h",
    ]
    .into_iter()
    .collect()
});

/// APT write commands
static APT_WRITE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing packages"),
        ("remove", "Removing packages"),
        ("purge", "Purging packages"),
        ("update", "Updating package lists"),
        ("upgrade", "Upgrading packages"),
        ("full-upgrade", "Full system upgrade"),
        ("dist-upgrade", "Distribution upgrade"),
        ("autoremove", "Removing unused packages"),
        ("autoclean", "Cleaning cache"),
        ("clean", "Cleaning cache"),
        ("build-dep", "Installing build dependencies"),
        ("source", "Downloading source"),
        ("edit-sources", "Editing sources"),
        ("satisfy", "Satisfying dependencies"),
    ]
    .into_iter()
    .collect()
});

fn check_apt(cmd: &CommandInfo) -> GateResult {
    let program = cmd.program.as_str();
    let args = &cmd.args;

    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    // apt-cache is always read-only
    if program == "apt-cache" {
        return GateResult::allow();
    }

    if APT_READ.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = APT_WRITE.get(subcmd) {
        return GateResult::ask(format!("{program}: {reason}"));
    }

    GateResult::ask(format!("{program}: {subcmd}"))
}

/// DNF/YUM read-only commands
static DNF_READ: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list", "info", "search", "provides", "whatprovides", "repolist",
        "repoinfo", "repoquery", "deplist", "check", "check-update",
        "history", "alias", "--version", "-v", "--help", "-h",
    ]
    .into_iter()
    .collect()
});

/// DNF/YUM write commands
static DNF_WRITE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing packages"),
        ("remove", "Removing packages"),
        ("erase", "Removing packages"),
        ("update", "Updating packages"),
        ("upgrade", "Upgrading packages"),
        ("downgrade", "Downgrading packages"),
        ("reinstall", "Reinstalling packages"),
        ("autoremove", "Removing unused packages"),
        ("clean", "Cleaning cache"),
        ("makecache", "Building cache"),
        ("group", "Group operation"),
        ("module", "Module operation"),
        ("swap", "Swapping packages"),
        ("distro-sync", "Syncing distribution"),
    ]
    .into_iter()
    .collect()
});

fn check_dnf(cmd: &CommandInfo) -> GateResult {
    let program = cmd.program.as_str();
    let args = &cmd.args;

    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    if DNF_READ.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = DNF_WRITE.get(subcmd) {
        return GateResult::ask(format!("{program}: {reason}"));
    }

    GateResult::ask(format!("{program}: {subcmd}"))
}

fn check_pacman(cmd: &CommandInfo) -> GateResult {
    let program = cmd.program.as_str();
    let args = &cmd.args;

    if args.is_empty() {
        return GateResult::allow();
    }

    let first = args[0].as_str();

    // Query operations are read-only
    if first.starts_with("-Q") || first == "--query" {
        return GateResult::allow();
    }

    // Database query (not modify)
    if first == "-Ss" || first == "-Si" || first == "-Sl" {
        return GateResult::allow();
    }

    // Version/help
    if first == "-V" || first == "--version" || first == "-h" || first == "--help" {
        return GateResult::allow();
    }

    // Sync operations
    if first.starts_with("-S") || first == "--sync" {
        if first == "-Ss" || first == "-Si" || first == "-Sl" || first == "-Sg" {
            return GateResult::allow(); // Search/info only
        }
        return GateResult::ask(format!("{program}: Installing/syncing packages"));
    }

    // Remove operations
    if first.starts_with("-R") || first == "--remove" {
        return GateResult::ask(format!("{program}: Removing packages"));
    }

    // Upgrade
    if first.starts_with("-U") || first == "--upgrade" {
        return GateResult::ask(format!("{program}: Upgrading packages"));
    }

    // Database operations
    if first.starts_with("-D") || first == "--database" {
        return GateResult::ask(format!("{program}: Database operation"));
    }

    // Files operations (read-only)
    if first.starts_with("-F") || first == "--files" {
        return GateResult::allow();
    }

    GateResult::ask(format!("{program}: {first}"))
}

/// Homebrew read-only commands
static BREW_READ: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list", "ls", "search", "info", "home", "homepage", "deps", "uses",
        "leaves", "outdated", "config", "doctor", "commands", "desc",
        "--version", "-v", "--help", "-h", "cat", "formula", "cask",
    ]
    .into_iter()
    .collect()
});

/// Homebrew write commands
static BREW_WRITE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing packages"),
        ("uninstall", "Uninstalling packages"),
        ("remove", "Removing packages"),
        ("upgrade", "Upgrading packages"),
        ("update", "Updating Homebrew"),
        ("reinstall", "Reinstalling packages"),
        ("link", "Linking packages"),
        ("unlink", "Unlinking packages"),
        ("pin", "Pinning packages"),
        ("unpin", "Unpinning packages"),
        ("tap", "Tapping repository"),
        ("untap", "Untapping repository"),
        ("cleanup", "Cleaning up"),
        ("autoremove", "Removing unused"),
        ("services", "Managing services"),
    ]
    .into_iter()
    .collect()
});

fn check_brew(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    if BREW_READ.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = BREW_WRITE.get(subcmd) {
        return GateResult::ask(format!("brew: {reason}"));
    }

    GateResult::ask(format!("brew: {subcmd}"))
}

fn check_zypper(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    let read_cmds: HashSet<&str> = [
        "search", "se", "info", "if", "list-updates", "lu", "packages", "pa",
        "patterns", "pt", "products", "pd", "repos", "lr", "services", "ls",
        "--version", "-V", "--help", "-h",
    ]
    .into_iter()
    .collect();

    let write_cmds: HashMap<&str, &str> = [
        ("install", "Installing packages"),
        ("in", "Installing packages"),
        ("remove", "Removing packages"),
        ("rm", "Removing packages"),
        ("update", "Updating packages"),
        ("up", "Updating packages"),
        ("dist-upgrade", "Distribution upgrade"),
        ("dup", "Distribution upgrade"),
        ("patch", "Installing patches"),
        ("addrepo", "Adding repository"),
        ("ar", "Adding repository"),
        ("removerepo", "Removing repository"),
        ("rr", "Removing repository"),
        ("refresh", "Refreshing repositories"),
        ("ref", "Refreshing repositories"),
        ("clean", "Cleaning cache"),
    ]
    .into_iter()
    .collect();

    if read_cmds.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = write_cmds.get(subcmd) {
        return GateResult::ask(format!("zypper: {reason}"));
    }

    GateResult::ask(format!("zypper: {subcmd}"))
}

fn check_apk(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    let read_cmds: HashSet<&str> = [
        "info", "list", "search", "dot", "policy", "stats", "audit",
        "--version", "-V", "--help", "-h",
    ]
    .into_iter()
    .collect();

    let write_cmds: HashMap<&str, &str> = [
        ("add", "Installing packages"),
        ("del", "Removing packages"),
        ("update", "Updating index"),
        ("upgrade", "Upgrading packages"),
        ("fix", "Fixing packages"),
        ("cache", "Cache operation"),
        ("fetch", "Fetching packages"),
    ]
    .into_iter()
    .collect();

    if read_cmds.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = write_cmds.get(subcmd) {
        return GateResult::ask(format!("apk: {reason}"));
    }

    GateResult::ask(format!("apk: {subcmd}"))
}

fn check_nix(cmd: &CommandInfo) -> GateResult {
    let program = cmd.program.as_str();
    let args = &cmd.args;

    if args.is_empty() {
        // nix-shell without args enters shell
        if program == "nix-shell" {
            return GateResult::ask("nix-shell: Entering Nix shell");
        }
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    // nix-env commands
    if program == "nix-env" {
        if subcmd == "-q" || subcmd == "--query" {
            return GateResult::allow();
        }
        if subcmd == "-i" || subcmd == "--install" {
            return GateResult::ask("nix-env: Installing packages");
        }
        if subcmd == "-e" || subcmd == "--uninstall" {
            return GateResult::ask("nix-env: Uninstalling packages");
        }
        if subcmd == "-u" || subcmd == "--upgrade" {
            return GateResult::ask("nix-env: Upgrading packages");
        }
        return GateResult::ask(format!("nix-env: {subcmd}"));
    }

    // nix-shell
    if program == "nix-shell" {
        return GateResult::ask("nix-shell: Entering Nix shell");
    }

    // Modern nix command
    let read_cmds: HashSet<&str> = [
        "search", "show", "eval", "repl", "flake", "path-info", "derivation",
        "store", "log", "why-depends", "--version", "--help",
    ]
    .into_iter()
    .collect();

    let write_cmds: HashMap<&str, &str> = [
        ("build", "Building derivation"),
        ("develop", "Entering dev shell"),
        ("run", "Running package"),
        ("shell", "Entering shell"),
        ("profile", "Profile operation"),
        ("upgrade-nix", "Upgrading Nix"),
        ("copy", "Copying paths"),
        ("collect-garbage", "Collecting garbage"),
    ]
    .into_iter()
    .collect();

    if read_cmds.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = write_cmds.get(subcmd) {
        return GateResult::ask(format!("nix: {reason}"));
    }

    GateResult::ask(format!("nix: {subcmd}"))
}

fn check_flatpak_snap(cmd: &CommandInfo) -> GateResult {
    let program = cmd.program.as_str();
    let args = &cmd.args;

    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    let read_cmds: HashSet<&str> = [
        "list", "info", "search", "remote-ls", "remotes", "history",
        "--version", "--help",
    ]
    .into_iter()
    .collect();

    let write_cmds: HashMap<&str, &str> = [
        ("install", "Installing"),
        ("uninstall", "Uninstalling"),
        ("remove", "Removing"),
        ("update", "Updating"),
        ("upgrade", "Upgrading"),
        ("run", "Running"),
        ("remote-add", "Adding remote"),
        ("remote-delete", "Removing remote"),
        ("repair", "Repairing"),
    ]
    .into_iter()
    .collect();

    if read_cmds.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = write_cmds.get(subcmd) {
        return GateResult::ask(format!("{program}: {reason}"));
    }

    GateResult::ask(format!("{program}: {subcmd}"))
}

static SYSTEMCTL_READ_CMDS: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "status",
        "show",
        "list-units",
        "list-unit-files",
        "list-sockets",
        "list-timers",
        "list-jobs",
        "list-dependencies",
        "is-active",
        "is-enabled",
        "is-failed",
        "is-system-running",
        "cat",
        "help",
        "--version",
        "-h",
        "--help",
    ]
    .into_iter()
    .collect()
});

static SYSTEMCTL_WRITE_CMDS: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("start", "Starting service"),
        ("stop", "Stopping service"),
        ("restart", "Restarting service"),
        ("reload", "Reloading service"),
        ("enable", "Enabling service"),
        ("disable", "Disabling service"),
        ("mask", "Masking service"),
        ("unmask", "Unmasking service"),
        ("kill", "Killing service"),
        ("reset-failed", "Resetting failed state"),
        ("daemon-reload", "Reloading daemon"),
        ("daemon-reexec", "Re-executing daemon"),
        ("set-default", "Setting default target"),
        ("isolate", "Isolating target"),
        ("edit", "Editing unit"),
    ]
    .into_iter()
    .collect()
});

/// Check systemctl command.
fn check_systemctl(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let subcmd = args[0].as_str();

    if SYSTEMCTL_READ_CMDS.contains(subcmd) {
        return GateResult::allow();
    }

    if let Some(reason) = SYSTEMCTL_WRITE_CMDS.get(subcmd) {
        return GateResult::ask(format!("systemctl: {reason}"));
    }

    GateResult::ask(format!("systemctl: {subcmd}"))
}

/// Check service command.
fn check_service(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    // service <name> status is read-only
    if args.len() >= 2 && args[1] == "status" {
        return GateResult::allow();
    }

    // --status-all is read-only
    if args.iter().any(|a| a == "--status-all") {
        return GateResult::allow();
    }

    let action = args.get(1).map_or("unknown", std::string::String::as_str);
    GateResult::ask(format!("service: {action}"))
}

/// Check crontab command.
fn check_crontab(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Only -l (list) is read-only
    // -u specifies user but doesn't make operation safe
    if args.iter().any(|a| a == "-l") {
        return GateResult::allow();
    }

    GateResult::ask("crontab: Modifying scheduled tasks")
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

    // === Database Tests ===

    mod database {
        use super::*;

        mod psql {
            use super::*;

            #[test]
            fn test_list_allows() {
                let result = check_system(&cmd("psql", &["-l"]));
                assert_eq!(result.decision, Decision::Allow);
            }

            #[test]
            fn test_select_allows() {
                let result = check_system(&cmd("psql", &["-c", "SELECT * FROM users"]));
                assert_eq!(result.decision, Decision::Allow);
            }

            #[test]
            fn test_describe_allows() {
                let result = check_system(&cmd("psql", &["-c", "\\dt"]));
                assert_eq!(result.decision, Decision::Allow);
            }

            #[test]
            fn test_insert_asks() {
                let result = check_system(&cmd("psql", &["-c", "INSERT INTO users VALUES (1)"]));
                assert_eq!(result.decision, Decision::Ask);
            }

            #[test]
            fn test_file_execution_asks() {
                let result = check_system(&cmd("psql", &["-f", "script.sql"]));
                assert_eq!(result.decision, Decision::Ask);
                assert!(result.reason.as_ref().unwrap().contains("file"));
            }

            #[test]
            fn test_file_long_form_asks() {
                let result = check_system(&cmd("psql", &["--file", "script.sql"]));
                assert_eq!(result.decision, Decision::Ask);
            }

            #[test]
            fn test_interactive_asks() {
                let result = check_system(&cmd("psql", &["-h", "localhost", "mydb"]));
                assert_eq!(result.decision, Decision::Ask);
            }
        }

        mod mysql {
            use super::*;

            #[test]
            fn test_select_allows() {
                let result = check_system(&cmd("mysql", &["-e", "SELECT * FROM users"]));
                assert_eq!(result.decision, Decision::Allow);
            }

            #[test]
            fn test_show_allows() {
                let result = check_system(&cmd("mysql", &["-e", "SHOW TABLES"]));
                assert_eq!(result.decision, Decision::Allow);
            }

            #[test]
            fn test_delete_asks() {
                let result = check_system(&cmd("mysql", &["-e", "DELETE FROM users"]));
                assert_eq!(result.decision, Decision::Ask);
            }
        }

        mod sqlite {
            use super::*;

            #[test]
            fn test_readonly_allows() {
                let result = check_system(&cmd("sqlite3", &["-readonly", "test.db"]));
                assert_eq!(result.decision, Decision::Allow);
            }

            #[test]
            fn test_normal_asks() {
                let result = check_system(&cmd("sqlite3", &["test.db"]));
                assert_eq!(result.decision, Decision::Ask);
            }
        }

        mod redis {
            use super::*;

            #[test]
            fn test_read_allows() {
                for redis_cmd in ["GET", "MGET", "HGET", "KEYS", "SCAN", "INFO", "PING"] {
                    let result = check_system(&cmd("redis-cli", &[redis_cmd, "key"]));
                    assert_eq!(result.decision, Decision::Allow, "Failed for: {redis_cmd}");
                }
            }

            #[test]
            fn test_write_asks() {
                for redis_cmd in ["SET", "DEL", "FLUSHDB"] {
                    let result = check_system(&cmd("redis-cli", &[redis_cmd, "key"]));
                    assert_eq!(result.decision, Decision::Ask, "Failed for: {redis_cmd}");
                }
            }
        }
    }

    // === Process Management Tests ===

    mod process_management {
        use super::*;

        #[test]
        fn test_kill_signal_0_allows() {
            let result = check_system(&cmd("kill", &["-0", "1234"]));
            assert_eq!(result.decision, Decision::Allow);
        }

        #[test]
        fn test_kill_commands_ask() {
            for program in ["kill", "pkill", "killall"] {
                let result = check_system(&cmd(program, &["1234"]));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {program}");
                assert!(result.reason.as_ref().unwrap().contains("Terminating"), "Failed for: {program}");
            }
        }
    }

    // === Make Tests ===

    mod make {
        use super::*;

        #[test]
        fn test_dry_run_allows() {
            for args in [&["-n"][..], &["--dry-run"], &["-p"], &["-q"]] {
                let result = check_system(&cmd("make", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_safe_targets_allow() {
            for target in ["test", "tests", "check", "lint", "build", "fmt", "help"] {
                let result = check_system(&cmd("make", &[target]));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {target}");
            }
        }

        #[test]
        fn test_risky_targets_ask() {
            for target in ["deploy", "install", "release", "publish"] {
                let result = check_system(&cmd("make", &[target]));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {target}");
                assert!(result.reason.as_ref().unwrap().contains(target), "Failed for: {target}");
            }
        }
    }

    // === Sudo Tests ===

    mod sudo {
        use super::*;

        #[test]
        fn test_safe_sudo_allows() {
            for args in [&["-l"][..], &["--list"], &["-v"], &["--validate"], &["-k"]] {
                let result = check_system(&cmd("sudo", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_sudo_command_asks() {
            let result = check_system(&cmd("sudo", &["apt", "install", "vim"]));
            assert_eq!(result.decision, Decision::Ask);
            // Should describe the underlying command
            assert!(result.reason.as_ref().unwrap().contains("Installing packages"));
        }

        #[test]
        fn test_sudo_with_flags_describes_command() {
            let result = check_system(&cmd("sudo", &["-u", "root", "systemctl", "restart", "nginx"]));
            assert_eq!(result.decision, Decision::Ask);
            assert!(result.reason.as_ref().unwrap().contains("systemctl restart"));
        }

        #[test]
        fn test_sudo_unknown_command_shows_program() {
            let result = check_system(&cmd("sudo", &["unknowncmd", "arg1"]));
            assert_eq!(result.decision, Decision::Ask);
            assert!(result.reason.as_ref().unwrap().contains("unknowncmd"));
        }

        #[test]
        fn test_doas_works_like_sudo() {
            let result = check_system(&cmd("doas", &["apt", "install", "vim"]));
            assert_eq!(result.decision, Decision::Ask);
            assert!(result.reason.as_ref().unwrap().contains("Installing packages"));
        }
    }

    // === Systemctl Tests ===

    mod systemctl {
        use super::*;

        #[test]
        fn test_read_allows() {
            for args in [
                &["status", "nginx"][..],
                &["show", "nginx"],
                &["list-units"],
                &["is-active", "nginx"],
                &["cat", "nginx"],
            ] {
                let result = check_system(&cmd("systemctl", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_write_asks() {
            let write_cmds = [
                ("start", "Starting"),
                ("stop", "Stopping"),
                ("restart", "Restarting"),
                ("enable", "Enabling"),
                ("disable", "Disabling"),
                ("daemon-reload", "Reloading"),
            ];

            for (subcmd, expected) in write_cmds {
                let result = check_system(&cmd("systemctl", &[subcmd, "nginx"]));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {subcmd}");
                assert!(result.reason.as_ref().unwrap().contains(expected), "Failed for: {subcmd}");
            }
        }
    }

    // === Service Tests ===

    mod service {
        use super::*;

        #[test]
        fn test_status_allows() {
            let result = check_system(&cmd("service", &["nginx", "status"]));
            assert_eq!(result.decision, Decision::Allow);
        }

        #[test]
        fn test_status_all_allows() {
            let result = check_system(&cmd("service", &["--status-all"]));
            assert_eq!(result.decision, Decision::Allow);
        }

        #[test]
        fn test_actions_ask() {
            for action in ["start", "stop", "restart"] {
                let result = check_system(&cmd("service", &["nginx", action]));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {action}");
            }
        }
    }

    // === Blocked Commands Tests ===

    mod blocked_commands {
        use super::*;

        #[test]
        fn test_power_commands_blocked() {
            for program in ["shutdown", "reboot", "poweroff", "halt"] {
                let result = check_system(&cmd(program, &[]));
                assert_eq!(result.decision, Decision::Block, "Failed for: {program}");
            }
        }

        #[test]
        fn test_disk_commands_blocked() {
            for program in ["mkfs", "fdisk", "parted", "gdisk"] {
                let result = check_system(&cmd(program, &["/dev/sda"]));
                assert_eq!(result.decision, Decision::Block, "Failed for: {program}");
            }
        }
    }

    // === Crontab Tests ===

    mod crontab {
        use super::*;

        #[test]
        fn test_list_allows() {
            let result = check_system(&cmd("crontab", &["-l"]));
            assert_eq!(result.decision, Decision::Allow);
        }

        #[test]
        fn test_list_with_user_allows() {
            let result = check_system(&cmd("crontab", &["-u", "root", "-l"]));
            assert_eq!(result.decision, Decision::Allow);
        }

        #[test]
        fn test_edit_asks() {
            let result = check_system(&cmd("crontab", &["-e"]));
            assert_eq!(result.decision, Decision::Ask);
        }

        #[test]
        fn test_user_alone_asks() {
            // -u only specifies user, doesn't make it safe
            let result = check_system(&cmd("crontab", &["-u", "root"]));
            assert_eq!(result.decision, Decision::Ask);
        }

        #[test]
        fn test_user_with_edit_asks() {
            let result = check_system(&cmd("crontab", &["-u", "root", "-e"]));
            assert_eq!(result.decision, Decision::Ask);
        }
    }

    // === Dd Tests ===

    mod dd {
        use super::*;

        #[test]
        fn test_dd_asks() {
            let result = check_system(&cmd("dd", &["if=/dev/zero", "of=test.img"]));
            assert_eq!(result.decision, Decision::Ask);
            assert!(result.reason.as_ref().unwrap().to_lowercase().contains("disk"));
        }
    }

    // === OS Package Managers ===

    mod apt {
        use super::*;

        #[test]
        fn test_read_allows() {
            for args in [
                &["list"][..],
                &["search", "vim"],
                &["show", "nginx"],
                &["--version"],
            ] {
                let result = check_system(&cmd("apt", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_apt_cache_allows() {
            let result = check_system(&cmd("apt-cache", &["search", "vim"]));
            assert_eq!(result.decision, Decision::Allow);
        }

        #[test]
        fn test_write_asks() {
            for (args, expected) in [
                (&["install", "vim"][..], "Installing"),
                (&["remove", "vim"], "Removing"),
                (&["update"], "Updating"),
                (&["upgrade"], "Upgrading"),
            ] {
                let result = check_system(&cmd("apt", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(result.reason.as_ref().unwrap().contains(expected), "Failed for: {args:?}");
            }
        }
    }

    mod brew {
        use super::*;

        #[test]
        fn test_read_allows() {
            for args in [
                &["list"][..],
                &["search", "ripgrep"],
                &["info", "git"],
                &["--version"],
            ] {
                let result = check_system(&cmd("brew", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_write_asks() {
            for (args, expected) in [
                (&["install", "ripgrep"][..], "Installing"),
                (&["uninstall", "git"], "Uninstalling"),
                (&["upgrade"], "Upgrading"),
            ] {
                let result = check_system(&cmd("brew", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(result.reason.as_ref().unwrap().contains(expected), "Failed for: {args:?}");
            }
        }
    }

    mod pacman {
        use super::*;

        #[test]
        fn test_query_allows() {
            for args in [
                &["-Q"][..],
                &["-Qs", "vim"],
                &["-Qi", "git"],
                &["--version"],
            ] {
                let result = check_system(&cmd("pacman", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_sync_asks() {
            let result = check_system(&cmd("pacman", &["-S", "vim"]));
            assert_eq!(result.decision, Decision::Ask);
            assert!(result.reason.as_ref().unwrap().contains("syncing"));
        }

        #[test]
        fn test_remove_asks() {
            let result = check_system(&cmd("pacman", &["-R", "vim"]));
            assert_eq!(result.decision, Decision::Ask);
            assert!(result.reason.as_ref().unwrap().contains("Removing"));
        }
    }

    mod nix {
        use super::*;

        #[test]
        fn test_query_allows() {
            let result = check_system(&cmd("nix-env", &["-q"]));
            assert_eq!(result.decision, Decision::Allow);
        }

        #[test]
        fn test_install_asks() {
            let result = check_system(&cmd("nix-env", &["-i", "ripgrep"]));
            assert_eq!(result.decision, Decision::Ask);
            assert!(result.reason.as_ref().unwrap().contains("Installing"));
        }

        #[test]
        fn test_nix_shell_asks() {
            let result = check_system(&cmd("nix-shell", &["-p", "ripgrep"]));
            assert_eq!(result.decision, Decision::Ask);
            assert!(result.reason.as_ref().unwrap().contains("shell"));
        }
    }
}
