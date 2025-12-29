//! System command permission gates (database, process, build, sudo, OS packages).
//!
//! Uses declarative rules with custom logic for:
//! - sudo/doas: extracts and describes underlying command
//! - psql/mysql: parses SQL to detect read vs write
//! - Complex blocked commands (shutdown, mkfs, etc.)

use crate::generated::rules::{
    check_alembic_declarative, check_ansible_declarative, check_apt_cache_declarative,
    check_apt_declarative, check_bazel_declarative, check_brew_declarative,
    check_cmake_declarative, check_createdb_declarative, check_dbmate_declarative,
    check_dd_declarative, check_dnf_declarative, check_dropdb_declarative,
    check_flyway_declarative, check_goose_declarative, check_gradle_declarative,
    check_hyperfine_declarative, check_just_declarative, check_kill_declarative,
    check_killall_declarative, check_make_declarative, check_meson_declarative,
    check_migrate_declarative, check_mongosh_declarative, check_mvn_declarative,
    check_mysql_declarative, check_ninja_declarative, check_pacman_declarative,
    check_pg_dump_declarative, check_pg_restore_declarative, check_pkill_declarative,
    check_psql_declarative, check_systemctl_declarative, check_task_declarative,
    check_vagrant_declarative, check_xkill_declarative,
};
use crate::models::{CommandInfo, Decision, GateResult};

/// Check system-level commands.
pub fn check_system(cmd: &CommandInfo) -> GateResult {
    // Strip path prefix to handle /usr/bin/psql etc.
    let program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);

    match program {
        // Database CLIs - custom SQL parsing
        "psql" => check_psql(cmd),
        "mysql" => check_mysql(cmd),
        "sqlite3" | "mongosh" | "mongo" | "redis-cli" => check_database_generic(cmd),

        // PostgreSQL utilities - use TOML rules
        "createdb" => check_createdb_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("createdb: Creating database")),
        "dropdb" => check_dropdb_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("dropdb: Dropping database")),
        "pg_dump" => check_pg_dump_declarative(cmd).unwrap_or_else(GateResult::allow),
        "pg_restore" => check_pg_restore_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("pg_restore: Restoring database")),

        // Database migration tools - use TOML rules
        "migrate" => check_migrate_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("migrate: Running database migration")),
        "goose" => check_goose_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("goose: Running database migration")),
        "dbmate" => check_dbmate_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("dbmate: Running database migration")),
        "flyway" => check_flyway_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("flyway: Running database migration")),
        "alembic" => check_alembic_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("alembic: Running database migration")),

        // Process management
        "kill" => check_kill(cmd),
        "pkill" => check_pkill(cmd),
        "killall" => check_killall(cmd),
        "xkill" => check_xkill_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("xkill: Kill window by clicking")),

        // Build tools
        "make" => check_make(cmd),
        "cmake" => check_cmake_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("cmake: Configuring build")),
        "ninja" => check_ninja_declarative(cmd).unwrap_or_else(GateResult::allow),
        "just" => check_just_declarative(cmd).unwrap_or_else(GateResult::allow),
        "task" => check_task_declarative(cmd).unwrap_or_else(GateResult::allow),
        "gradle" | "gradlew" => {
            check_gradle_declarative(cmd).unwrap_or_else(|| GateResult::ask("gradle: Build task"))
        }
        "mvn" | "maven" | "mvnw" => {
            check_mvn_declarative(cmd).unwrap_or_else(|| GateResult::ask("maven: Build task"))
        }
        "bazel" | "bazelisk" => {
            check_bazel_declarative(cmd).unwrap_or_else(|| GateResult::ask("bazel: Build task"))
        }
        "meson" => check_meson_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("meson: Build operation")),
        "ansible" | "ansible-playbook" | "ansible-galaxy" | "ansible-vault" => {
            check_ansible_declarative(cmd)
                .unwrap_or_else(|| GateResult::ask("ansible: Running playbook"))
        }
        "vagrant" => check_vagrant_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("vagrant: VM operation")),
        "hyperfine" => check_hyperfine_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("hyperfine: Running benchmarks")),

        // System management - custom sudo handling
        "sudo" | "doas" => check_sudo(cmd),
        "systemctl" => check_systemctl(cmd),
        "service" => GateResult::ask("service: Service management"),

        // OS Package managers
        "apt" | "apt-get" => check_apt(cmd),
        "apt-cache" => check_apt_cache_declarative(cmd).unwrap_or_else(GateResult::allow),
        "dnf" | "yum" => check_dnf(cmd),
        "pacman" | "yay" | "paru" => check_pacman(cmd),
        "brew" => check_brew(cmd),
        "zypper" => GateResult::ask("zypper: Package management"),
        "apk" => GateResult::ask("apk: Package management"),
        "nix" | "nix-env" | "nix-shell" => GateResult::ask("nix: Package management"),
        "flatpak" | "snap" => GateResult::ask(format!("{program}: Package management")),

        // Dangerous system commands - blocked
        "shutdown" | "reboot" | "poweroff" | "halt" | "init" => {
            GateResult::block(format!("{program}: System power command blocked"))
        }
        "mkfs" | "fdisk" | "parted" | "gdisk" => {
            GateResult::block(format!("{program}: Disk partitioning blocked"))
        }

        "dd" => check_dd_declarative(cmd)
            .unwrap_or_else(|| GateResult::block("dd: Low-level disk operation blocked")),
        "crontab" => check_crontab(cmd),

        _ => GateResult::skip(),
    }
}

// === Database CLIs ===

fn check_psql(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // List databases is read-only
    if args.iter().any(|a| a == "-l" || a == "--list") {
        return GateResult::allow();
    }

    // File execution
    if args.iter().any(|a| a == "-f" || a == "--file") {
        return GateResult::ask("psql: Executing SQL file");
    }

    // Command execution - parse SQL
    if let Some(idx) = args.iter().position(|a| a == "-c" || a == "--command") {
        if idx + 1 < args.len() {
            let query = args[idx + 1].to_uppercase();
            if query.starts_with("SELECT") || query.starts_with("\\D") || query.starts_with("\\L") {
                return GateResult::allow();
            }
            return GateResult::ask("psql: Executing SQL");
        }
    }

    // Use declarative for other cases
    check_psql_declarative(cmd).unwrap_or_else(|| GateResult::ask("psql: Database connection"))
}

fn check_mysql(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Execute option
    if let Some(idx) = args.iter().position(|a| a == "-e" || a == "--execute") {
        if idx + 1 < args.len() {
            let query = args[idx + 1].to_uppercase();
            if query.starts_with("SELECT") || query.starts_with("SHOW") || query.starts_with("DESC")
            {
                return GateResult::allow();
            }
            return GateResult::ask("mysql: Executing SQL");
        }
    }

    check_mysql_declarative(cmd).unwrap_or_else(|| GateResult::ask("mysql: Database connection"))
}

fn check_database_generic(cmd: &CommandInfo) -> GateResult {
    if cmd.program == "mongosh" || cmd.program == "mongo" {
        check_mongosh_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("mongosh: Database connection"))
    } else {
        GateResult::ask(format!("{}: Database connection", cmd.program))
    }
}

// === Process Management ===

fn check_kill(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // kill -0 just checks if process exists
    if args.iter().any(|a| a == "-0") {
        return GateResult::allow();
    }

    // -l lists signals
    if args.iter().any(|a| a == "-l" || a == "-L") {
        return GateResult::allow();
    }

    check_kill_declarative(cmd).unwrap_or_else(|| GateResult::ask("kill: Terminating process"))
}

fn check_pkill(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // -0 just checks
    if args.iter().any(|a| a == "-0") {
        return GateResult::allow();
    }

    check_pkill_declarative(cmd).unwrap_or_else(|| GateResult::ask("pkill: Terminating processes"))
}

fn check_killall(cmd: &CommandInfo) -> GateResult {
    check_killall_declarative(cmd)
        .unwrap_or_else(|| GateResult::ask("killall: Terminating processes"))
}

// === Build Tools ===

fn check_make(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Dry run is safe
    if args.iter().any(|a| a == "-n" || a == "--dry-run") {
        return GateResult::allow();
    }

    // Check declarative for known safe targets
    if let Some(result) = check_make_declarative(cmd) {
        if matches!(result.decision, Decision::Allow | Decision::Ask) {
            return result;
        }
    }

    // Common safe targets
    let target = args.first().map(String::as_str).unwrap_or("");
    let safe_targets = ["test", "check", "build", "all", "clean", "lint", "format"];
    if safe_targets.contains(&target) {
        return GateResult::allow();
    }

    GateResult::ask(format!(
        "make: {}",
        if target.is_empty() {
            "default target"
        } else {
            target
        }
    ))
}

// === sudo/doas ===

fn check_sudo(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // -l lists permissions, -v validates, -k invalidates
    if args.iter().any(|a| a == "-l" || a == "-v" || a == "-k") {
        return GateResult::allow();
    }

    // Find the actual command being run
    let cmd_start = args
        .iter()
        .position(|a| !a.starts_with('-') && a != "sudo" && a != "doas");

    if let Some(idx) = cmd_start {
        let underlying_cmd = &args[idx];
        let underlying_args = &args[idx + 1..];

        // Describe what sudo is doing
        let description = describe_sudo_command(underlying_cmd, underlying_args);
        return GateResult::ask(format!("{}: {}", cmd.program, description));
    }

    GateResult::ask(format!("{}: Running as root", cmd.program))
}

fn describe_sudo_command(cmd: &str, args: &[String]) -> String {
    match cmd {
        "apt" | "apt-get" => {
            let action = args.first().map(String::as_str).unwrap_or("operation");
            format!("Installing packages (apt {action})")
        }
        "dnf" | "yum" => {
            let action = args.first().map(String::as_str).unwrap_or("operation");
            format!("Installing packages ({cmd} {action})")
        }
        "pacman" => "Installing packages (pacman)".to_string(),
        "brew" => "Homebrew operation".to_string(),
        "systemctl" => {
            let action = args.first().map(String::as_str).unwrap_or("operation");
            format!("Service management ({action})")
        }
        "rm" => "Removing files".to_string(),
        "mv" => "Moving files".to_string(),
        "cp" => "Copying files".to_string(),
        "chmod" | "chown" => "Changing permissions".to_string(),
        _ => format!("Running '{cmd}'"),
    }
}

// === systemctl ===

fn check_systemctl(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Read-only operations
    let read_ops = [
        "status",
        "list-units",
        "list-unit-files",
        "is-active",
        "is-enabled",
        "show",
    ];
    if args
        .first()
        .map(|a| read_ops.contains(&a.as_str()))
        .unwrap_or(false)
    {
        return GateResult::allow();
    }

    check_systemctl_declarative(cmd)
        .unwrap_or_else(|| GateResult::ask("systemctl: Service management"))
}

// === OS Package Managers ===

fn check_apt(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Read-only
    let read_ops = ["list", "search", "show", "policy", "depends", "rdepends"];
    if args
        .first()
        .map(|a| read_ops.contains(&a.as_str()))
        .unwrap_or(false)
    {
        return GateResult::allow();
    }

    check_apt_declarative(cmd).unwrap_or_else(|| GateResult::ask("apt: Package management"))
}

fn check_dnf(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    let read_ops = ["list", "info", "search", "repolist", "repoquery"];
    if args
        .first()
        .map(|a| read_ops.contains(&a.as_str()))
        .unwrap_or(false)
    {
        return GateResult::allow();
    }

    check_dnf_declarative(cmd).unwrap_or_else(|| GateResult::ask("dnf: Package management"))
}

fn check_pacman(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // -Q is query (read-only)
    if args.iter().any(|a| a.starts_with("-Q")) {
        return GateResult::allow();
    }

    check_pacman_declarative(cmd).unwrap_or_else(|| GateResult::ask("pacman: Package management"))
}

fn check_brew(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    let read_ops = [
        "list",
        "info",
        "search",
        "deps",
        "uses",
        "leaves",
        "--version",
    ];
    if args
        .first()
        .map(|a| read_ops.contains(&a.as_str()))
        .unwrap_or(false)
    {
        return GateResult::allow();
    }

    check_brew_declarative(cmd).unwrap_or_else(|| GateResult::ask("brew: Package management"))
}

// === crontab ===

fn check_crontab(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // -l lists
    if args.iter().any(|a| a == "-l") {
        return GateResult::allow();
    }

    GateResult::ask("crontab: Editing scheduled tasks")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;

    // === Database ===

    #[test]
    fn test_psql_list_allows() {
        let result = check_system(&cmd("psql", &["-l"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_psql_select_allows() {
        let result = check_system(&cmd("psql", &["-c", "SELECT * FROM users"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_psql_insert_asks() {
        let result = check_system(&cmd("psql", &["-c", "INSERT INTO users VALUES (1)"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Process ===

    #[test]
    fn test_kill_check_allows() {
        let result = check_system(&cmd("kill", &["-0", "1234"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_kill_asks() {
        let result = check_system(&cmd("kill", &["1234"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === make ===

    #[test]
    fn test_make_test_allows() {
        let result = check_system(&cmd("make", &["test"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_make_dry_run_allows() {
        let result = check_system(&cmd("make", &["-n", "deploy"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_make_deploy_asks() {
        let result = check_system(&cmd("make", &["deploy"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === sudo ===

    #[test]
    fn test_sudo_list_allows() {
        let result = check_system(&cmd("sudo", &["-l"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_sudo_apt_asks() {
        let result = check_system(&cmd("sudo", &["apt", "install", "vim"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.unwrap().contains("Installing packages"));
    }

    // === systemctl ===

    #[test]
    fn test_systemctl_status_allows() {
        let result = check_system(&cmd("systemctl", &["status", "nginx"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_systemctl_restart_asks() {
        let result = check_system(&cmd("systemctl", &["restart", "nginx"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === apt ===

    #[test]
    fn test_apt_list_allows() {
        let result = check_system(&cmd("apt", &["list", "--installed"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_apt_install_asks() {
        let result = check_system(&cmd("apt", &["install", "vim"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Blocked ===

    #[test]
    fn test_shutdown_blocked() {
        let result = check_system(&cmd("shutdown", &["-h", "now"]));
        assert_eq!(result.decision, Decision::Block);
    }

    #[test]
    fn test_mkfs_blocked() {
        let result = check_system(&cmd("mkfs", &["-t", "ext4", "/dev/sda1"]));
        assert_eq!(result.decision, Decision::Block);
    }

    // === crontab ===

    #[test]
    fn test_crontab_list_allows() {
        let result = check_system(&cmd("crontab", &["-l"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_crontab_edit_asks() {
        let result = check_system(&cmd("crontab", &["-e"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Non-system ===

    #[test]
    fn test_non_system_skips() {
        let result = check_system(&cmd("git", &["status"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}
