//! Mise task file parsing and command extraction.
//!
//! Finds and parses mise.toml/.mise.toml files to extract the underlying
//! shell commands from task definitions, enabling permission checks on
//! the actual commands that will run.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Mise configuration file structure (subset we care about)
#[derive(Debug, Default)]
pub struct MiseConfig {
    pub tasks: Vec<MiseTask>,
}

#[derive(Debug, Clone)]
pub struct MiseTask {
    pub name: String,
    pub run: Option<String>,
    pub depends: Vec<String>,
    pub dir: Option<String>,
}

/// Find mise config file starting from cwd and walking up
pub fn find_mise_config(cwd: &str) -> Option<PathBuf> {
    let start = Path::new(cwd);
    let candidates = [".mise.toml", "mise.toml"];

    let mut current = Some(start);
    while let Some(dir) = current {
        for name in &candidates {
            let path = dir.join(name);
            if path.exists() {
                return Some(path);
            }
        }
        current = dir.parent();
    }
    None
}

/// Parse a mise TOML config file
pub fn load_mise_config(path: &Path) -> Option<MiseConfig> {
    let content = std::fs::read_to_string(path).ok()?;
    parse_mise_toml_str(&content)
}

/// Parse mise TOML content into MiseConfig (public for testing)
pub fn parse_mise_toml_str(content: &str) -> Option<MiseConfig> {
    let table: toml::Table = content.parse().ok()?;
    let mut tasks = Vec::new();

    // Tasks are in [tasks.name] sections
    if let Some(toml::Value::Table(tasks_table)) = table.get("tasks") {
        for (name, value) in tasks_table {
            if let toml::Value::Table(task_def) = value {
                let task = parse_task(name, task_def);
                tasks.push(task);
            }
        }
    }

    Some(MiseConfig { tasks })
}

fn parse_task(name: &str, def: &toml::Table) -> MiseTask {
    let run = def.get("run").and_then(|v| v.as_str()).map(String::from);

    let depends = def
        .get("depends")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let dir = def.get("dir").and_then(|v| v.as_str()).map(String::from);

    MiseTask {
        name: name.to_string(),
        run,
        depends,
        dir,
    }
}

/// Extract all commands that would run for a task (including dependencies)
///
/// Returns commands in execution order (dependencies first)
pub fn extract_task_commands(config: &MiseConfig, task_name: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut visited = HashSet::new();
    collect_task_commands(config, task_name, &mut commands, &mut visited);
    commands
}

fn collect_task_commands(
    config: &MiseConfig,
    task_name: &str,
    commands: &mut Vec<String>,
    visited: &mut HashSet<String>,
) {
    // Prevent circular dependencies
    if visited.contains(task_name) {
        return;
    }
    visited.insert(task_name.to_string());

    // Find the task
    let Some(task) = config.tasks.iter().find(|t| t.name == task_name) else {
        return;
    };

    // Process dependencies first
    for dep in &task.depends {
        collect_task_commands(config, dep, commands, visited);
    }

    // Add this task's run command
    if let Some(run) = &task.run {
        // Handle multi-line scripts - extract individual commands
        // For now, treat the whole script as one unit
        let trimmed = run.trim();
        if !trimmed.is_empty() {
            // If it starts with shebang, skip the shebang line
            let script = if trimmed.starts_with("#!") {
                trimmed
                    .lines()
                    .skip(1)
                    .collect::<Vec<_>>()
                    .join("\n")
                    .trim()
                    .to_string()
            } else {
                trimmed.to_string()
            };

            // Add dir prefix if specified
            if let Some(dir) = &task.dir {
                commands.push(format!("cd {} && {}", dir, script));
            } else {
                commands.push(script);
            }
        }
    }
}

/// Check if a command is a mise task invocation and extract the task name
pub fn parse_mise_invocation(command: &str) -> Option<String> {
    let parts: Vec<&str> = command.split_whitespace().collect();

    if parts.is_empty() {
        return None;
    }

    // Must start with "mise"
    if parts[0] != "mise" {
        return None;
    }

    if parts.len() < 2 {
        return None;
    }

    // "mise run <task>" or "mise r <task>"
    if (parts[1] == "run" || parts[1] == "r") && parts.len() >= 3 {
        // Get task name (may have arguments after it)
        return Some(parts[2].to_string());
    }

    // "mise <task>" - task name directly (if not a mise subcommand)
    let mise_subcommands = [
        "activate",
        "alias",
        "bin-paths",
        "cache",
        "completion",
        "config",
        "current",
        "deactivate",
        "direnv",
        "doctor",
        "env",
        "exec",
        "generate",
        "global",
        "hook-env",
        "hook-not-found",
        "implode",
        "install",
        "latest",
        "link",
        "local",
        "ls",
        "ls-remote",
        "outdated",
        "plugins",
        "prune",
        "registry",
        "reshim",
        "run",
        "self-update",
        "set",
        "settings",
        "shell",
        "sync",
        "tasks",
        "tool",
        "trust",
        "uninstall",
        "unset",
        "upgrade",
        "use",
        "version",
        "watch",
        "where",
        "which",
        // Short forms
        "r",
        "x",
        "i",
        "u",
        "p",
        "e",
    ];

    if !mise_subcommands.contains(&parts[1]) {
        // It's a task name
        return Some(parts[1].to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mise_invocation_run() {
        assert_eq!(
            parse_mise_invocation("mise run lint"),
            Some("lint".to_string())
        );
        assert_eq!(
            parse_mise_invocation("mise run lint:fix"),
            Some("lint:fix".to_string())
        );
        assert_eq!(
            parse_mise_invocation("mise r test"),
            Some("test".to_string())
        );
    }

    #[test]
    fn test_parse_mise_invocation_direct() {
        assert_eq!(parse_mise_invocation("mise lint"), Some("lint".to_string()));
        assert_eq!(
            parse_mise_invocation("mise dev:frontend"),
            Some("dev:frontend".to_string())
        );
    }

    #[test]
    fn test_parse_mise_invocation_subcommands() {
        // These are mise subcommands, not tasks
        assert_eq!(parse_mise_invocation("mise install"), None);
        assert_eq!(parse_mise_invocation("mise use node@20"), None);
        assert_eq!(parse_mise_invocation("mise ls"), None);
    }

    #[test]
    fn test_parse_mise_toml() {
        let toml = r#"
[tasks.lint]
description = "Run linter"
run = "pnpm lint"

[tasks."lint:fix"]
description = "Fix lint issues"
run = "pnpm lint:fix"
depends = ["lint"]

[tasks."dev:frontend"]
description = "Run frontend"
dir = "web"
run = "pnpm dev"
"#;

        let config = parse_mise_toml_str(toml).unwrap();
        assert_eq!(config.tasks.len(), 3);

        let lint = config.tasks.iter().find(|t| t.name == "lint").unwrap();
        assert_eq!(lint.run.as_deref(), Some("pnpm lint"));

        let lint_fix = config.tasks.iter().find(|t| t.name == "lint:fix").unwrap();
        assert_eq!(lint_fix.depends, vec!["lint"]);

        let dev = config
            .tasks
            .iter()
            .find(|t| t.name == "dev:frontend")
            .unwrap();
        assert_eq!(dev.dir.as_deref(), Some("web"));
    }

    #[test]
    fn test_extract_task_commands_simple() {
        let toml = r#"
[tasks.test]
run = "cargo test"
"#;
        let config = parse_mise_toml_str(toml).unwrap();
        let commands = extract_task_commands(&config, "test");
        assert_eq!(commands, vec!["cargo test"]);
    }

    #[test]
    fn test_extract_task_commands_with_depends() {
        let toml = r#"
[tasks.build]
run = "cargo build"

[tasks.test]
run = "cargo test"
depends = ["build"]
"#;
        let config = parse_mise_toml_str(toml).unwrap();
        let commands = extract_task_commands(&config, "test");
        assert_eq!(commands, vec!["cargo build", "cargo test"]);
    }

    #[test]
    fn test_extract_task_commands_with_dir() {
        let toml = r#"
[tasks."dev:web"]
dir = "frontend"
run = "pnpm dev"
"#;
        let config = parse_mise_toml_str(toml).unwrap();
        let commands = extract_task_commands(&config, "dev:web");
        assert_eq!(commands, vec!["cd frontend && pnpm dev"]);
    }

    #[test]
    fn test_extract_task_commands_multiline() {
        let toml = r#"
[tasks.setup]
run = """
#!/usr/bin/env bash
set -e
echo "Installing..."
pnpm install
"""
"#;
        let config = parse_mise_toml_str(toml).unwrap();
        let commands = extract_task_commands(&config, "setup");
        assert_eq!(commands.len(), 1);
        assert!(commands[0].contains("pnpm install"));
        assert!(!commands[0].contains("#!/"));
    }

    #[test]
    fn test_extract_task_commands_circular_deps() {
        let toml = r#"
[tasks.a]
run = "echo a"
depends = ["b"]

[tasks.b]
run = "echo b"
depends = ["a"]
"#;
        let config = parse_mise_toml_str(toml).unwrap();
        // Should not infinite loop
        let commands = extract_task_commands(&config, "a");
        assert!(commands.len() <= 2);
    }

    #[test]
    fn test_extract_task_commands_missing() {
        let toml = r#"
[tasks.test]
run = "cargo test"
"#;
        let config = parse_mise_toml_str(toml).unwrap();
        let commands = extract_task_commands(&config, "nonexistent");
        assert!(commands.is_empty());
    }
}
