//! Settings writer for modifying Claude Code settings.json files.
//!
//! Supports adding and removing permission rules from settings files.

use fs2::FileExt;
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::PathBuf;

/// Scope for settings files
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    User,
    Project,
    Local,
}

impl Scope {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Self::User),
            "project" => Some(Self::Project),
            "local" => Some(Self::Local),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
            Self::Local => "local",
        }
    }

    pub fn path(&self) -> PathBuf {
        match self {
            Self::User => {
                // Check CLAUDE_CONFIG_DIR env var first, fall back to ~/.claude
                let config_dir = std::env::var("CLAUDE_CONFIG_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| {
                        dirs::home_dir()
                            .unwrap_or_else(|| PathBuf::from("."))
                            .join(".claude")
                    });
                config_dir.join("settings.json")
            }
            Self::Project | Self::Local => {
                // Resolve to absolute path at call time to avoid issues if cwd changes
                let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                let filename = match self {
                    Self::Project => "settings.json",
                    Self::Local => "settings.local.json",
                    _ => unreachable!(),
                };
                cwd.join(".claude").join(filename)
            }
        }
    }

    /// Get the settings file path for a specific project directory
    pub fn path_for_project(&self, project_path: &str) -> PathBuf {
        match self {
            Self::User => self.path(), // User scope ignores project
            Self::Project => PathBuf::from(project_path)
                .join(".claude")
                .join("settings.json"),
            Self::Local => PathBuf::from(project_path)
                .join(".claude")
                .join("settings.local.json"),
        }
    }
}

/// Type of permission rule
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleType {
    Allow,
    Ask,
    Deny,
}

impl RuleType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }
}

/// A permission rule from settings.json
#[derive(Debug, Clone)]
pub struct PermissionRule {
    pub pattern: String,
    pub rule_type: RuleType,
    pub scope: Scope,
}

/// Load settings from a scope, returning empty object if not found
fn load_settings(scope: Scope) -> Value {
    let path = scope.path();
    if !path.exists() {
        return json!({});
    }

    fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

/// Atomically modify settings with exclusive lock.
/// Holds the lock for the entire read-modify-write operation to prevent race conditions.
fn with_exclusive_settings<F, R>(scope: Scope, f: F) -> std::io::Result<R>
where
    F: FnOnce(&mut Value) -> R,
{
    with_exclusive_settings_path(&scope.path(), f)
}

/// Atomically modify settings at a specific path
fn with_exclusive_settings_path<F, R>(path: &PathBuf, f: F) -> std::io::Result<R>
where
    F: FnOnce(&mut Value) -> R,
{
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Open file for read+write with exclusive lock
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;

    #[allow(clippy::incompatible_msrv)] // fs2 crate method, not std
    file.lock_exclusive()?;

    // Read current contents
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    // Parse (or default if empty/invalid)
    let mut settings: Value = if contents.is_empty() {
        json!({})
    } else {
        serde_json::from_str(&contents).unwrap_or_else(|_| json!({}))
    };

    // Execute the modification function
    let result = f(&mut settings);

    // Write back
    file.set_len(0)?;
    file.seek(std::io::SeekFrom::Start(0))?;

    let json = serde_json::to_string_pretty(&settings)? + "\n";
    file.write_all(json.as_bytes())?;
    file.flush()?;

    #[allow(clippy::incompatible_msrv)] // fs2 crate method, not std
    file.unlock()?;

    Ok(result)
}

/// Add a permission rule to settings.json
/// Removes the pattern from other rule types first to prevent conflicts
pub fn add_rule(scope: Scope, pattern: &str, rule_type: RuleType) -> std::io::Result<()> {
    let formatted = format_pattern(pattern);

    with_exclusive_settings(scope, |settings| {
        // Ensure permissions object exists
        if settings.get("permissions").is_none() {
            settings["permissions"] = json!({});
        }

        let permissions = settings.get_mut("permissions").unwrap();

        // First, remove from ALL rule arrays to prevent conflicts
        // A pattern should only exist in one array at a time
        for other_type in ["allow", "ask", "deny"] {
            if let Some(arr) = permissions
                .get_mut(other_type)
                .and_then(|v| v.as_array_mut())
            {
                arr.retain(|r| r.as_str() != Some(&formatted));
            }
        }

        let rule_key = rule_type.as_str();

        // Ensure the rule array exists
        if permissions.get(rule_key).is_none() {
            permissions[rule_key] = json!([]);
        }

        let rules = permissions[rule_key].as_array_mut().unwrap();

        // Add the rule (we just removed any existing, so no need to check)
        rules.push(json!(formatted));
    })
}

/// Add a permission rule to a specific project's settings file
pub fn add_rule_to_project(
    scope: Scope,
    project_path: &str,
    pattern: &str,
    rule_type: RuleType,
) -> std::io::Result<()> {
    let formatted = format_pattern(pattern);
    let path = scope.path_for_project(project_path);

    with_exclusive_settings_path(&path, |settings| {
        // Ensure permissions object exists
        if settings.get("permissions").is_none() {
            settings["permissions"] = json!({});
        }

        let permissions = settings.get_mut("permissions").unwrap();

        // Remove from ALL rule arrays to prevent conflicts
        for other_type in ["allow", "ask", "deny"] {
            if let Some(arr) = permissions
                .get_mut(other_type)
                .and_then(|v| v.as_array_mut())
            {
                arr.retain(|r| r.as_str() != Some(&formatted));
            }
        }

        let rule_key = rule_type.as_str();

        // Ensure the rule array exists
        if permissions.get(rule_key).is_none() {
            permissions[rule_key] = json!([]);
        }

        let rules = permissions[rule_key].as_array_mut().unwrap();
        rules.push(json!(formatted));
    })
}

/// Remove a permission rule from settings.json
pub fn remove_rule(scope: Scope, pattern: &str) -> std::io::Result<bool> {
    let formatted = format_pattern(pattern);

    with_exclusive_settings(scope, |settings| {
        let Some(permissions) = settings.get_mut("permissions") else {
            return false;
        };

        let mut removed = false;

        for rule_type in ["allow", "ask", "deny"] {
            if let Some(rules) = permissions.get_mut(rule_type) {
                if let Some(arr) = rules.as_array_mut() {
                    let len_before = arr.len();
                    arr.retain(|r| r.as_str() != Some(&formatted));
                    if arr.len() < len_before {
                        removed = true;
                    }
                }
            }
        }

        removed
    })
}

/// List all permission rules from a scope
pub fn list_rules(scope: Scope) -> Vec<PermissionRule> {
    let settings = load_settings(scope);
    let mut rules = Vec::new();

    let Some(permissions) = settings.get("permissions") else {
        return rules;
    };

    for (rule_type, key) in [
        (RuleType::Allow, "allow"),
        (RuleType::Ask, "ask"),
        (RuleType::Deny, "deny"),
    ] {
        if let Some(arr) = permissions.get(key).and_then(|v| v.as_array()) {
            for pattern in arr {
                if let Some(p) = pattern.as_str() {
                    rules.push(PermissionRule {
                        pattern: p.to_string(),
                        rule_type,
                        scope,
                    });
                }
            }
        }
    }

    rules
}

/// List all rules from all scopes
pub fn list_all_rules() -> Vec<PermissionRule> {
    let mut rules = Vec::new();
    for scope in [Scope::User, Scope::Project, Scope::Local] {
        rules.extend(list_rules(scope));
    }
    rules
}

/// Format a pattern for settings.json (add Bash() wrapper if needed)
pub fn format_pattern(pattern: &str) -> String {
    if pattern.starts_with("Bash(") && pattern.ends_with(')') {
        pattern.to_string()
    } else {
        format!("Bash({})", pattern)
    }
}

/// Parse a pattern from settings.json format
pub fn parse_pattern(formatted: &str) -> String {
    if formatted.starts_with("Bash(") && formatted.ends_with(')') {
        formatted[5..formatted.len() - 1].to_string()
    } else {
        formatted.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[allow(dead_code)]
    fn with_temp_home<F>(test: F)
    where
        F: FnOnce(),
    {
        let temp_dir = TempDir::new().unwrap();
        // SAFETY: Test runs single-threaded
        unsafe { std::env::set_var("HOME", temp_dir.path()) };
        test();
    }

    #[test]
    fn test_format_pattern() {
        assert_eq!(format_pattern("npm install*"), "Bash(npm install*)");
        assert_eq!(format_pattern("Bash(git*)"), "Bash(git*)");
    }

    #[test]
    fn test_parse_pattern() {
        assert_eq!(parse_pattern("Bash(npm install*)"), "npm install*");
        assert_eq!(parse_pattern("git*"), "git*");
    }

    #[test]
    fn test_scope_from_str() {
        assert_eq!(Scope::parse("user"), Some(Scope::User));
        assert_eq!(Scope::parse("project"), Some(Scope::Project));
        assert_eq!(Scope::parse("local"), Some(Scope::Local));
        assert_eq!(Scope::parse("invalid"), None);
    }

    #[test]
    fn test_user_scope_respects_config_dir_env() {
        let temp_dir = TempDir::new().unwrap();
        let custom_path = temp_dir.path().to_string_lossy().to_string();

        // Set the env var
        unsafe { std::env::set_var("CLAUDE_CONFIG_DIR", &custom_path) };

        let path = Scope::User.path();
        assert!(path.starts_with(temp_dir.path()));
        assert!(path.ends_with("settings.json"));

        // Clean up
        unsafe { std::env::remove_var("CLAUDE_CONFIG_DIR") };
    }
}
