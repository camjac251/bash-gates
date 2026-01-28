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
            Self::User => dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".claude")
                .join("settings.json"),
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
    let path = scope.path();

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
        .open(&path)?;

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

    // Write back - truncate and seek to start
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
}
