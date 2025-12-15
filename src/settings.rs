//! Settings.json parsing and matching for Claude Code permissions.
//!
//! Loads user (~/.claude/settings.json) and project (.claude/settings.json)
//! settings to check if a command matches any allow/deny/ask rules.

use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Default)]
pub struct Permissions {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub ask: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct Settings {
    #[serde(default)]
    pub permissions: Permissions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsDecision {
    Allow,
    Deny,
    Ask,
    NoMatch,
}

impl Settings {
    /// Load and merge settings from user + project locations.
    pub fn load(cwd: &str) -> Self {
        let mut merged = Settings::default();

        // Load user settings (~/.claude/settings.json)
        if let Some(home) = dirs::home_dir() {
            let user_path = home.join(".claude/settings.json");
            if let Ok(s) = Self::load_file(&user_path) {
                merged.merge(s);
            }
        }

        // Load project settings (.claude/settings.json relative to cwd)
        if !cwd.is_empty() {
            let project_path = Path::new(cwd).join(".claude/settings.json");
            if let Ok(s) = Self::load_file(&project_path) {
                merged.merge(s);
            }
        }

        merged
    }

    fn load_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let settings: Settings = serde_json::from_str(&content)?;
        Ok(settings)
    }

    fn merge(&mut self, other: Settings) {
        self.permissions.allow.extend(other.permissions.allow);
        self.permissions.deny.extend(other.permissions.deny);
        self.permissions.ask.extend(other.permissions.ask);
    }

    /// Check command against settings rules.
    /// Priority: deny > ask > allow
    pub fn check_command(&self, command: &str) -> SettingsDecision {
        // Check deny first (highest priority)
        if self.matches_any(&self.permissions.deny, command) {
            return SettingsDecision::Deny;
        }

        // Check ask
        if self.matches_any(&self.permissions.ask, command) {
            return SettingsDecision::Ask;
        }

        // Check allow
        if self.matches_any(&self.permissions.allow, command) {
            return SettingsDecision::Allow;
        }

        SettingsDecision::NoMatch
    }

    /// Match command against Bash(...) patterns
    fn matches_any(&self, patterns: &[String], command: &str) -> bool {
        for pattern in patterns {
            if let Some(bash_pattern) = pattern.strip_prefix("Bash(") {
                if let Some(inner) = bash_pattern.strip_suffix(')') {
                    if Self::matches_bash_pattern(inner, command) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Match Bash pattern:
    /// - "cmd:*" - prefix match with word boundary (git:* matches "git status")
    /// - "cmd*" - glob prefix match (cat /dev/zero* matches "cat /dev/zero | head")
    /// - "cmd" - exact match
    fn matches_bash_pattern(pattern: &str, command: &str) -> bool {
        if let Some(prefix) = pattern.strip_suffix(":*") {
            // Word-boundary prefix match: "git:*" matches "git", "git status"
            command == prefix || command.starts_with(&format!("{prefix} "))
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            // Glob prefix match: "cat /dev/zero*" matches "cat /dev/zero", "cat /dev/zero | head"
            command.starts_with(prefix)
        } else {
            // Exact match: "pwd" only matches "pwd"
            command == pattern
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_match() {
        assert!(Settings::matches_bash_pattern("git:*", "git"));
        assert!(Settings::matches_bash_pattern("git:*", "git status"));
        assert!(Settings::matches_bash_pattern(
            "git:*",
            "git push origin main"
        ));
        assert!(!Settings::matches_bash_pattern("git:*", "gitk"));
        assert!(!Settings::matches_bash_pattern("git:*", "github"));
    }

    #[test]
    fn test_exact_match() {
        assert!(Settings::matches_bash_pattern("pwd", "pwd"));
        assert!(!Settings::matches_bash_pattern("pwd", "pwd -L"));
        assert!(!Settings::matches_bash_pattern("pwd", "pwdx"));
    }

    #[test]
    fn test_glob_match() {
        // Glob suffix: "cat /dev/zero*" matches anything starting with "cat /dev/zero"
        assert!(Settings::matches_bash_pattern(
            "cat /dev/zero*",
            "cat /dev/zero"
        ));
        assert!(Settings::matches_bash_pattern(
            "cat /dev/zero*",
            "cat /dev/zero | head"
        ));
        assert!(!Settings::matches_bash_pattern(
            "cat /dev/zero*",
            "cat /dev/random"
        ));
        assert!(!Settings::matches_bash_pattern(
            "cat /dev/zero*",
            "cat file.txt"
        ));
    }

    #[test]
    fn test_exact_match_with_args() {
        assert!(Settings::matches_bash_pattern("rm -rf /", "rm -rf /"));
        assert!(!Settings::matches_bash_pattern("rm -rf /", "rm -rf /tmp"));
    }

    #[test]
    fn test_check_command_priority() {
        let settings = Settings {
            permissions: Permissions {
                deny: vec!["Bash(rm -rf /)".to_string()],
                ask: vec!["Bash(rm:*)".to_string()],
                allow: vec!["Bash(ls:*)".to_string()],
            },
        };

        // Deny wins
        assert_eq!(settings.check_command("rm -rf /"), SettingsDecision::Deny);
        // Ask for other rm commands
        assert_eq!(settings.check_command("rm file.txt"), SettingsDecision::Ask);
        // Allow for ls
        assert_eq!(settings.check_command("ls -la"), SettingsDecision::Allow);
        // No match for unknown
        assert_eq!(settings.check_command("foo"), SettingsDecision::NoMatch);
    }

    #[test]
    fn test_cat_dev_zero_deny() {
        let settings = Settings {
            permissions: Permissions {
                deny: vec!["Bash(cat /dev/zero*)".to_string()], // glob pattern
                ask: vec![],
                allow: vec!["Bash(cat:*)".to_string()],
            },
        };

        // Deny wins over allow for /dev/zero
        assert_eq!(
            settings.check_command("cat /dev/zero"),
            SettingsDecision::Deny
        );
        // But regular cat is allowed
        assert_eq!(
            settings.check_command("cat file.txt"),
            SettingsDecision::Allow
        );
    }
}
