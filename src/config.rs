//! User configuration for tool-gates features.
//!
//! Loaded from `$XDG_CONFIG_HOME/tool-gates/config.toml`
//! (defaults to `~/.config/tool-gates/config.toml`).
//!
//! All features are enabled by default. The config file is optional --
//! if missing or unparseable, all defaults apply.
//!
//! ## Block tools
//!
//! If `[[block_tools]]` is omitted, built-in defaults apply (Glob, Grep,
//! firecrawl+GitHub). If present (even empty), only those rules are used.
//!
//! ```toml
//! [[block_tools]]
//! tool = "Glob"
//! message = "Use 'fd' instead."
//! requires_tool = "fd"  # only block if fd is installed
//!
//! [[block_tools]]
//! tool = "*firecrawl*"
//! block_domains = ["github.com", "raw.githubusercontent.com"]
//! message = "Use 'gh api' for GitHub."
//! requires_tool = "gh"
//! ```
//!
//! ## File guards
//!
//! Extend or replace the built-in guarded filenames and directories:
//!
//! ```toml
//! [file_guards]
//! extra_names = [".myconfig"]     # add to built-in list
//! extra_dirs = [".myide"]         # add to built-in list
//! extra_prefixes = [".myrules-"]  # add to built-in list
//! extra_extensions = [".toml"]    # add to built-in list
//! ```
//!
//! ## Hints
//!
//! ```toml
//! [features]
//! hints = false            # disable all modern CLI hints
//!
//! [hints]
//! disable = ["man", "du"]  # suppress specific legacy command hints
//! ```
//!
//! ## Cache
//!
//! ```toml
//! [cache]
//! ttl_days = 14  # tool detection cache TTL (default: 7)
//! ```

use serde::Deserialize;
use std::path::PathBuf;
use std::sync::OnceLock;

/// Top-level configuration.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub features: Features,
    /// Tool blocking rules. `None` = use built-in defaults.
    /// `Some([...])` = use exactly these rules (full user control).
    #[serde(default)]
    pub block_tools: Option<Vec<BlockRule>>,
    /// File guard customization.
    #[serde(default)]
    pub file_guards: FileGuardsConfig,
    /// Hint customization.
    #[serde(default)]
    pub hints: HintsConfig,
    /// Cache settings.
    #[serde(default)]
    pub cache: CacheConfig,
    /// Security reminder customization.
    #[serde(default)]
    pub security_reminders: SecurityRemindersConfig,
    /// Auto-approve rules for Skill tool calls.
    #[serde(default)]
    pub auto_approve_skills: Vec<SkillApprovalRule>,
}

impl Config {
    /// Get the effective block rules (user-defined or built-in defaults).
    pub fn block_rules(&self) -> &[BlockRule] {
        match &self.block_tools {
            Some(rules) => rules,
            None => DEFAULT_BLOCK_RULES.as_ref(),
        }
    }
}

/// Feature toggles. All default to `true`.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Features {
    /// AST-based bash command permission gating
    pub bash_gates: bool,
    /// Symlink guard for AI config files (Read/Write/Edit/MultiEdit)
    pub file_guards: bool,
    /// Modern CLI hints (cat->bat, grep->rg, etc.)
    pub hints: bool,
    /// Security anti-pattern scanning for Write/Edit/MultiEdit content
    pub security_reminders: bool,
}

impl Default for Features {
    fn default() -> Self {
        Self {
            bash_gates: true,
            file_guards: true,
            hints: true,
            security_reminders: true,
        }
    }
}

/// Hint customization.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct HintsConfig {
    /// Legacy command names to suppress hints for (e.g., ["man", "du"]).
    pub disable: Vec<String>,
}

/// Cache settings.
#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct CacheConfig {
    /// Tool cache TTL in days. Default: 7.
    pub ttl_days: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self { ttl_days: 7 }
    }
}

/// Auto-approve rule for Skill tool calls.
#[derive(Debug, Deserialize, Clone)]
pub struct SkillApprovalRule {
    /// Skill name pattern. Exact or glob with `*` (e.g., `"beads*"`).
    pub skill: String,
    /// Custom approval reason. Defaults to "Auto-approved by tool-gates config".
    #[serde(default)]
    pub message: Option<String>,
    /// Only approve if the project directory is under one of these paths.
    /// Supports `~` expansion.
    #[serde(default)]
    pub if_project_under: Vec<String>,
    /// Only approve if the project directory contains one of these dirs/files.
    #[serde(default)]
    pub if_project_has: Vec<String>,
}

impl SkillApprovalRule {
    /// Check if this rule matches a skill name (exact or glob).
    pub fn matches_skill(&self, skill_name: &str) -> bool {
        let pattern = &self.skill;
        if !pattern.contains('*') {
            return pattern == skill_name;
        }
        // Reuse same glob logic as BlockRule
        match (pattern.strip_prefix('*'), pattern.strip_suffix('*')) {
            (Some(rest), Some(_)) => {
                let inner = rest.strip_suffix('*').unwrap_or(rest);
                skill_name.contains(inner)
            }
            (Some(suffix), None) => skill_name.ends_with(suffix),
            (None, Some(prefix)) => skill_name.starts_with(prefix),
            _ => pattern == skill_name,
        }
    }

    /// Check if the directory conditions are met.
    pub fn conditions_met(&self, project_dir: &str) -> bool {
        // If no conditions, always match
        if self.if_project_under.is_empty() && self.if_project_has.is_empty() {
            return true;
        }

        let project_path = std::path::Path::new(project_dir);

        // Check if_project_under: project must be at or under one of these paths
        if !self.if_project_under.is_empty() {
            let matched = self.if_project_under.iter().any(|dir| {
                let expanded = expand_tilde(dir);
                let base = std::path::Path::new(&expanded);
                project_path == base || project_path.starts_with(base)
            });
            if !matched {
                return false;
            }
        }

        // Check if_project_has: project dir must contain one of these entries
        if !self.if_project_has.is_empty() {
            let matched = self
                .if_project_has
                .iter()
                .any(|entry| project_path.join(entry).exists());
            if !matched {
                return false;
            }
        }

        true
    }
}

/// Expand `~` to home directory in a path string.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).display().to_string();
        }
    } else if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home.display().to_string();
        }
    }
    path.to_string()
}

/// Security reminders configuration.
#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct SecurityRemindersConfig {
    /// Enable secret detection -- AWS keys, private keys, tokens (default: true).
    /// These are Tier 1 (always denied, never deduped).
    pub secrets: bool,
    /// Enable anti-pattern detection -- eval, exec, innerHTML, pickle, etc. (default: true).
    /// These are Tier 2 (PostToolUse nudge, deduped per file+rule per session).
    pub anti_patterns: bool,
    /// Enable informational warnings -- SSL verify=False, chmod 777, etc. (default: true).
    /// These are Tier 3 (allow with additionalContext, deduped per session).
    pub warnings: bool,
    /// Rule names to disable (e.g., ["eval_injection", "pickle_deserialization"]).
    pub disable_rules: Vec<String>,
}

impl Default for SecurityRemindersConfig {
    fn default() -> Self {
        Self {
            secrets: true,
            anti_patterns: true,
            warnings: true,
            disable_rules: Vec::new(),
        }
    }
}

/// File guard configuration for extending or replacing guarded paths.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct FileGuardsConfig {
    /// Additional guarded filenames (merged with built-ins, case-insensitive).
    pub extra_names: Vec<String>,
    /// Additional guarded directory names (merged with built-ins, case-insensitive).
    pub extra_dirs: Vec<String>,
    /// Additional guarded filename prefixes (merged with built-ins).
    pub extra_prefixes: Vec<String>,
    /// Additional config file extensions for guarded directories (merged with built-ins).
    pub extra_extensions: Vec<String>,
}

/// A rule that blocks a tool call with a deny decision.
#[derive(Debug, Deserialize, Clone)]
pub struct BlockRule {
    /// Tool name pattern. Exact match or glob with `*`:
    /// - `"Glob"` matches only `Glob`
    /// - `"*firecrawl*"` matches `mcp__firecrawl__firecrawl_scrape`, etc.
    pub tool: String,
    /// Deny message shown to the AI assistant.
    pub message: String,
    /// If set, only block when a URL field in tool_input matches one of these domains.
    /// Checks `url` and `urls` fields in tool_input.
    #[serde(default)]
    pub block_domains: Vec<String>,
    /// If set, only block when this CLI tool is installed.
    /// Prevents suggesting alternatives that aren't available.
    #[serde(default)]
    pub requires_tool: Option<String>,
}

impl BlockRule {
    /// Check if this rule matches a tool name.
    pub fn matches_tool(&self, tool_name: &str) -> bool {
        let pattern = &self.tool;

        if !pattern.contains('*') {
            // Exact match
            return pattern == tool_name;
        }

        // Simple glob using strip_prefix/strip_suffix (UTF-8 safe)
        match (pattern.strip_prefix('*'), pattern.strip_suffix('*')) {
            (Some(rest), Some(_)) => {
                // *contains* (includes lone "*" which matches everything)
                let inner = rest.strip_suffix('*').unwrap_or(rest);
                tool_name.contains(inner)
            }
            (Some(suffix), None) => {
                // *suffix
                tool_name.ends_with(suffix)
            }
            (None, Some(prefix)) => {
                // prefix*
                tool_name.starts_with(prefix)
            }
            _ => {
                // middle* not supported, treat as exact
                pattern == tool_name
            }
        }
    }

    /// Check if this is an unconditional block (no domain filter).
    pub fn is_unconditional(&self) -> bool {
        self.block_domains.is_empty()
    }
}

/// Built-in default block rules (used when config omits `[[block_tools]]`).
static DEFAULT_BLOCK_RULES: std::sync::LazyLock<Vec<BlockRule>> = std::sync::LazyLock::new(|| {
    vec![
        BlockRule {
            tool: "Glob".to_string(),
            message: "Glob tool is blocked. Use 'fd' instead.".to_string(),
            block_domains: vec![],
            requires_tool: Some("fd".to_string()),
        },
        BlockRule {
            tool: "Grep".to_string(),
            message: "Grep tool is blocked. Use 'rg' (ripgrep) or 'ast-grep' (for code)."
                .to_string(),
            block_domains: vec![],
            requires_tool: Some("rg".to_string()),
        },
        BlockRule {
            tool: "*firecrawl*".to_string(),
            message: "Firecrawl blocked for GitHub. Use: gh api repos/OWNER/REPO/contents/PATH"
                .to_string(),
            block_domains: vec![
                "github.com".to_string(),
                "www.github.com".to_string(),
                "gist.github.com".to_string(),
                "raw.githubusercontent.com".to_string(),
            ],
            requires_tool: Some("gh".to_string()),
        },
    ]
});

/// Get the config file path.
fn config_path() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .ok()
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("tool-gates")
        .join("config.toml")
}

/// Load configuration. Returns defaults if file doesn't exist or can't be parsed.
pub fn load() -> Config {
    let path = config_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => match toml::from_str(&content) {
            Ok(config) => config,
            Err(e) => {
                eprintln!(
                    "tool-gates: warning: config parse error in {}: {e}",
                    path.display()
                );
                Config::default()
            }
        },
        Err(_) => Config::default(),
    }
}

/// Global config singleton -- loaded once per process.
static GLOBAL_CONFIG: OnceLock<Config> = OnceLock::new();

/// Get the global config (loads from disk on first call).
pub fn get() -> &'static Config {
    GLOBAL_CONFIG.get_or_init(load)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_all_enabled() {
        let config = Config::default();
        assert!(config.features.bash_gates);
        assert!(config.features.file_guards);
        assert!(config.features.hints);
        assert_eq!(config.cache.ttl_days, 7);
    }

    #[test]
    fn test_default_block_rules() {
        let config = Config::default();
        let rules = config.block_rules();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].tool, "Glob");
        assert_eq!(rules[0].requires_tool.as_deref(), Some("fd"));
        assert_eq!(rules[1].tool, "Grep");
        assert_eq!(rules[1].requires_tool.as_deref(), Some("rg"));
        assert_eq!(rules[2].tool, "*firecrawl*");
        assert_eq!(rules[2].requires_tool.as_deref(), Some("gh"));
    }

    #[test]
    fn test_partial_config_keeps_default_blocks() {
        let toml = r#"
[features]
file_guards = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(!config.features.file_guards);
        assert!(config.block_tools.is_none());
        assert_eq!(config.block_rules().len(), 3);
    }

    #[test]
    fn test_custom_block_rules_replace_defaults() {
        let toml = r#"
[[block_tools]]
tool = "WebFetch"
message = "Use internal API."
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let rules = config.block_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].tool, "WebFetch");
        assert!(rules[0].requires_tool.is_none());
    }

    #[test]
    fn test_empty_block_tools_disables_all() {
        let toml = r#"
block_tools = []
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.block_rules().len(), 0);
    }

    #[test]
    fn test_requires_tool_parsing() {
        let toml = r#"
[[block_tools]]
tool = "Glob"
message = "Use fd."
requires_tool = "fd"

[[block_tools]]
tool = "Grep"
message = "Use rg."
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let rules = config.block_rules();
        assert_eq!(rules[0].requires_tool.as_deref(), Some("fd"));
        assert!(rules[1].requires_tool.is_none());
    }

    #[test]
    fn test_file_guards_config_defaults() {
        let config = Config::default();
        assert!(config.file_guards.extra_names.is_empty());
        assert!(config.file_guards.extra_dirs.is_empty());
        assert!(config.file_guards.extra_prefixes.is_empty());
        assert!(config.file_guards.extra_extensions.is_empty());
    }

    #[test]
    fn test_file_guards_config_parsing() {
        let toml = r#"
[file_guards]
extra_names = [".myconfig", ".teamrules"]
extra_dirs = [".myide", ".teamconfig"]
extra_prefixes = [".myrules-"]
extra_extensions = [".toml"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.file_guards.extra_names.len(), 2);
        assert_eq!(config.file_guards.extra_dirs.len(), 2);
        assert_eq!(config.file_guards.extra_prefixes.len(), 1);
        assert_eq!(config.file_guards.extra_extensions.len(), 1);
    }

    #[test]
    fn test_block_rule_exact_match() {
        let rule = BlockRule {
            tool: "Glob".to_string(),
            message: "blocked".to_string(),
            block_domains: vec![],
            requires_tool: None,
        };
        assert!(rule.matches_tool("Glob"));
        assert!(!rule.matches_tool("Grep"));
    }

    #[test]
    fn test_block_rule_contains_glob() {
        let rule = BlockRule {
            tool: "*firecrawl*".to_string(),
            message: "blocked".to_string(),
            block_domains: vec![],
            requires_tool: None,
        };
        assert!(rule.matches_tool("mcp__firecrawl__firecrawl_scrape"));
        assert!(!rule.matches_tool("mcp__other__tool"));
    }

    #[test]
    fn test_block_rule_prefix_glob() {
        let rule = BlockRule {
            tool: "mcp__slack*".to_string(),
            message: "blocked".to_string(),
            block_domains: vec![],
            requires_tool: None,
        };
        assert!(rule.matches_tool("mcp__slack__post_message"));
        assert!(!rule.matches_tool("mcp__github__create_issue"));
    }

    #[test]
    fn test_domain_block_config_parsing() {
        let toml = r#"
[[block_tools]]
tool = "*firecrawl*"
message = "Use gh api."
block_domains = ["github.com", "raw.githubusercontent.com"]
requires_tool = "gh"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        let rules = config.block_rules();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].block_domains.len(), 2);
        assert_eq!(rules[0].requires_tool.as_deref(), Some("gh"));
    }

    #[test]
    fn test_empty_config() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.features.bash_gates);
        assert!(config.features.file_guards);
        assert_eq!(config.block_rules().len(), 3);
    }

    #[test]
    fn test_invalid_config_returns_defaults() {
        let config: Config = toml::from_str("not valid {{{").unwrap_or_default();
        assert!(config.features.bash_gates);
    }

    #[test]
    fn test_hints_feature_toggle() {
        let toml = r#"
[features]
hints = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(!config.features.hints);
        assert!(config.features.bash_gates); // others keep defaults
    }

    #[test]
    fn test_hints_disable_list() {
        let toml = r#"
[hints]
disable = ["man", "du", "tree"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.hints.disable.len(), 3);
        assert!(config.hints.disable.contains(&"man".to_string()));
    }

    #[test]
    fn test_cache_ttl() {
        let toml = r#"
[cache]
ttl_days = 14
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.cache.ttl_days, 14);
    }

    #[test]
    fn test_unknown_keys_ignored() {
        let toml = r#"
[features]
bash_gates = true
some_future_flag = true

[unknown_section]
key = "val"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.features.bash_gates);
    }

    #[test]
    fn test_wildcard_glob_matches_everything() {
        let rule = BlockRule {
            tool: "*".to_string(),
            message: "blocked".to_string(),
            block_domains: vec![],
            requires_tool: None,
        };
        assert!(rule.matches_tool("Glob"));
        assert!(rule.matches_tool("Read"));
        assert!(rule.matches_tool("anything"));
    }

    #[test]
    fn test_security_reminders_default_enabled() {
        let config = Config::default();
        assert!(config.features.security_reminders);
    }

    #[test]
    fn test_security_reminders_toggle_off() {
        let toml = r#"
[features]
security_reminders = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(!config.features.security_reminders);
        assert!(config.features.bash_gates); // others keep defaults
    }

    #[test]
    fn test_security_reminders_config_parsing() {
        let toml = r#"
[security_reminders]
disable_rules = ["eval_injection", "pickle_deserialization"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.security_reminders.disable_rules.len(), 2);
        assert!(
            config
                .security_reminders
                .disable_rules
                .contains(&"eval_injection".to_string())
        );
    }

    #[test]
    fn test_security_reminders_config_defaults() {
        let config = Config::default();
        assert!(config.security_reminders.secrets);
        assert!(config.security_reminders.anti_patterns);
        assert!(config.security_reminders.warnings);
        assert!(config.security_reminders.disable_rules.is_empty());
    }

    #[test]
    fn test_security_reminders_per_tier_toggles() {
        let toml = r#"
[security_reminders]
secrets = true
anti_patterns = false
warnings = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.security_reminders.secrets);
        assert!(!config.security_reminders.anti_patterns);
        assert!(!config.security_reminders.warnings);
    }

    // === Skill approval tests ===

    #[test]
    fn test_skill_approval_exact_match() {
        let rule = SkillApprovalRule {
            skill: "my-tool".to_string(),
            message: None,
            if_project_under: vec![],
            if_project_has: vec![],
        };
        assert!(rule.matches_skill("my-tool"));
        assert!(!rule.matches_skill("my-tool:search"));
    }

    #[test]
    fn test_skill_approval_glob_prefix() {
        let rule = SkillApprovalRule {
            skill: "my-plugin*".to_string(),
            message: None,
            if_project_under: vec![],
            if_project_has: vec![],
        };
        assert!(rule.matches_skill("my-plugin:list"));
        assert!(rule.matches_skill("my-plugin:create"));
        assert!(rule.matches_skill("my-plugin"));
        assert!(!rule.matches_skill("other-tool"));
    }

    #[test]
    fn test_skill_approval_no_conditions_always_matches() {
        let rule = SkillApprovalRule {
            skill: "any-skill".to_string(),
            message: None,
            if_project_under: vec![],
            if_project_has: vec![],
        };
        assert!(rule.conditions_met("/any/path"));
    }

    #[test]
    fn test_skill_approval_if_project_has() {
        let rule = SkillApprovalRule {
            skill: "tracker*".to_string(),
            message: None,
            if_project_under: vec![],
            if_project_has: vec![".tracker".to_string()],
        };
        // /tmp has no .tracker dir -> should not match
        assert!(!rule.conditions_met("/tmp"));
        // /tmp/. exists, so if_project_has = ["."] always matches
        let rule2 = SkillApprovalRule {
            skill: "test".to_string(),
            message: None,
            if_project_under: vec![],
            if_project_has: vec![".".to_string()],
        };
        assert!(rule2.conditions_met("/tmp"));
    }

    #[test]
    fn test_skill_approval_if_project_under() {
        let rule = SkillApprovalRule {
            skill: "deploy-tool".to_string(),
            message: None,
            if_project_under: vec!["/home/test/projects/allowed".to_string()],
            if_project_has: vec![],
        };
        assert!(rule.conditions_met("/home/test/projects/allowed"));
        assert!(rule.conditions_met("/home/test/projects/allowed/subdir"));
        assert!(!rule.conditions_met("/home/test/projects/other"));
    }

    #[test]
    fn test_skill_approval_config_parsing() {
        let toml = r#"
[[auto_approve_skills]]
skill = "tracker*"
if_project_has = [".tracker"]

[[auto_approve_skills]]
skill = "deploy-tool"
if_project_under = ["~/projects/staging"]
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.auto_approve_skills.len(), 2);
        assert_eq!(config.auto_approve_skills[0].skill, "tracker*");
        assert_eq!(
            config.auto_approve_skills[0].if_project_has,
            vec![".tracker"]
        );
        assert_eq!(config.auto_approve_skills[1].skill, "deploy-tool");
        assert_eq!(
            config.auto_approve_skills[1].if_project_under,
            vec!["~/projects/staging"]
        );
    }

    #[test]
    fn test_skill_approval_message_parsing() {
        let toml = r#"
[[auto_approve_skills]]
skill = "my-plugin*"
message = "Plugin project detected"
if_project_has = [".my-plugin"]

[[auto_approve_skills]]
skill = "other-tool"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(
            config.auto_approve_skills[0].message.as_deref(),
            Some("Plugin project detected")
        );
        assert_eq!(config.auto_approve_skills[1].message, None);
    }

    #[test]
    fn test_skill_approval_default_empty() {
        let config = Config::default();
        assert!(config.auto_approve_skills.is_empty());
    }

    #[test]
    fn test_expand_tilde() {
        let expanded = expand_tilde("~/projects/work");
        assert!(!expanded.starts_with('~'));
        assert!(expanded.contains("projects/work"));

        // Non-tilde path unchanged
        assert_eq!(expand_tilde("/absolute/path"), "/absolute/path");
    }

    #[test]
    fn test_glob_utf8_safe() {
        // Non-ASCII in pattern should not panic
        let rule = BlockRule {
            tool: "*\u{00e9}*".to_string(), // *e-accent*
            message: "blocked".to_string(),
            block_domains: vec![],
            requires_tool: None,
        };
        assert!(!rule.matches_tool("Glob")); // doesn't match, but doesn't panic
    }
}
