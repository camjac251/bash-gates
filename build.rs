//! Build script for bash-gates.
//!
//! Reads all rules/*.toml files and generates:
//! - src/generated/rules.rs - Rust code for declarative gates
//! - src/generated/toml_policy.rs - Gemini CLI TOML policy string

use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

fn main() {
    // Set git version info for --version flag
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/");

    // Get git version: tag if on tag, otherwise tag-commits-hash
    let git_version = std::process::Command::new("git")
        .args(["describe", "--tags", "--always"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GIT_VERSION={}", git_version);

    // Rerun if any rule file changes
    println!("cargo:rerun-if-changed=rules/");

    let rules_dir = Path::new("rules");
    if !rules_dir.exists() {
        eprintln!("Warning: rules/ directory not found, skipping code generation");
        return;
    }

    // Watch each file individually for reliable rebuilds
    for entry in fs::read_dir(rules_dir)
        .expect("Failed to read rules directory")
        .flatten()
    {
        println!("cargo:rerun-if-changed={}", entry.path().display());
    }

    // Collect all rule files
    let mut rule_files: Vec<(String, RuleFile)> = Vec::new();

    for entry in fs::read_dir(rules_dir).expect("Failed to read rules directory") {
        let entry = entry.expect("Failed to read directory entry");
        let path = entry.path();

        if path.extension().map(|e| e == "toml").unwrap_or(false) {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();

            let content = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));

            let rules: RuleFile = toml::from_str(&content)
                .unwrap_or_else(|e| panic!("Failed to parse {}: {}", path.display(), e));

            // Validate the rule file
            validate_rule_file(&path, &rules);

            rule_files.push((name, rules));
        }
    }

    // Sort by priority (lower = processed first)
    rule_files.sort_by(|a, b| {
        let pa = a.1.meta.priority.unwrap_or(100);
        let pb = b.1.meta.priority.unwrap_or(100);
        pa.cmp(&pb)
    });

    // Generate Rust code
    let rust_code = generate_rust_code(&rule_files);

    // Generate TOML policy
    let toml_policy = generate_toml_policy(&rule_files);

    // Write to src/generated/
    let out_dir = Path::new("src/generated");
    fs::create_dir_all(out_dir).expect("Failed to create src/generated directory");

    fs::write(out_dir.join("rules.rs"), rust_code).expect("Failed to write rules.rs");

    fs::write(out_dir.join("toml_policy.rs"), toml_policy).expect("Failed to write toml_policy.rs");

    // Always write mod.rs to ensure it includes all generated modules
    let mod_content = r#"//! Auto-generated code from rules/*.toml files.
//!
//! DO NOT EDIT - changes will be overwritten by build.rs

pub mod rules;
pub mod toml_policy;
"#;
    fs::write(out_dir.join("mod.rs"), mod_content).expect("Failed to write mod.rs");
}

// ============================================================================
// Validation
// ============================================================================

fn validate_rule_file(path: &Path, rules: &RuleFile) {
    let file_name = path.display().to_string();

    // Validate safe_commands
    for (i, cmd) in rules.safe_commands.iter().enumerate() {
        if cmd.trim().is_empty() {
            panic!("{}: safe_commands[{}] is empty", file_name, i);
        }
    }

    // Validate each program
    for program in &rules.programs {
        validate_program_rules(path, program);
    }

    // Validate conditional_allow
    for (i, rule) in rules.conditional_allow.iter().enumerate() {
        if rule.program.trim().is_empty() {
            panic!(
                "{}: conditional_allow[{}] has empty program name",
                file_name, i
            );
        }
    }
}

fn validate_program_rules(path: &Path, program: &ProgramRules) {
    let file_name = path.display().to_string();
    let prog_name = &program.name;

    if prog_name.trim().is_empty() {
        panic!("{}: program has empty name", file_name);
    }

    // Track subcommands for conflict detection
    let mut allow_cmds: HashSet<String> = HashSet::new();
    let mut ask_cmds: HashSet<String> = HashSet::new();
    let mut block_cmds: HashSet<String> = HashSet::new();

    // Validate allow rules
    for (i, rule) in program.allow.iter().enumerate() {
        let parts = rule.subcommand_parts();
        // Allow rules with no subcommand are valid (they match the bare program)
        // Allow rules with only prefix are also valid
        if !parts.is_empty() {
            let key = parts.join(" ");
            if allow_cmds.contains(&key) {
                panic!(
                    "{}: {}: duplicate allow rule for '{}'",
                    file_name, prog_name, key
                );
            }
            allow_cmds.insert(key);
        } else if rule.subcommand_prefix.is_none()
            && rule.action_prefix.is_none()
            && rule.if_flags_any.is_empty()
        {
            // This is a bare allow rule with no conditions - it's valid
            if allow_cmds.contains("") {
                panic!("{}: {}: duplicate bare allow rule", file_name, prog_name);
            }
            allow_cmds.insert(String::new());
        }
        // Check for empty unless_flags entries
        for (j, flag) in rule.unless_flags.iter().enumerate() {
            if flag.trim().is_empty() {
                panic!(
                    "{}: {}: allow[{}].unless_flags[{}] is empty",
                    file_name, prog_name, i, j
                );
            }
        }
    }

    // Validate ask rules
    let mut has_bare_ask = false;
    for (i, rule) in program.ask.iter().enumerate() {
        let parts = rule.subcommand_parts();

        // Reason is required
        if rule.reason.trim().is_empty() {
            let subcmd = if !parts.is_empty() {
                parts.join(" ")
            } else {
                format!("rule #{}", i)
            };
            panic!(
                "{}: {}: ask '{}' has empty reason",
                file_name, prog_name, subcmd
            );
        }

        // Track bare ask rules (no subcommand, no prefix, no flags - matches any invocation)
        if parts.is_empty()
            && rule.subcommand_prefix.is_none()
            && rule.action_prefix.is_none()
            && rule.if_flags_any.is_empty()
        {
            if has_bare_ask {
                panic!("{}: {}: duplicate bare ask rule", file_name, prog_name);
            }
            has_bare_ask = true;
            continue; // Bare ask is valid - it matches the program itself
        }

        // Only check for duplicates on simple asks (no flags or prefix)
        // Flagged/prefixed asks can have the same subcommand as they have different conditions
        if !parts.is_empty()
            && rule.if_flags_any.is_empty()
            && rule.subcommand_prefix.is_none()
            && rule.action_prefix.is_none()
        {
            let key = parts.join(" ");
            if ask_cmds.contains(&key) {
                panic!(
                    "{}: {}: duplicate ask rule for '{}'",
                    file_name, prog_name, key
                );
            }
            ask_cmds.insert(key);
        }
    }

    // Validate block rules
    let mut has_bare_block = false;
    for (i, rule) in program.block.iter().enumerate() {
        let parts = rule.subcommand_parts();

        // Track bare block rules (matches any invocation of the program)
        if parts.is_empty() && rule.subcommand_prefix.is_none() {
            if has_bare_block {
                panic!("{}: {}: duplicate bare block rule", file_name, prog_name);
            }
            has_bare_block = true;
            // Bare block is valid - it matches the program itself (e.g., shutdown)
        }

        if rule.reason.trim().is_empty() {
            let key = if !parts.is_empty() {
                parts.join(" ")
            } else if let Some(ref prefix) = rule.subcommand_prefix {
                format!("{}*", prefix)
            } else {
                format!("rule #{}", i)
            };
            panic!(
                "{}: {}: block '{}' has empty reason",
                file_name, prog_name, key
            );
        }

        // Track for duplicate/conflict detection (only for rules with subcommand, not prefix-only)
        if !parts.is_empty() {
            let key = parts.join(" ");
            if block_cmds.contains(&key) {
                panic!(
                    "{}: {}: duplicate block rule for '{}'",
                    file_name, prog_name, key
                );
            }
            block_cmds.insert(key.clone());

            // Check for conflicts with allow rules
            if allow_cmds.contains(&key) {
                panic!(
                    "{}: {}: conflicting rules - '{}' is in both allow and block",
                    file_name, prog_name, key
                );
            }
        }
    }
}

// ============================================================================
// Types (duplicated from src/codegen/types.rs for build.rs independence)
// ============================================================================

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct RuleFile {
    #[serde(default)]
    meta: RuleMeta,
    #[serde(default)]
    programs: Vec<ProgramRules>,
    #[serde(default)]
    safe_commands: Vec<String>,
    #[serde(default)]
    conditional_allow: Vec<ConditionalRule>,
    #[serde(default)]
    custom_handlers: Vec<CustomHandler>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct RuleMeta {
    name: Option<String>,
    description: Option<String>,
    priority: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct ProgramRules {
    name: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    allow: Vec<AllowRule>,
    #[serde(default)]
    ask: Vec<AskRule>,
    #[serde(default)]
    block: Vec<BlockRule>,
    #[serde(default)]
    allow_if_flags: Vec<FlagOverride>,
    #[serde(default)]
    api_rules: Option<ApiRules>,
    #[serde(default)]
    default_allow: bool,
    #[serde(default)]
    unknown_action: UnknownAction,
}

#[derive(Debug, Default, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum UnknownAction {
    #[default]
    Ask,
    Allow,
    Skip,
    Block,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowRule {
    #[serde(default)]
    subcommand: Option<String>,
    #[serde(default)]
    subcommands: Vec<String>,
    #[serde(default)]
    subcommand_prefix: Option<String>,
    /// Check if args[1] (the "action" in commands like `aws <service> <action>`)
    /// starts with this prefix. Useful for AWS-style commands where the action
    /// is the second argument regardless of which service is used.
    #[serde(default)]
    action_prefix: Option<String>,
    #[serde(default)]
    unless_flags: Vec<String>,
    #[serde(default)]
    unless_args_contain: Vec<String>,
    #[serde(default)]
    if_flags_any: Vec<String>,
    /// Optional reason for allowing (shown in decision output)
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AskRule {
    #[serde(default)]
    subcommand: Option<String>,
    #[serde(default)]
    subcommands: Vec<String>,
    #[serde(default)]
    subcommand_prefix: Option<String>,
    /// Check if args[1] (the "action" in commands like `aws <service> <action>`)
    /// starts with this prefix. Useful for AWS-style commands where the action
    /// is the second argument regardless of which service is used.
    #[serde(default)]
    action_prefix: Option<String>,
    reason: String,
    #[serde(default)]
    #[allow(dead_code)] // Used in TOML but not in Gemini export (inherits default ask)
    warn: bool,
    #[serde(default)]
    if_flags: Vec<String>,
    #[serde(default)]
    if_flags_any: Vec<String>,
    /// If true, this ask rule should be auto-allowed in acceptEdits mode
    /// (when the command targets files within the allowed directories).
    #[serde(default)]
    accept_edits_auto_allow: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockRule {
    #[serde(default)]
    subcommand: Option<String>,
    #[serde(default)]
    subcommands: Vec<String>,
    #[serde(default)]
    subcommand_prefix: Option<String>,
    reason: String,
    #[serde(default)]
    if_args_contain: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct FlagOverride {
    flags_any: Vec<String>,
    #[serde(default)]
    for_subcommands: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiRules {
    trigger: String,
    #[serde(default)]
    method_flags: Vec<String>,
    #[serde(default)]
    safe_methods: Vec<String>,
    #[serde(default)]
    default_method: Option<String>,
    /// Flags that implicitly trigger POST (e.g., -f, --field for gh api)
    #[serde(default)]
    implicit_post_flags: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct ConditionalRule {
    program: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    unless_flags: Vec<String>,
    #[serde(default)]
    on_flag_present: OnFlagAction,
    #[serde(default)]
    description: Option<String>,
    /// If true, this conditional ask should be auto-allowed in acceptEdits mode
    #[serde(default)]
    accept_edits_auto_allow: bool,
}

#[derive(Debug, Default, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum OnFlagAction {
    #[default]
    Skip,
    Ask,
    Block,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct CustomHandler {
    program: String,
    handler: String,
    #[serde(default)]
    description: Option<String>,
}

impl AllowRule {
    fn subcommand_parts(&self) -> Vec<&str> {
        if let Some(ref s) = self.subcommand {
            s.split_whitespace().collect()
        } else if !self.subcommands.is_empty() {
            self.subcommands.iter().map(String::as_str).collect()
        } else {
            vec![]
        }
    }
}

impl AskRule {
    fn subcommand_parts(&self) -> Vec<&str> {
        if let Some(ref s) = self.subcommand {
            s.split_whitespace().collect()
        } else if !self.subcommands.is_empty() {
            self.subcommands.iter().map(String::as_str).collect()
        } else {
            vec![]
        }
    }
}

impl BlockRule {
    fn subcommand_parts(&self) -> Vec<&str> {
        if let Some(ref s) = self.subcommand {
            s.split_whitespace().collect()
        } else if !self.subcommands.is_empty() {
            self.subcommands.iter().map(String::as_str).collect()
        } else {
            vec![]
        }
    }
}

// ============================================================================
// Rust Code Generation
// ============================================================================

fn generate_rust_code(rule_files: &[(String, RuleFile)]) -> String {
    let mut output = String::new();

    // Header
    output.push_str("//! Auto-generated from rules/*.toml files.\n");
    output.push_str("//! DO NOT EDIT - changes will be overwritten by build.rs\n\n");

    output.push_str("#![allow(dead_code)]\n");
    output.push_str("#![allow(clippy::too_many_lines)]\n");
    output.push_str("#![allow(clippy::nonminimal_bool)]\n\n");

    output.push_str("use std::collections::{HashMap, HashSet};\n");
    output.push_str("use std::sync::LazyLock;\n");
    output.push_str("use crate::models::{CommandInfo, GateResult};\n\n");

    // Collect all safe commands
    let mut all_safe_commands: Vec<&str> = Vec::new();
    for (_, rules) in rule_files {
        for cmd in &rules.safe_commands {
            all_safe_commands.push(cmd);
        }
    }
    all_safe_commands.sort();
    all_safe_commands.dedup();

    if !all_safe_commands.is_empty() {
        output.push_str(&generate_safe_commands(&all_safe_commands));
        output.push('\n');
    }

    // Collect all conditional allows
    let mut all_conditionals: Vec<&ConditionalRule> = Vec::new();
    for (_, rules) in rule_files {
        for cond in &rules.conditional_allow {
            all_conditionals.push(cond);
        }
    }

    if !all_conditionals.is_empty() {
        output.push_str(&generate_conditional_rules(&all_conditionals));
        output.push('\n');
    }

    // Generate per-program rules
    for (name, rules) in rule_files {
        for program in &rules.programs {
            output.push_str(&generate_program_rules(name, program));
            output.push('\n');
        }
    }

    // Generate master check function
    output.push_str(&generate_master_check(rule_files));

    // Generate unified gate functions
    output.push_str(&generate_gate_functions(rule_files));

    // Generate file-editing detection code
    output.push_str(&generate_file_editing_code(rule_files));

    output
}

fn generate_safe_commands(commands: &[&str]) -> String {
    let mut output = String::new();

    output.push_str("/// Safe commands that are always allowed\n");
    output.push_str("pub static SAFE_COMMANDS: LazyLock<HashSet<&str>> = LazyLock::new(|| {\n");
    output.push_str("    [\n");

    for cmd in commands {
        output.push_str(&format!("        \"{}\",\n", escape_rust_string(cmd)));
    }

    output.push_str("    ].into_iter().collect()\n");
    output.push_str("});\n\n");

    output.push_str("/// Check if a command is in the safe commands list\n");
    output.push_str("pub fn check_safe_command(cmd: &CommandInfo) -> Option<GateResult> {\n");
    output.push_str("    // Strip path prefix to handle /usr/bin/cat etc.\n");
    output.push_str("    let program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);\n");
    output.push_str("    if SAFE_COMMANDS.contains(program) {\n");
    output.push_str("        Some(GateResult::allow())\n");
    output.push_str("    } else {\n");
    output.push_str("        None\n");
    output.push_str("    }\n");
    output.push_str("}\n");

    output
}

fn generate_conditional_rules(rules: &[&ConditionalRule]) -> String {
    let mut output = String::new();

    output.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n");
    output.push_str("pub enum ConditionalAction {\n");
    output.push_str("    Skip,\n");
    output.push_str("    Ask,\n");
    output.push_str("    Block,\n");
    output.push_str("}\n\n");

    output
        .push_str("/// Conditional allow rules (program -> (flags that prevent allow, action))\n");
    output.push_str(
        "pub static CONDITIONAL_ALLOW: LazyLock<HashMap<&str, (&[&str], ConditionalAction)>> = LazyLock::new(|| {\n",
    );
    output.push_str("    [\n");

    for rule in rules {
        let flags: Vec<String> = rule
            .unless_flags
            .iter()
            .map(|f| format!("\"{}\"", escape_rust_string(f)))
            .collect();
        let action = match rule.on_flag_present {
            OnFlagAction::Skip => "ConditionalAction::Skip",
            OnFlagAction::Ask => "ConditionalAction::Ask",
            OnFlagAction::Block => "ConditionalAction::Block",
        };
        output.push_str(&format!(
            "        (\"{}\", (&[{}] as &[&str], {})),\n",
            escape_rust_string(&rule.program),
            flags.join(", "),
            action
        ));
        for alias in &rule.aliases {
            output.push_str(&format!(
                "        (\"{}\", (&[{}] as &[&str], {})),\n",
                escape_rust_string(alias),
                flags.join(", "),
                action
            ));
        }
    }

    output.push_str("    ].into_iter().collect()\n");
    output.push_str("});\n\n");

    output.push_str("/// Check conditional allow rules\n");
    output.push_str("pub fn check_conditional_allow(cmd: &CommandInfo) -> Option<GateResult> {\n");
    output.push_str("    // Strip path prefix to handle /usr/bin/sed etc.\n");
    output.push_str("    let program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);\n");
    output.push_str("    if let Some((flags, action)) = CONDITIONAL_ALLOW.get(program) {\n");
    output.push_str(
        "        let has_flag = cmd.args.iter().any(|arg| flags.contains(&arg.as_str()));\n",
    );
    output.push_str("        if has_flag {\n");
    output.push_str("            match action {\n");
    output.push_str("                ConditionalAction::Skip => None,\n");
    output.push_str("                ConditionalAction::Ask => Some(GateResult::ask(format!(\"{}: in-place edit\", cmd.program))),\n");
    output.push_str("                ConditionalAction::Block => Some(GateResult::block(format!(\"{}: blocked\", cmd.program))),\n");
    output.push_str("            }\n");
    output.push_str("        } else {\n");
    output.push_str("            Some(GateResult::allow())\n");
    output.push_str("        }\n");
    output.push_str("    } else {\n");
    output.push_str("        None\n");
    output.push_str("    }\n");
    output.push_str("}\n");

    output
}

fn generate_program_rules(file_name: &str, program: &ProgramRules) -> String {
    let mut output = String::new();
    let name = &program.name;
    let name_upper = name.to_uppercase().replace('-', "_");
    let fn_name = name.replace('-', "_");

    output.push_str(&format!(
        "// === {} (from {}.toml) ===\n\n",
        name.to_uppercase(),
        file_name
    ));

    // Collect simple allows (no conditions, no reason)
    let simple_allows: Vec<String> = program
        .allow
        .iter()
        .filter(|r| {
            r.subcommand_prefix.is_none()
                && r.action_prefix.is_none()
                && r.unless_flags.is_empty()
                && r.unless_args_contain.is_empty()
                && r.if_flags_any.is_empty()
                && r.reason.is_none() // Allows with reasons go to complex path
        })
        .map(|r| r.subcommand_parts().join(" "))
        .filter(|s| !s.is_empty())
        .collect();

    // Collect simple asks (with subcommand)
    let simple_asks: Vec<(String, String)> = program
        .ask
        .iter()
        .filter(|r| {
            r.subcommand_prefix.is_none()
                && r.action_prefix.is_none()
                && r.if_flags.is_empty()
                && r.if_flags_any.is_empty()
        })
        .map(|r| (r.subcommand_parts().join(" "), r.reason.clone()))
        .filter(|(s, _)| !s.is_empty())
        .collect();

    // Find bare ask rule (matches any invocation of the program)
    let bare_ask: Option<&AskRule> = program.ask.iter().find(|r| {
        r.subcommand_parts().is_empty()
            && r.subcommand_prefix.is_none()
            && r.action_prefix.is_none()
            && r.if_flags_any.is_empty()
    });

    // Collect simple blocks
    let simple_blocks: Vec<(String, String)> = program
        .block
        .iter()
        .filter(|r| r.if_args_contain.is_empty())
        .map(|r| (r.subcommand_parts().join(" "), r.reason.clone()))
        .filter(|(s, _)| !s.is_empty())
        .collect();

    // Collect complex blocks (with if_args_contain or subcommand_prefix)
    let complex_blocks: Vec<&BlockRule> = program
        .block
        .iter()
        .filter(|r| !r.if_args_contain.is_empty() || r.subcommand_prefix.is_some())
        .collect();

    // Find bare block rule (matches any invocation of the program)
    let bare_block: Option<&BlockRule> = program.block.iter().find(|r| {
        r.subcommand_parts().is_empty()
            && r.subcommand_prefix.is_none()
            && r.if_args_contain.is_empty()
    });

    // Generate statics
    if !simple_allows.is_empty() {
        output.push_str(&format!(
            "pub static {}_ALLOW: LazyLock<HashSet<&str>> = LazyLock::new(|| {{\n",
            name_upper
        ));
        output.push_str("    [\n");
        for subcmd in &simple_allows {
            output.push_str(&format!("        \"{}\",\n", escape_rust_string(subcmd)));
        }
        output.push_str("    ].into_iter().collect()\n");
        output.push_str("});\n\n");
    }

    if !simple_asks.is_empty() {
        output.push_str(&format!(
            "pub static {}_ASK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {{\n",
            name_upper
        ));
        output.push_str("    [\n");
        for (subcmd, reason) in &simple_asks {
            output.push_str(&format!(
                "        (\"{}\", \"{}\"),\n",
                escape_rust_string(subcmd),
                escape_rust_string(reason)
            ));
        }
        output.push_str("    ].into_iter().collect()\n");
        output.push_str("});\n\n");
    }

    if !simple_blocks.is_empty() {
        output.push_str(&format!(
            "pub static {}_BLOCK: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {{\n",
            name_upper
        ));
        output.push_str("    [\n");
        for (subcmd, reason) in &simple_blocks {
            output.push_str(&format!(
                "        (\"{}\", \"{}\"),\n",
                escape_rust_string(subcmd),
                escape_rust_string(reason)
            ));
        }
        output.push_str("    ].into_iter().collect()\n");
        output.push_str("});\n\n");
    }

    // Generate check function
    output.push_str(&format!("/// Check {} commands declaratively\n", name));
    output.push_str(&format!(
        "pub fn check_{}_declarative(cmd: &CommandInfo) -> Option<GateResult> {{\n",
        fn_name
    ));

    // Check program name and aliases
    let mut programs = vec![format!("\"{}\"", name)];
    for alias in &program.aliases {
        programs.push(format!("\"{}\"", alias));
    }
    output.push_str(&format!(
        "    if ![{}].contains(&cmd.program.as_str()) {{\n",
        programs.join(", ")
    ));
    output.push_str("        return None;\n");
    output.push_str("    }\n\n");

    // Check allow_if_flags first
    if !program.allow_if_flags.is_empty() {
        output.push_str("    // Check allow_if_flags (e.g., --dry-run)\n");
        for flag_override in &program.allow_if_flags {
            let flags: Vec<String> = flag_override
                .flags_any
                .iter()
                .map(|f| format!("\"{}\"", escape_rust_string(f)))
                .collect();
            output.push_str(&format!(
                "    if cmd.args.iter().any(|a| [{}].contains(&a.as_str())) {{\n",
                flags.join(", ")
            ));
            output.push_str("        return Some(GateResult::allow());\n");
            output.push_str("    }\n");
        }
        output.push('\n');
    }

    // Handle bare block rule (blocks any invocation of the program)
    if let Some(block) = bare_block {
        output.push_str(&format!(
            "    // Bare block rule - any {} invocation is blocked\n",
            name
        ));
        output.push_str(&format!(
            "    Some(GateResult::block(\"{}: {}\"))\n",
            name,
            escape_rust_string(&block.reason)
        ));
        output.push_str("}\n");
        return output; // Skip all subcommand matching code
    }

    // Get subcommand for matching
    output.push_str("    #[allow(unused_variables)]\n");
    output.push_str("    let subcmd = if cmd.args.is_empty() {\n");
    output.push_str("        String::new()\n");
    output.push_str("    } else if cmd.args.len() == 1 {\n");
    output.push_str("        cmd.args[0].clone()\n");
    output.push_str("    } else {\n");
    output.push_str("        format!(\"{} {}\", cmd.args[0], cmd.args[1])\n");
    output.push_str("    };\n");
    output.push_str("    #[allow(unused_variables)]\n");
    output.push_str(
        "    let subcmd_single = cmd.args.first().map(String::as_str).unwrap_or(\"\");\n\n",
    );

    // Check blocks first (highest priority)
    if !simple_blocks.is_empty() {
        output.push_str(&format!(
            "    if let Some(reason) = {}_BLOCK.get(subcmd.as_str()) {{\n",
            name_upper
        ));
        output.push_str(&format!(
            "        return Some(GateResult::block(format!(\"{}: {{}}\", reason)));\n",
            name
        ));
        output.push_str("    }\n\n");
    }

    // Check complex blocks (with if_args_contain or subcommand_prefix)
    if !complex_blocks.is_empty() {
        output.push_str("    // Check conditional block rules\n");
        for block in &complex_blocks {
            let parts = block.subcommand_parts();

            // Handle subcommand_prefix blocks
            if let Some(ref prefix) = block.subcommand_prefix {
                if parts.is_empty() {
                    // Use subcmd for multi-word prefixes, subcmd_single for single-word
                    let var = if prefix.contains(' ') {
                        "subcmd"
                    } else {
                        "subcmd_single"
                    };
                    output.push_str(&format!(
                        "    if {}.starts_with(\"{}\") {{\n",
                        var,
                        escape_rust_string(prefix)
                    ));
                } else {
                    let check = generate_subcommand_match(&parts);
                    output.push_str(&format!(
                        "    if {} && cmd.args.get({}).is_some_and(|a| a.starts_with(\"{}\")) {{\n",
                        check,
                        parts.len(),
                        escape_rust_string(prefix)
                    ));
                }
                output.push_str(&format!(
                    "        return Some(GateResult::block(\"{}: {}\"));\n",
                    name,
                    escape_rust_string(&block.reason)
                ));
                output.push_str("    }\n");
                continue;
            }

            // Handle if_args_contain blocks
            if parts.is_empty() {
                continue;
            }
            let subcmd_check = generate_subcommand_match(&parts);
            let args_checks: Vec<String> = block
                .if_args_contain
                .iter()
                .map(|a| {
                    format!(
                        "cmd.args.iter().any(|x| x == \"{}\")",
                        escape_rust_string(a)
                    )
                })
                .collect();
            output.push_str(&format!(
                "    if {} && ({}) {{\n",
                subcmd_check,
                args_checks.join(" || ")
            ));
            output.push_str(&format!(
                "        return Some(GateResult::block(\"{}: {}\"));\n",
                name,
                escape_rust_string(&block.reason)
            ));
            output.push_str("    }\n");
        }
        output.push('\n');
    }

    // Check complex asks (with flags or prefixes)
    let complex_asks: Vec<&AskRule> = program
        .ask
        .iter()
        .filter(|r| {
            !r.if_flags_any.is_empty() || r.subcommand_prefix.is_some() || r.action_prefix.is_some()
        })
        .collect();

    if !complex_asks.is_empty() {
        output.push_str("    // Check ask rules with flag/prefix conditions\n");
        for ask in complex_asks {
            if !ask.if_flags_any.is_empty() {
                let parts = ask.subcommand_parts();
                let subcmd_check = if parts.is_empty() {
                    "true".to_string()
                } else {
                    generate_subcommand_match(&parts)
                };
                let flags: Vec<String> = ask
                    .if_flags_any
                    .iter()
                    .map(|f| format!("\"{}\"", escape_rust_string(f)))
                    .collect();
                output.push_str(&format!(
                    "    if {} && cmd.args.iter().any(|a| [{}].contains(&a.as_str())) {{\n",
                    subcmd_check,
                    flags.join(", ")
                ));
                output.push_str(&format!(
                    "        return Some(GateResult::ask(\"{}\"));\n",
                    escape_rust_string(&ask.reason)
                ));
                output.push_str("    }\n");
            }
            // Handle subcommand_prefix for ask rules
            if let Some(ref prefix) = ask.subcommand_prefix {
                let parts = ask.subcommand_parts();
                if parts.is_empty() {
                    // Use subcmd for multi-word prefixes, subcmd_single for single-word
                    let var = if prefix.contains(' ') {
                        "subcmd"
                    } else {
                        "subcmd_single"
                    };
                    output.push_str(&format!(
                        "    if {}.starts_with(\"{}\") {{\n",
                        var,
                        escape_rust_string(prefix)
                    ));
                } else {
                    let check = generate_subcommand_match(&parts);
                    output.push_str(&format!(
                        "    if {} && cmd.args.get({}).is_some_and(|a| a.starts_with(\"{}\")) {{\n",
                        check,
                        parts.len(),
                        escape_rust_string(prefix)
                    ));
                }
                output.push_str(&format!(
                    "        return Some(GateResult::ask(\"{}: {}\"));\n",
                    name,
                    escape_rust_string(&ask.reason)
                ));
                output.push_str("    }\n");
            }
            // Handle action_prefix - checks if args[1] starts with prefix
            // Useful for AWS-style commands: aws <service> <action>
            if let Some(ref prefix) = ask.action_prefix {
                output.push_str(&format!(
                    "    if cmd.args.get(1).is_some_and(|a| a.starts_with(\"{}\")) {{\n",
                    escape_rust_string(prefix)
                ));
                output.push_str(&format!(
                    "        return Some(GateResult::ask(\"{}: {}\"));\n",
                    name,
                    escape_rust_string(&ask.reason)
                ));
                output.push_str("    }\n");
            }
        }
        output.push('\n');
    }

    // Check simple allows
    if !simple_allows.is_empty() {
        output.push_str(&format!(
            "    if {}_ALLOW.contains(subcmd.as_str()) || {}_ALLOW.contains(subcmd_single) {{\n",
            name_upper, name_upper
        ));
        output.push_str("        return Some(GateResult::allow());\n");
        output.push_str("    }\n\n");
    }

    // Check complex allows (with conditions)
    let complex_allows: Vec<&AllowRule> = program
        .allow
        .iter()
        .filter(|r| {
            r.subcommand_prefix.is_some()
                || r.action_prefix.is_some()
                || !r.unless_flags.is_empty()
                || !r.if_flags_any.is_empty()
                || r.reason.is_some() // Allows with reasons need special handling
        })
        .collect();

    if !complex_allows.is_empty() {
        output.push_str("    // Check conditional allow rules\n");
        for allow in complex_allows {
            let parts = allow.subcommand_parts();

            let allow_call = generate_allow_call(&allow.reason);

            if let Some(ref prefix) = allow.subcommand_prefix {
                if parts.is_empty() {
                    // Use subcmd for multi-word prefixes, subcmd_single for single-word
                    let var = if prefix.contains(' ') {
                        "subcmd"
                    } else {
                        "subcmd_single"
                    };
                    output.push_str(&format!(
                        "    if {}.starts_with(\"{}\") {{\n",
                        var,
                        escape_rust_string(prefix)
                    ));
                } else {
                    let check = generate_subcommand_match(&parts);
                    output.push_str(&format!(
                        "    if {} && cmd.args.get({}).is_some_and(|a| a.starts_with(\"{}\")) {{\n",
                        check,
                        parts.len(),
                        escape_rust_string(prefix)
                    ));
                }
                output.push_str(&format!("        return {};\n", allow_call));
                output.push_str("    }\n");
            }

            // Handle action_prefix - checks if args[1] starts with prefix
            // Useful for AWS-style commands: aws <service> <action>
            if let Some(ref prefix) = allow.action_prefix {
                output.push_str(&format!(
                    "    if cmd.args.get(1).is_some_and(|a| a.starts_with(\"{}\")) {{\n",
                    escape_rust_string(prefix)
                ));
                output.push_str(&format!("        return {};\n", allow_call));
                output.push_str("    }\n");
            }

            if !allow.unless_flags.is_empty() && !parts.is_empty() {
                let check = generate_subcommand_match(&parts);
                let flags: Vec<String> = allow
                    .unless_flags
                    .iter()
                    .map(|f| format!("\"{}\"", escape_rust_string(f)))
                    .collect();
                output.push_str(&format!(
                    "    if {} && !cmd.args.iter().any(|a| [{}].contains(&a.as_str())) {{\n",
                    check,
                    flags.join(", ")
                ));
                output.push_str(&format!("        return {};\n", allow_call));
                output.push_str("    }\n");
            }

            // Handle if_flags_any (allow if any of these flags present)
            if !allow.if_flags_any.is_empty() {
                let flags: Vec<String> = allow
                    .if_flags_any
                    .iter()
                    .map(|f| format!("\"{}\"", escape_rust_string(f)))
                    .collect();
                // Include subcommand check if subcommand is specified
                let subcmd_check = if parts.is_empty() {
                    "true".to_string()
                } else {
                    generate_subcommand_match(&parts)
                };
                output.push_str(&format!(
                    "    if {} && cmd.args.iter().any(|a| [{}].contains(&a.as_str())) {{\n",
                    subcmd_check,
                    flags.join(", ")
                ));
                output.push_str(&format!("        return {};\n", allow_call));
                output.push_str("    }\n");
            }

            // Handle allows with just a reason (simple subcommand match with custom reason)
            if allow.reason.is_some()
                && allow.subcommand_prefix.is_none()
                && allow.action_prefix.is_none()
                && allow.unless_flags.is_empty()
                && allow.if_flags_any.is_empty()
                && !parts.is_empty()
            {
                let check = generate_subcommand_match(&parts);
                output.push_str(&format!("    if {} {{\n", check));
                output.push_str(&format!("        return {};\n", allow_call));
                output.push_str("    }\n");
            }
        }
        output.push('\n');
    }

    // Check simple asks
    if !simple_asks.is_empty() {
        output.push_str(&format!(
            "    if let Some(reason) = {}_ASK.get(subcmd.as_str()).or_else(|| {}_ASK.get(subcmd_single)) {{\n",
            name_upper, name_upper
        ));
        output.push_str(&format!(
            "        return Some(GateResult::ask(format!(\"{}: {{}}\", reason)));\n",
            name
        ));
        output.push_str("    }\n\n");
    }

    // Handle API rules
    if let Some(ref api) = program.api_rules {
        output.push_str(&generate_api_rules(name, api));
        output.push('\n');
    }

    // Handle bare ask rule (matches any invocation of the program)
    if let Some(ask) = bare_ask {
        output.push_str(&format!(
            "    // Bare ask rule - any {} invocation asks\n",
            name
        ));
        output.push_str(&format!(
            "    Some(GateResult::ask(\"{}: {}\"))\n",
            name,
            escape_rust_string(&ask.reason)
        ));
    } else {
        // Handle unknown action (bare_block already returned early above)
        match program.unknown_action {
            UnknownAction::Ask => {
                output.push_str(&format!(
                    "    Some(GateResult::ask(format!(\"{}: {{}}\", subcmd_single)))\n",
                    name
                ));
            }
            UnknownAction::Allow => {
                output.push_str("    Some(GateResult::allow())\n");
            }
            UnknownAction::Skip => {
                output.push_str("    None\n");
            }
            UnknownAction::Block => {
                output.push_str(&format!(
                    "    Some(GateResult::block(format!(\"{}: unknown subcommand {{}}\", subcmd_single)))\n",
                    name
                ));
            }
        }
    }

    output.push_str("}\n");

    output
}

fn generate_subcommand_match(parts: &[&str]) -> String {
    match parts.len() {
        0 => "true".to_string(),
        1 => format!("subcmd_single == \"{}\"", escape_rust_string(parts[0])),
        2 => format!(
            "cmd.args.len() >= 2 && cmd.args[0] == \"{}\" && cmd.args[1] == \"{}\"",
            escape_rust_string(parts[0]),
            escape_rust_string(parts[1])
        ),
        _ => {
            let checks: Vec<String> = parts
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    format!(
                        "cmd.args.get({}) == Some(&\"{}\".to_string())",
                        i,
                        escape_rust_string(p)
                    )
                })
                .collect();
            format!(
                "cmd.args.len() >= {} && {}",
                parts.len(),
                checks.join(" && ")
            )
        }
    }
}

fn generate_api_rules(name: &str, api: &ApiRules) -> String {
    let mut output = String::new();

    output.push_str(&format!(
        "    // API rules for '{} {}'\n",
        name, api.trigger
    ));
    output.push_str(&format!(
        "    if subcmd_single == \"{}\" {{\n",
        escape_rust_string(&api.trigger)
    ));

    let method_flags: Vec<String> = api
        .method_flags
        .iter()
        .map(|f| format!("\"{}\"", escape_rust_string(f)))
        .collect();
    let safe_methods: Vec<String> = api
        .safe_methods
        .iter()
        .map(|m| format!("\"{}\"", m.to_uppercase()))
        .collect();

    // Check for explicit method flag first
    output.push_str("        let explicit_method = cmd.args.iter()\n");
    output.push_str("            .position(|a| [");
    output.push_str(&method_flags.join(", "));
    output.push_str("].contains(&a.as_str()))\n");
    output.push_str("            .and_then(|i| cmd.args.get(i + 1))\n");
    output.push_str("            .map(|s| s.to_uppercase());\n");

    // Check for implicit POST flags (e.g., -f, --field for gh api)
    if !api.implicit_post_flags.is_empty() {
        let implicit_flags: Vec<String> = api
            .implicit_post_flags
            .iter()
            .map(|f| format!("\"{}\"", escape_rust_string(f)))
            .collect();
        output.push_str("        let has_implicit_post = cmd.args.iter().any(|a| {\n");
        output.push_str("            let arg = a.as_str();\n");
        output.push_str(&format!(
            "            [{}].iter().any(|f| arg == *f || arg.starts_with(&format!(\"{{}}=\", f)))\n",
            implicit_flags.join(", ")
        ));
        output.push_str("        });\n");
        output.push_str("        let method = explicit_method.unwrap_or_else(|| {\n");
        output.push_str("            if has_implicit_post {\n");
        output.push_str("                \"POST\".to_string()\n");
        output.push_str("            } else {\n");
        if let Some(ref default) = api.default_method {
            output.push_str(&format!(
                "                \"{}\".to_string()\n",
                default.to_uppercase()
            ));
        } else {
            output.push_str("                String::new()\n");
        }
        output.push_str("            }\n");
        output.push_str("        });\n");
    } else if let Some(ref default) = api.default_method {
        output.push_str(&format!(
            "        let method = explicit_method.unwrap_or_else(|| \"{}\".to_string());\n",
            default.to_uppercase()
        ));
    } else {
        output.push_str("        let method = explicit_method.unwrap_or_default();\n");
    }

    output.push_str(&format!(
        "        if [{}].contains(&method.as_str()) {{\n",
        safe_methods.join(", ")
    ));
    output.push_str("            return Some(GateResult::allow());\n");
    output.push_str("        }\n");
    output.push_str(&format!(
        "        return Some(GateResult::ask(format!(\"{} {}: {{}} request\", method)));\n",
        name, api.trigger
    ));
    output.push_str("    }\n");

    output
}

fn generate_master_check(rule_files: &[(String, RuleFile)]) -> String {
    let mut output = String::new();

    output.push_str("/// Check command against all declarative rules\n");
    output
        .push_str("/// Returns Some(GateResult) if handled by declarative rules, None otherwise\n");
    output.push_str("pub fn check_declarative(cmd: &CommandInfo) -> Option<GateResult> {\n");

    // First check safe commands
    output.push_str("    // Check safe commands first\n");
    output.push_str("    if let Some(result) = check_safe_command(cmd) {\n");
    output.push_str("        return Some(result);\n");
    output.push_str("    }\n\n");

    // Check conditional allows
    output.push_str("    // Check conditional allow rules\n");
    output.push_str("    if let Some(result) = check_conditional_allow(cmd) {\n");
    output.push_str("        return Some(result);\n");
    output.push_str("    }\n\n");

    // Check each program
    output.push_str("    // Check program-specific rules\n");
    for (_, rules) in rule_files {
        for program in &rules.programs {
            let fn_name = program.name.replace('-', "_");
            output.push_str(&format!(
                "    if let Some(result) = check_{}_declarative(cmd) {{\n",
                fn_name
            ));
            output.push_str("        return Some(result);\n");
            output.push_str("    }\n");
        }
    }

    output.push_str("\n    None\n");
    output.push_str("}\n");

    output
}

fn generate_gate_functions(rule_files: &[(String, RuleFile)]) -> String {
    let mut output = String::new();

    output.push_str("// === Generated Gate Functions ===\n");
    output.push_str("// These replace manual routing in gate files.\n");
    output.push_str("// Add tool to TOML, rebuild, done - no Rust changes needed.\n\n");

    for (name, rules) in rule_files {
        // Skip files with no programs (like basics which only has safe_commands)
        if rules.programs.is_empty() {
            continue;
        }

        let gate_name = name.replace('-', "_");

        // Collect all program names and aliases this gate handles
        let mut all_names: Vec<&str> = Vec::new();
        for program in &rules.programs {
            all_names.push(&program.name);
            for alias in &program.aliases {
                all_names.push(alias);
            }
        }

        // Build a set of programs with custom handlers
        let custom_programs: HashSet<&str> = rules
            .custom_handlers
            .iter()
            .map(|h| h.program.as_str())
            .collect();

        output.push_str(&format!(
            "/// Generated gate for {} - handles: {}\n",
            name,
            all_names.join(", ")
        ));
        output.push_str(&format!(
            "/// Custom handlers needed for: {:?}\n",
            custom_programs.iter().collect::<Vec<_>>()
        ));
        output.push_str(&format!(
            "pub fn check_{}_gate(cmd: &CommandInfo) -> GateResult {{\n",
            gate_name
        ));

        // Match on program name
        output.push_str("    match cmd.program.as_str() {\n");

        for program in &rules.programs {
            let fn_name = program.name.replace('-', "_");

            // Collect names to match (program name + aliases)
            let mut names = vec![format!("\"{}\"", program.name)];
            for alias in &program.aliases {
                names.push(format!("\"{}\"", alias));
            }

            if custom_programs.contains(program.name.as_str()) {
                // Program has custom handler - skip, caller must handle
                output.push_str(&format!(
                    "        {} => GateResult::skip(), // custom handler: {}\n",
                    names.join(" | "),
                    rules
                        .custom_handlers
                        .iter()
                        .find(|h| h.program == program.name)
                        .map(|h| h.handler.as_str())
                        .unwrap_or("unknown")
                ));
            } else {
                // Pure declarative - call generated function
                output.push_str(&format!(
                    "        {} => check_{}_declarative(cmd).unwrap_or_else(GateResult::skip),\n",
                    names.join(" | "),
                    fn_name
                ));
            }
        }

        output.push_str("        _ => GateResult::skip(),\n");
        output.push_str("    }\n");
        output.push_str("}\n\n");

        // Generate list of programs handled by this gate
        output.push_str(&format!("/// Programs handled by the {} gate\n", name));
        output.push_str(&format!(
            "pub static {}_PROGRAMS: &[&str] = &[\n",
            gate_name.to_uppercase()
        ));
        for program in &rules.programs {
            output.push_str(&format!("    \"{}\",\n", program.name));
            for alias in &program.aliases {
                output.push_str(&format!("    \"{}\",\n", alias));
            }
        }
        output.push_str("];\n\n");
    }

    output
}

// ============================================================================
// File Editing Detection Code Generation
// ============================================================================

/// Represents a file-editing rule extracted from TOML
#[derive(Debug)]
struct FileEditingRule {
    program: String,
    aliases: Vec<String>,
    subcommand: Option<String>,
    if_flags_any: Vec<String>,
    // True if this is a bare ask with accept_edits_auto_allow (no subcommand or flags needed)
    is_bare: bool,
}

fn generate_file_editing_code(rule_files: &[(String, RuleFile)]) -> String {
    let mut output = String::new();

    output.push_str(
        "// ============================================================================\n",
    );
    output.push_str("// File Editing Detection (generated from accept_edits_auto_allow rules)\n");
    output.push_str(
        "// ============================================================================\n\n",
    );

    // Collect all file-editing rules from TOML
    let mut rules: Vec<FileEditingRule> = Vec::new();
    let mut programs_set: HashSet<String> = HashSet::new();

    for (_, rule_file) in rule_files {
        // Collect from ask rules
        for program in &rule_file.programs {
            for ask in &program.ask {
                if ask.accept_edits_auto_allow {
                    let rule = FileEditingRule {
                        program: program.name.clone(),
                        aliases: program.aliases.clone(),
                        subcommand: ask.subcommand.clone(),
                        if_flags_any: ask.if_flags_any.clone(),
                        is_bare: ask.subcommand.is_none()
                            && ask.subcommand_prefix.is_none()
                            && ask.if_flags_any.is_empty(),
                    };
                    programs_set.insert(program.name.clone());
                    for alias in &program.aliases {
                        programs_set.insert(alias.clone());
                    }
                    rules.push(rule);
                }
            }
        }

        // Collect from conditional_allow rules (these have unless_flags that trigger ask)
        for cond in &rule_file.conditional_allow {
            if cond.accept_edits_auto_allow && cond.on_flag_present == OnFlagAction::Ask {
                let rule = FileEditingRule {
                    program: cond.program.clone(),
                    aliases: cond.aliases.clone(),
                    subcommand: None,
                    if_flags_any: cond.unless_flags.clone(),
                    is_bare: false,
                };
                programs_set.insert(cond.program.clone());
                for alias in &cond.aliases {
                    programs_set.insert(alias.clone());
                }
                rules.push(rule);
            }
        }
    }

    // Generate static list of file-editing programs
    let mut programs: Vec<&str> = programs_set.iter().map(String::as_str).collect();
    programs.sort();

    output.push_str(
        "/// Programs that have file-editing rules (generated from accept_edits_auto_allow)\n",
    );
    output.push_str(
        "pub static FILE_EDITING_PROGRAMS: LazyLock<HashSet<&str>> = LazyLock::new(|| {\n",
    );
    output.push_str("    [\n");
    for prog in &programs {
        output.push_str(&format!("        \"{}\",\n", escape_rust_string(prog)));
    }
    output.push_str("    ].into_iter().collect()\n");
    output.push_str("});\n\n");

    // Generate the check function
    output.push_str("/// Check if a command is a file-editing command (generated from accept_edits_auto_allow rules)\n");
    output
        .push_str("/// Returns true if the command should be auto-allowed in acceptEdits mode.\n");
    output.push_str("pub fn is_file_editing_command(cmd: &CommandInfo) -> bool {\n");
    output.push_str(
        "    let base_program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);\n",
    );
    output.push_str("    \n");
    output.push_str("    // Quick check: is this a known file-editing program?\n");
    output.push_str("    if !FILE_EDITING_PROGRAMS.contains(base_program) {\n");
    output.push_str("        return false;\n");
    output.push_str("    }\n\n");

    // Group rules by program for efficient matching
    let mut rules_by_program: std::collections::HashMap<String, Vec<&FileEditingRule>> =
        std::collections::HashMap::new();
    for rule in &rules {
        rules_by_program
            .entry(rule.program.clone())
            .or_default()
            .push(rule);
        for alias in &rule.aliases {
            rules_by_program
                .entry(alias.clone())
                .or_default()
                .push(rule);
        }
    }

    // Generate match statement
    output.push_str("    match base_program {\n");

    // Sort programs for deterministic output
    let mut sorted_programs: Vec<&String> = rules_by_program.keys().collect();
    sorted_programs.sort();

    for prog in sorted_programs {
        let prog_rules = &rules_by_program[prog];
        output.push_str(&format!("        \"{}\" => {{\n", escape_rust_string(prog)));

        // Group by condition type for cleaner code
        let bare_rules: Vec<_> = prog_rules.iter().filter(|r| r.is_bare).collect();
        let flag_rules: Vec<_> = prog_rules
            .iter()
            .filter(|r| !r.if_flags_any.is_empty())
            .collect();
        let subcommand_rules: Vec<_> = prog_rules
            .iter()
            .filter(|r| r.subcommand.is_some() && r.if_flags_any.is_empty())
            .collect();

        // Bare rules (always file-editing for this program)
        if !bare_rules.is_empty() {
            output.push_str("            // Bare rule: always file-editing\n");
            output.push_str("            true\n");
        } else {
            let mut conditions: Vec<String> = Vec::new();

            // Flag-based rules
            for rule in &flag_rules {
                let flags: Vec<String> = rule
                    .if_flags_any
                    .iter()
                    .map(|f| format!("\"{}\"", escape_rust_string(f)))
                    .collect();
                if let Some(ref subcmd) = rule.subcommand {
                    conditions.push(format!(
                        "(cmd.args.first().is_some_and(|a| a == \"{}\") && cmd.args.iter().any(|a| [{}].contains(&a.as_str())))",
                        escape_rust_string(subcmd),
                        flags.join(", ")
                    ));
                } else {
                    conditions.push(format!(
                        "cmd.args.iter().any(|a| [{}].contains(&a.as_str()))",
                        flags.join(", ")
                    ));
                }
            }

            // Subcommand-only rules (no flags required)
            for rule in &subcommand_rules {
                if let Some(ref subcmd) = rule.subcommand {
                    conditions.push(format!(
                        "cmd.args.first().is_some_and(|a| a == \"{}\")",
                        escape_rust_string(subcmd)
                    ));
                }
            }

            if conditions.is_empty() {
                output.push_str("            false\n");
            } else if conditions.len() == 1 {
                output.push_str(&format!("            {}\n", conditions[0]));
            } else {
                output.push_str("            ");
                output.push_str(&conditions.join("\n                || "));
                output.push('\n');
            }
        }

        output.push_str("        }\n");
    }

    output.push_str("        _ => false,\n");
    output.push_str("    }\n");
    output.push_str("}\n\n");

    output
}

// ============================================================================
// TOML Policy Generation
// ============================================================================

/// Priority levels for TOML policy rules
mod priority {
    pub const BLOCK: u32 = 900;
    pub const ALLOW: u32 = 100;
    pub const DEFAULT: u32 = 1;
}

fn generate_toml_policy(rule_files: &[(String, RuleFile)]) -> String {
    let mut output = String::new();

    output.push_str("//! Auto-generated TOML policy for Gemini CLI.\n");
    output.push_str("//! DO NOT EDIT - changes will be overwritten by build.rs\n\n");

    output.push_str("/// Generated TOML policy content\n");
    output.push_str("pub const TOML_POLICY: &str = r#\"\n");

    // Header
    output.push_str("# Bash Gates - Generated Policy for Gemini CLI\n");
    output.push_str("#\n");
    output.push_str("# This file was auto-generated from declarative TOML rules.\n");
    output.push_str("# Save to: ~/.gemini/policies/bash-gates.toml\n");
    output.push_str("#\n");
    output.push_str("# Only allow and deny rules are generated.\n");
    output.push_str("# Everything else inherits Gemini CLI's default: ask_user\n");
    output.push_str("#\n\n");

    // Generate rules
    for (name, rules) in rule_files {
        output.push_str(&format!("# === {} gate ===\n\n", name.to_uppercase()));

        // Safe commands - consolidated into array rules
        if !rules.safe_commands.is_empty() {
            // Single rule with commandPrefix array for "cmd ..." (with args)
            output.push_str("# Safe commands (with args)\n");
            output.push_str("[[rule]]\n");
            output.push_str("toolName = \"run_shell_command\"\n");
            output.push_str("commandPrefix = [\n");
            for cmd in &rules.safe_commands {
                output.push_str(&format!("    \"{} \",\n", toml_escape(cmd)));
            }
            output.push_str("]\n");
            output.push_str("decision = \"allow\"\n");
            output.push_str(&format!("priority = {}\n\n", priority::ALLOW));

            // Single regex rule for bare commands (no args)
            output.push_str("# Safe commands (bare, no args)\n");
            output.push_str("[[rule]]\n");
            output.push_str("toolName = \"run_shell_command\"\n");
            let bare_pattern: Vec<String> = rules
                .safe_commands
                .iter()
                .map(|cmd| regex_escape(cmd))
                .collect();
            output.push_str(&format!(
                "commandRegex = \"^({})$\"\n",
                bare_pattern.join("|")
            ));
            output.push_str("decision = \"allow\"\n");
            output.push_str(&format!("priority = {}\n\n", priority::ALLOW));
        }

        // Conditional allow rules - only generate deny for block
        // Skip allow rules - Gemini CLI can't express "allow unless flag present"
        // These commands will fall through to default ask_user, which is safer
        for cond in &rules.conditional_allow {
            for flag in &cond.unless_flags {
                if cond.on_flag_present == OnFlagAction::Block {
                    output.push_str(&format!(
                        "# {}: blocked when {} flag present\n",
                        cond.program, flag
                    ));
                    output.push_str("[[rule]]\n");
                    output.push_str("toolName = \"run_shell_command\"\n");
                    output.push_str(&format!(
                        "commandRegex = \"{}\\\\s+.*{}\"\n",
                        regex_escape(&cond.program),
                        regex_escape(flag)
                    ));
                    output.push_str("decision = \"deny\"\n");
                    output.push_str(&format!("priority = {}\n\n", priority::BLOCK));
                }
            }
            // Note: No allow rule generated - falls through to default ask_user
        }

        // Program rules
        for program in &rules.programs {
            // Blocks (highest priority)
            for block in &program.block {
                let parts = block.subcommand_parts();

                output.push_str(&format!("# Block: {}\n", block.reason));
                output.push_str("[[rule]]\n");
                output.push_str("toolName = \"run_shell_command\"\n");

                // Handle bare blocks (matches any invocation)
                // Only if no if_args_contain - those need regex matching
                if parts.is_empty()
                    && block.subcommand_prefix.is_none()
                    && block.if_args_contain.is_empty()
                {
                    output.push_str(&format!(
                        "commandPrefix = \"{} \"\n",
                        toml_escape(&program.name)
                    ));
                    output.push_str("decision = \"deny\"\n");
                    output.push_str(&format!("priority = {}\n\n", priority::BLOCK));
                    continue;
                }

                // Handle subcommand_prefix blocks
                if let Some(ref prefix) = block.subcommand_prefix {
                    if parts.is_empty() {
                        output.push_str(&format!(
                            "commandPrefix = \"{} {}\"\n",
                            program.name, prefix
                        ));
                    } else {
                        output.push_str(&format!(
                            "commandPrefix = \"{} {} {}\"\n",
                            program.name,
                            parts.join(" "),
                            prefix
                        ));
                    }
                } else if block.if_args_contain.is_empty() {
                    // Simple block - use prefix
                    output.push_str(&format!(
                        "commandPrefix = \"{} {}\"\n",
                        program.name,
                        parts.join(" ")
                    ));
                } else {
                    // Complex block - use regex to match when args contain specific values
                    let args_pattern: Vec<String> = block
                        .if_args_contain
                        .iter()
                        .map(|a| regex_escape(a))
                        .collect();
                    output.push_str(&format!(
                        "commandRegex = \"{}\\\\s+{}(\\\\s+.*)?({})(\\\\s|$)\"\n",
                        regex_escape(&program.name),
                        parts
                            .iter()
                            .map(|p| regex_escape(p))
                            .collect::<Vec<_>>()
                            .join("\\\\s+"),
                        args_pattern.join("|")
                    ));
                }
                output.push_str("decision = \"deny\"\n");
                output.push_str(&format!("priority = {}\n\n", priority::BLOCK));
            }

            // Allows - collect simple allows for consolidation
            let mut simple_allow_prefixes: Vec<String> = Vec::new();

            for allow in &program.allow {
                let parts = allow.subcommand_parts();

                // Handle unless_flags - skip generating ask rules, they inherit default
                // Just add to allow list (lower priority than default ask means it won't match when flags present)
                if !allow.unless_flags.is_empty() {
                    // Skip commands with unless_flags - let default ask handle them
                    // This is safer: sed -i will ask, sed without -i will also ask
                    // Trade-off: less convenient but more secure
                    continue;
                }

                // Handle if_flags_any - allow when specific flags present
                if !allow.if_flags_any.is_empty() {
                    let subcmd = if parts.is_empty() {
                        program.name.clone()
                    } else {
                        format!("{} {}", program.name, parts.join(" "))
                    };

                    for flag in &allow.if_flags_any {
                        output.push_str(&format!("# {}: allow when {} present\n", subcmd, flag));
                        output.push_str("[[rule]]\n");
                        output.push_str("toolName = \"run_shell_command\"\n");
                        output.push_str(&format!(
                            "commandRegex = \"{}\\\\s+.*{}\"\n",
                            regex_escape(&subcmd),
                            regex_escape(flag)
                        ));
                        output.push_str("decision = \"allow\"\n");
                        output.push_str(&format!("priority = {}\n\n", priority::ALLOW + 10)); // Higher priority than base allow
                    }
                    continue;
                }

                // Handle action_prefix - allow when 2nd arg (action) starts with prefix
                // Used for AWS-style commands: aws <service> <action>
                if let Some(ref prefix) = allow.action_prefix {
                    output.push_str(&format!(
                        "# {}: allow when action starts with {}\n",
                        program.name, prefix
                    ));
                    output.push_str("[[rule]]\n");
                    output.push_str("toolName = \"run_shell_command\"\n");
                    // Match: program <anything> <prefix>...
                    output.push_str(&format!(
                        "commandRegex = \"{}\\\\s+\\\\S+\\\\s+{}[^\\\\s]*\"\n",
                        regex_escape(&program.name),
                        regex_escape(prefix)
                    ));
                    output.push_str("decision = \"allow\"\n");
                    output.push_str(&format!("priority = {}\n\n", priority::ALLOW));
                    continue;
                }

                // Simple allow - collect for consolidation
                if parts.is_empty() {
                    continue;
                }
                simple_allow_prefixes.push(format!("{} {}", program.name, parts.join(" ")));
            }

            // Output consolidated simple allows
            if !simple_allow_prefixes.is_empty() {
                output.push_str("[[rule]]\n");
                output.push_str("toolName = \"run_shell_command\"\n");
                if simple_allow_prefixes.len() == 1 {
                    output.push_str(&format!(
                        "commandPrefix = \"{}\"\n",
                        toml_escape(&simple_allow_prefixes[0])
                    ));
                } else {
                    output.push_str("commandPrefix = [\n");
                    for prefix in &simple_allow_prefixes {
                        output.push_str(&format!("    \"{}\",\n", toml_escape(prefix)));
                    }
                    output.push_str("]\n");
                }
                output.push_str("decision = \"allow\"\n");
                output.push_str(&format!("priority = {}\n\n", priority::ALLOW));
            }

            // Skip all ask rules - they inherit Gemini CLI's default ask_user

            // Handle unknown_action fallback rules - only Allow and Block need explicit rules
            match program.unknown_action {
                UnknownAction::Ask | UnknownAction::Skip => {
                    // Inherits default ask_user, no rule needed
                }
                UnknownAction::Allow => {
                    output.push_str(&format!("# {}: unknown subcommands allow\n", program.name));
                    output.push_str("[[rule]]\n");
                    output.push_str("toolName = \"run_shell_command\"\n");
                    output.push_str(&format!(
                        "commandPrefix = \"{} \"\n",
                        toml_escape(&program.name)
                    ));
                    output.push_str("decision = \"allow\"\n");
                    output.push_str(&format!("priority = {}\n\n", priority::DEFAULT + 10));
                }
                UnknownAction::Block => {
                    output.push_str(&format!(
                        "# {}: unknown subcommands blocked\n",
                        program.name
                    ));
                    output.push_str("[[rule]]\n");
                    output.push_str("toolName = \"run_shell_command\"\n");
                    output.push_str(&format!(
                        "commandPrefix = \"{} \"\n",
                        toml_escape(&program.name)
                    ));
                    output.push_str("decision = \"deny\"\n");
                    output.push_str(&format!("priority = {}\n\n", priority::DEFAULT + 10));
                }
            }
        }
    }

    // No default fallback needed - Gemini CLI defaults to ask_user for run_shell_command

    output.push_str("\"#;\n");

    output
}

/// Escape special regex characters for TOML commandRegex
fn regex_escape(s: &str) -> String {
    let special = [
        '.', '^', '$', '*', '+', '?', '{', '}', '[', ']', '|', '(', ')', '\\', '-',
    ];
    let mut result = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        if special.contains(&c) {
            result.push_str("\\\\"); // Double escape for TOML string
        }
        result.push(c);
    }
    result
}

fn escape_rust_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Generate a GateResult::allow() call, with optional reason
fn generate_allow_call(reason: &Option<String>) -> String {
    match reason {
        Some(r) => format!(
            "Some(GateResult::allow_with_reason(\"{}\"))",
            escape_rust_string(r)
        ),
        None => "Some(GateResult::allow())".to_string(),
    }
}

fn toml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
