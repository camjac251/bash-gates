//! Tool Gates - Intelligent tool permission gate for AI coding assistants.
//!
//! Formerly `bash-gates`. Single binary that handles all tool types:
//! - **Bash**: AST-parsed command gating (13 ordered gates, settings.json integration)
//! - **Read/Write/Edit/MultiEdit**: Symlink guard for AI config files
//! - **Glob/Grep/MCP tools**: Configurable tool blocking
//!
//! Supports three Claude Code hook events:
//! - `PreToolUse`: Routes all tool types through the appropriate handler
//! - `PermissionRequest`: Approve safe Bash commands for subagents
//! - `PostToolUse`: Track successful Bash execution for approval learning
//!
//! Configuration: `~/.config/tool-gates/config.toml`
//!
//! Usage:
//!   `echo '{"tool_name": "Bash", "tool_input": {"command": "gh pr list"}}' | tool-gates`
//!   `echo '{"tool_name": "Read", "tool_input": {"file_path": "/project/CLAUDE.md"}}' | tool-gates`
//!   `echo '{"tool_name": "Glob", "tool_input": {"pattern": "*.rs"}}' | tool-gates`

use std::env;
use std::io::{self, Read};
use tool_gates::config;
use tool_gates::file_guards::check_file_guard;
use tool_gates::models::{HookInput, HookOutput, PermissionRequestInput, PostToolUseInput};
use tool_gates::patterns::suggest_patterns;
use tool_gates::pending::{clear_pending, pending_count, read_pending};
use tool_gates::permission_request::handle_permission_request;
use tool_gates::post_tool_use::handle_post_tool_use;
use tool_gates::router::check_command_with_settings_and_session;
use tool_gates::settings_writer::{
    RuleType, Scope, add_rule, list_all_rules, list_rules, remove_rule,
};
use tool_gates::toml_export;
use tool_gates::tool_blocks::check_tool_block;
use tool_gates::tool_cache;
use tool_gates::tracking::{CommandPart, track_ask_command};
use tool_gates::tui::run_review;

fn main() {
    // One-time migration from ~/.cache/bash-gates/ to ~/.cache/tool-gates/
    tool_gates::cache::ensure_cache_migrated();

    let args: Vec<String> = env::args().collect();

    // Handle subcommands first
    if args.len() > 1 && args[1] == "hooks" {
        handle_hooks_subcommand(&args[2..]);
        return;
    }

    if args.len() > 1 && args[1] == "approve" {
        handle_approve_subcommand(&args[2..]);
        return;
    }

    if args.len() > 1 && args[1] == "rules" {
        handle_rules_subcommand(&args[2..]);
        return;
    }

    if args.len() > 1 && args[1] == "pending" {
        handle_pending_subcommand(&args[2..]);
        return;
    }

    if args.len() > 1 && args[1] == "review" {
        let show_all = args.iter().any(|a| a == "--all" || a == "-a");
        handle_review_subcommand(show_all);
        return;
    }

    // Handle global flags
    if args
        .iter()
        .any(|a| a == "--export-toml" || a == "--gemini-policy")
    {
        print!("{}", toml_export::generate_toml());
        return;
    }

    if args.iter().any(|a| a == "--refresh-tools") {
        eprintln!("Refreshing tool cache...");
        let cache = tool_cache::refresh_cache();
        let available: Vec<_> = cache
            .tools
            .iter()
            .filter(|(_, v)| **v)
            .map(|(k, _)| k.as_str())
            .collect();
        eprintln!(
            "Available modern tools: {}",
            if available.is_empty() {
                "none".to_string()
            } else {
                available.join(", ")
            }
        );
        return;
    }

    if args.iter().any(|a| a == "--tools-status") {
        println!("{}", tool_cache::cache_status());
        return;
    }

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("tool-gates {}", env!("GIT_VERSION"));
        return;
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_main_help();
        return;
    }

    // Read input from stdin
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        eprintln!("Error reading stdin: {e}");
        print_no_opinion();
        return;
    }

    if input.trim().is_empty() {
        print_no_opinion();
        return;
    }

    // First, try to detect hook type from raw JSON
    let hook_event: Option<String> = serde_json::from_str::<serde_json::Value>(&input)
        .ok()
        .and_then(|v| {
            v.get("hook_event_name")
                .and_then(|h| h.as_str().map(String::from))
        });

    // Route based on hook event type
    match hook_event.as_deref() {
        Some("PermissionRequest") => {
            handle_permission_request_hook(&input);
        }
        Some("PostToolUse") => {
            handle_post_tool_use_hook(&input);
        }
        _ => {
            // Default: PreToolUse or unspecified
            handle_pre_tool_use_hook(&input);
        }
    }
}

/// Handle PreToolUse hook -- routes all tool types
fn handle_pre_tool_use_hook(input: &str) {
    let hook_input: HookInput = match serde_json::from_str(input) {
        Ok(hi) => hi,
        Err(e) => {
            eprintln!("Error: Invalid JSON input: {e}");
            print_no_opinion();
            return;
        }
    };

    let config = config::load();

    // Check configurable block rules first (applies to ALL tool types)
    // Re-extract tool_input as raw map since Structured variant
    // drops unknown fields (url, pattern, etc.)
    let tool_input_map = serde_json::from_str::<serde_json::Value>(input)
        .ok()
        .and_then(|v| v.get("tool_input").cloned())
        .and_then(|v| match v {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default();
    if let Some(output) =
        check_tool_block(&hook_input.tool_name, &tool_input_map, config.block_rules())
    {
        if let Ok(json) = serde_json::to_string(&output) {
            println!("{json}");
        } else {
            println!(
                r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Internal error serializing block deny"}}}}"#
            );
        }
        return;
    }

    // Route by tool type
    match hook_input.tool_name.as_str() {
        // Bash tools: full gate engine
        "Bash" => {
            if !config.features.bash_gates {
                print_no_opinion();
                return;
            }
            handle_bash_pre_tool_use(&hook_input);
        }
        // File tools: symlink guard
        "Read" | "Write" | "Edit" | "MultiEdit" => {
            if !config.features.file_guards {
                return; // silent pass-through
            }
            // Extract file paths from raw JSON to avoid ToolInputVariant::Structured
            // dropping unknown fields (MultiEdit uses files[].file_path, not file_path)
            let file_paths = extract_file_paths_from_map(&tool_input_map);
            for file_path in &file_paths {
                if let Some(output) =
                    check_file_guard(file_path, &hook_input.tool_name, &config.file_guards)
                {
                    if let Ok(json) = serde_json::to_string(&output) {
                        println!("{json}");
                    } else {
                        // Fallback: hardcoded deny to avoid silent pass-through
                        println!(
                            r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Internal error serializing file guard deny"}}}}"#
                        );
                    }
                    return; // deny on first guarded symlink found
                }
            }
            // No output = allow
        }
        // All other tools: pass through (blocks already checked above)
        _ => {}
    }
}

/// Extract all file paths from a raw tool_input map.
/// Handles both single-file tools (file_path) and MultiEdit (files[].file_path).
fn extract_file_paths_from_map(map: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    let mut paths = Vec::new();

    // Single file_path (Read/Write/Edit)
    if let Some(fp) = map.get("file_path").and_then(|v| v.as_str()) {
        if !fp.is_empty() {
            paths.push(fp.to_string());
        }
    }

    // MultiEdit: files[].file_path
    if let Some(files) = map.get("files").and_then(|v| v.as_array()) {
        for file in files {
            if let Some(fp) = file.get("file_path").and_then(|v| v.as_str()) {
                if !fp.is_empty() {
                    paths.push(fp.to_string());
                }
            }
        }
    }

    paths
}

/// Handle Bash-specific PreToolUse logic (gate engine + tracking)
fn handle_bash_pre_tool_use(hook_input: &HookInput) {
    let command = hook_input.get_command();
    if command.is_empty() {
        print_no_opinion();
        return;
    }

    // Check command with settings.json awareness, mode detection, and session hint dedup
    let output = check_command_with_settings_and_session(
        &command,
        &hook_input.cwd,
        &hook_input.permission_mode,
        &hook_input.session_id,
    );

    // If the result is "ask", track it for PostToolUse correlation
    if let Some(ref hso) = output.hook_specific_output {
        if hso.permission_decision == "ask" && !hook_input.tool_use_id.is_empty() {
            let commands = tool_gates::parser::extract_commands(&command);
            let suggested_patterns: Vec<String> =
                commands.iter().flat_map(suggest_patterns).collect();

            let breakdown: Vec<CommandPart> = commands
                .iter()
                .map(|cmd| {
                    CommandPart::new(
                        &cmd.program,
                        &cmd.args,
                        tool_gates::Decision::Ask,
                        hso.permission_decision_reason
                            .as_deref()
                            .unwrap_or("Requires approval"),
                    )
                })
                .collect();

            track_ask_command(
                &hook_input.tool_use_id,
                &command,
                suggested_patterns,
                breakdown,
                &hook_input.project_id(),
                &hook_input.cwd,
                &hook_input.session_id,
            );
        }
    }

    match serde_json::to_string(&output) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("Error serializing output: {e}");
            print_no_opinion();
        }
    }
}

/// Handle PermissionRequest hook (for subagent approval)
fn handle_permission_request_hook(input: &str) {
    let perm_input: PermissionRequestInput = match serde_json::from_str(input) {
        Ok(pi) => pi,
        Err(e) => {
            eprintln!("Error: Invalid PermissionRequest JSON: {e}");
            // Don't output anything - let normal prompt show
            return;
        }
    };

    // Only process Bash tools
    if perm_input.tool_name != "Bash" {
        // Don't output anything - let normal prompt show
        return;
    }

    // Check if we should approve this
    if let Some(output) = handle_permission_request(&perm_input) {
        match serde_json::to_string(&output) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("Error serializing PermissionRequest output: {e}");
                // Don't output anything - let normal prompt show
            }
        }
    }
    // If None, we don't output anything - lets the normal permission prompt show
}

/// Handle PostToolUse hook (for tracking successful executions)
fn handle_post_tool_use_hook(input: &str) {
    let post_input: PostToolUseInput = match serde_json::from_str(input) {
        Ok(pi) => pi,
        Err(e) => {
            eprintln!("Error: Invalid PostToolUse JSON: {e}");
            return;
        }
    };

    // Only process Bash tools
    if post_input.tool_name != "Bash" {
        return;
    }

    // Handle the post-tool-use event (tracks successful executions)
    if let Some(output) = handle_post_tool_use(&post_input) {
        match serde_json::to_string(&output) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("Error serializing PostToolUse output: {e}");
            }
        }
    }
    // If None, we don't output anything
}

fn get_binary_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "tool-gates".to_string())
}

/// PreToolUse matcher for built-in tools (exact match mode).
/// Bash (gate engine), Read/Write/Edit/MultiEdit (file guards), Glob/Grep (block rules).
const PRE_TOOL_USE_MATCHER: &str = "Bash|Read|Write|Edit|MultiEdit|Glob|Grep";

/// PreToolUse matcher for MCP tools (regex mode).
/// Matches all MCP tool calls; block rules in config decide what to deny.
const MCP_TOOL_USE_MATCHER: &str = "mcp__.*";

fn generate_hook_entry(binary_path: &str, matcher: &str) -> serde_json::Value {
    serde_json::json!({
        "matcher": matcher,
        "hooks": [{"type": "command", "command": binary_path, "timeout": 10}]
    })
}

fn generate_hooks_json(binary_path: &str) -> serde_json::Value {
    serde_json::json!({
        "PreToolUse": [
            generate_hook_entry(binary_path, PRE_TOOL_USE_MATCHER),
            generate_hook_entry(binary_path, MCP_TOOL_USE_MATCHER),
        ],
        "PermissionRequest": [generate_hook_entry(binary_path, "Bash")],
        "PostToolUse": [generate_hook_entry(binary_path, "Bash")]
    })
}

/// Get the settings file path based on scope
/// - "user" → ~/.claude/settings.json (or CLAUDE_CONFIG_DIR/settings.json)
/// - "project" → .claude/settings.json (committed, shared with team)
/// - "local" → .claude/settings.local.json (not committed, user+project specific)
fn get_settings_path(scope: &str) -> std::path::PathBuf {
    match scope {
        "user" => {
            // Check CLAUDE_CONFIG_DIR env var first, fall back to ~/.claude
            std::env::var("CLAUDE_CONFIG_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| {
                    dirs::home_dir()
                        .unwrap_or_else(|| std::path::PathBuf::from("."))
                        .join(".claude")
                })
                .join("settings.json")
        }
        "project" => std::path::PathBuf::from(".claude").join("settings.json"),
        "local" => std::path::PathBuf::from(".claude").join("settings.local.json"),
        _ => {
            eprintln!(
                "Error: Invalid scope '{}'. Use: user, project, or local",
                scope
            );
            std::process::exit(1);
        }
    }
}

/// Check if tool-gates hook already exists in a hook array.
/// Detects any matcher pattern that includes "Bash" and points to tool-gates/bash-gates.
fn has_tool_gates_hook(hooks_array: &serde_json::Value) -> bool {
    if let Some(arr) = hooks_array.as_array() {
        for entry in arr {
            let matcher = entry.get("matcher").and_then(|m| m.as_str()).unwrap_or("");
            // Match both old "Bash" and new broader patterns containing "Bash"
            if matcher.contains("Bash") {
                if let Some(hooks) = entry.get("hooks").and_then(|h| h.as_array()) {
                    for hook in hooks {
                        if let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) {
                            if cmd.contains("tool-gates") || cmd.contains("bash-gates") {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

/// Install hooks into settings.json
fn install_hooks(scope: &str, dry_run: bool) {
    let binary_path = get_binary_path();
    let settings_path = get_settings_path(scope);

    eprintln!("tool-gates installer");
    eprintln!("Binary: {}", binary_path);
    eprintln!("Target: {} ({})", settings_path.display(), scope);
    eprintln!();

    // Read existing settings or create new
    let mut settings: serde_json::Value = if settings_path.exists() {
        match std::fs::read_to_string(&settings_path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: Failed to parse {}: {}", settings_path.display(), e);
                    std::process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("Error: Failed to read {}: {}", settings_path.display(), e);
                std::process::exit(1);
            }
        }
    } else {
        serde_json::json!({})
    };

    // Ensure hooks object exists
    if settings.get("hooks").is_none() {
        settings["hooks"] = serde_json::json!({});
    }

    let hooks = settings.get_mut("hooks").unwrap();
    let pre_tool_use_entry = generate_hook_entry(&binary_path, PRE_TOOL_USE_MATCHER);
    let mcp_tool_use_entry = generate_hook_entry(&binary_path, MCP_TOOL_USE_MATCHER);
    let bash_entry = generate_hook_entry(&binary_path, "Bash");
    let mut changes = Vec::new();

    // Check and add PreToolUse (built-in tools + MCP tools as separate entries)
    if hooks.get("PreToolUse").is_none() {
        hooks["PreToolUse"] = serde_json::json!([]);
    }
    if has_tool_gates_hook(&hooks["PreToolUse"]) {
        eprintln!("✓ PreToolUse hook already configured");
    } else {
        let arr = hooks["PreToolUse"].as_array_mut().unwrap();
        arr.push(pre_tool_use_entry);
        arr.push(mcp_tool_use_entry);
        changes.push("PreToolUse");
        eprintln!("+ Adding PreToolUse hooks (built-in tools + MCP)");
    }

    // Check and add PermissionRequest (Bash only)
    if hooks.get("PermissionRequest").is_none() {
        hooks["PermissionRequest"] = serde_json::json!([]);
    }
    if has_tool_gates_hook(&hooks["PermissionRequest"]) {
        eprintln!("✓ PermissionRequest hook already configured");
    } else {
        hooks["PermissionRequest"]
            .as_array_mut()
            .unwrap()
            .push(bash_entry.clone());
        changes.push("PermissionRequest");
        eprintln!("+ Adding PermissionRequest hook");
    }

    // Check and add PostToolUse (Bash only)
    if hooks.get("PostToolUse").is_none() {
        hooks["PostToolUse"] = serde_json::json!([]);
    }
    if has_tool_gates_hook(&hooks["PostToolUse"]) {
        eprintln!("✓ PostToolUse hook already configured");
    } else {
        hooks["PostToolUse"]
            .as_array_mut()
            .unwrap()
            .push(bash_entry);
        changes.push("PostToolUse");
        eprintln!("+ Adding PostToolUse hook");
    }

    if changes.is_empty() {
        eprintln!("\nNo changes needed - tool-gates already installed.");
        return;
    }

    if dry_run {
        eprintln!("\n--dry-run: Would write to {}", settings_path.display());
        eprintln!("\nResulting hooks configuration:");
        println!(
            "{}",
            serde_json::to_string_pretty(&settings["hooks"]).unwrap()
        );
        return;
    }

    // Create parent directory if needed
    if let Some(parent) = settings_path.parent() {
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("Error: Failed to create {}: {}", parent.display(), e);
                std::process::exit(1);
            }
        }
    }

    // Write settings
    match std::fs::write(
        &settings_path,
        serde_json::to_string_pretty(&settings).unwrap() + "\n",
    ) {
        Ok(_) => {
            eprintln!("\n✓ Installed to {}", settings_path.display());
            eprintln!("\nHooks added: {}", changes.join(", "));
            eprintln!("\nAll three hooks are required:");
            eprintln!("  - PreToolUse: Command safety for main session");
            eprintln!("  - PermissionRequest: Safe commands work in subagents");
            eprintln!("  - PostToolUse: Track successful commands for approval learning");
        }
        Err(e) => {
            eprintln!("Error: Failed to write {}: {}", settings_path.display(), e);
            std::process::exit(1);
        }
    }
}

/// Handle `tool-gates hooks` subcommand
fn handle_hooks_subcommand(args: &[String]) {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_hooks_help();
        return;
    }

    let subcommand = &args[0];
    let sub_args = &args[1..];

    match subcommand.as_str() {
        "add" => handle_hooks_add(sub_args),
        "status" => handle_hooks_status(),
        "json" => print_hooks_json(),
        _ => {
            eprintln!("Unknown hooks subcommand: {}", subcommand);
            eprintln!("Run 'tool-gates hooks --help' for usage.");
            std::process::exit(1);
        }
    }
}

/// Handle `tool-gates hooks add`
fn handle_hooks_add(args: &[String]) {
    let dry_run = args.iter().any(|a| a == "--dry-run" || a == "-n");

    // Parse --scope option
    let scope = args
        .iter()
        .position(|a| a == "--scope" || a == "-s")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    // No scope specified: show help (always required, even for dry-run)
    if scope.is_none() {
        eprintln!("Error: --scope (-s) is required\n");
        print_hooks_add_help();
        std::process::exit(1);
    }

    let scope = scope.unwrap();
    install_hooks(scope, dry_run);
}

/// Handle `tool-gates hooks status`
fn handle_hooks_status() {
    let scopes = [
        ("user", get_settings_path("user")),
        ("project", get_settings_path("project")),
        ("local", get_settings_path("local")),
    ];

    eprintln!("tool-gates hook status\n");

    for (scope, path) in &scopes {
        eprint!("{:8} {} ", scope, path.display());

        if !path.exists() {
            eprintln!("(not found)");
            continue;
        }

        match std::fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(settings) => {
                    let hooks = settings.get("hooks");
                    let has_pre = hooks
                        .and_then(|h| h.get("PreToolUse"))
                        .map(has_tool_gates_hook)
                        .unwrap_or(false);
                    let has_perm = hooks
                        .and_then(|h| h.get("PermissionRequest"))
                        .map(has_tool_gates_hook)
                        .unwrap_or(false);
                    let has_post = hooks
                        .and_then(|h| h.get("PostToolUse"))
                        .map(has_tool_gates_hook)
                        .unwrap_or(false);

                    let installed_count =
                        [has_pre, has_perm, has_post].iter().filter(|&&x| x).count();

                    if installed_count == 3 {
                        eprintln!("✓ installed (all hooks)");
                    } else if installed_count > 0 {
                        let mut missing = Vec::new();
                        if !has_pre {
                            missing.push("PreToolUse");
                        }
                        if !has_perm {
                            missing.push("PermissionRequest");
                        }
                        if !has_post {
                            missing.push("PostToolUse");
                        }
                        eprintln!("⚠ partial (missing {})", missing.join(", "));
                    } else {
                        eprintln!("- not installed");
                    }
                }
                Err(_) => eprintln!("(parse error)"),
            },
            Err(_) => eprintln!("(read error)"),
        }
    }
}

/// Print hooks JSON only
fn print_hooks_json() {
    let binary_path = get_binary_path();
    let hooks = generate_hooks_json(&binary_path);
    println!("{}", serde_json::to_string_pretty(&hooks).unwrap());
}

fn print_main_help() {
    eprintln!("tool-gates - Intelligent tool permission gate for AI coding assistants");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  tool-gates                   Read hook input from stdin (default)");
    eprintln!("  tool-gates hooks <command>   Manage Claude Code hooks");
    eprintln!("  tool-gates approve <pattern> Add permission rule to settings");
    eprintln!("  tool-gates rules <command>   List/remove permission rules");
    eprintln!("  tool-gates pending <command> Manage pending approval queue");
    eprintln!("  tool-gates review            Interactive TUI for pending approvals");
    eprintln!("  tool-gates --export-toml     Export Gemini CLI policy rules");
    eprintln!("  tool-gates --refresh-tools   Refresh modern CLI tool detection");
    eprintln!("  tool-gates --tools-status    Show detected modern tools");
    eprintln!("  tool-gates --help            Show this help");
    eprintln!("  tool-gates --version         Show version");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!("  hooks add -s <scope>         Add hooks to Claude Code settings");
    eprintln!("  hooks status                 Show hook installation status");
    eprintln!("  approve <pattern> -s <scope> Add allow rule for command pattern");
    eprintln!("  rules list                   List all permission rules");
    eprintln!("  rules remove <pattern>       Remove a permission rule");
    eprintln!("  pending list                 List pending approvals");
    eprintln!("  pending clear                Clear pending approval queue");
    eprintln!("  review                       Interactive TUI for pending approvals");
    eprintln!();
    eprintln!("SCOPES:");
    eprintln!("  user     ~/.claude/settings.json (global, recommended)");
    eprintln!("  project  .claude/settings.json (shared with team)");
    eprintln!("  local    .claude/settings.local.json (personal, not committed)");
    eprintln!();
    eprintln!("EXAMPLES:");
    eprintln!("  tool-gates hooks add -s user          # Install hooks");
    eprintln!("  tool-gates approve 'npm:*' -s local   # Allow npm commands");
    eprintln!("  tool-gates rules list                 # Show all rules");
    eprintln!("  tool-gates pending list               # Show pending approvals");
    eprintln!();
    eprintln!("  tool-gates --export-toml > ~/.gemini/policies/tool-gates.toml");
}

fn print_hooks_help() {
    eprintln!("tool-gates hooks - Manage Claude Code hooks");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  tool-gates hooks add -s <scope>   Add hooks to settings file");
    eprintln!("  tool-gates hooks status           Show hook installation status");
    eprintln!("  tool-gates hooks json             Output hooks JSON only");
    eprintln!();
    eprintln!("SCOPES:");
    eprintln!("  user     ~/.claude/settings.json (global user settings)");
    eprintln!("  project  .claude/settings.json (committed, shared with team)");
    eprintln!("  local    .claude/settings.local.json (not committed)");
    eprintln!();
    eprintln!("EXAMPLES:");
    eprintln!("  tool-gates hooks add -s user         # Recommended for personal use");
    eprintln!("  tool-gates hooks add -s project      # Share hooks with team");
    eprintln!("  tool-gates hooks add -s user --dry-run  # Preview changes");
}

fn print_hooks_add_help() {
    eprintln!("USAGE:");
    eprintln!("  tool-gates hooks add -s <scope> [--dry-run]");
    eprintln!();
    eprintln!("SCOPES:");
    eprintln!("  user     ~/.claude/settings.json");
    eprintln!("  project  .claude/settings.json");
    eprintln!("  local    .claude/settings.local.json");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  -s, --scope <scope>   Target settings file (required)");
    eprintln!("  -n, --dry-run         Preview changes without writing");
}

// === Approve subcommand ===

fn handle_approve_subcommand(args: &[String]) {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_approve_help();
        return;
    }

    // Find the pattern (first non-flag argument)
    let pattern = args.iter().find(|a| !a.starts_with('-'));

    let Some(pattern) = pattern else {
        eprintln!("Error: Pattern is required");
        eprintln!();
        print_approve_help();
        std::process::exit(1);
    };

    // Validate pattern is not empty or whitespace-only
    let pattern = pattern.trim();
    if pattern.is_empty() {
        eprintln!("Error: Pattern cannot be empty");
        std::process::exit(1);
    }

    // Parse --scope option
    let scope_str = args
        .iter()
        .position(|a| a == "--scope" || a == "-s")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let Some(scope_str) = scope_str else {
        eprintln!("Error: --scope (-s) is required");
        eprintln!();
        print_approve_help();
        std::process::exit(1);
    };

    let Some(scope) = Scope::parse(scope_str) else {
        eprintln!(
            "Error: Invalid scope '{}'. Use: user, project, or local",
            scope_str
        );
        std::process::exit(1);
    };

    // Parse --type option (default: allow)
    let rule_type_str = args
        .iter()
        .position(|a| a == "--type" || a == "-t")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("allow");

    let rule_type = match rule_type_str {
        "allow" => RuleType::Allow,
        "ask" => RuleType::Ask,
        "deny" => RuleType::Deny,
        _ => {
            eprintln!(
                "Error: Invalid rule type '{}'. Use: allow, ask, or deny",
                rule_type_str
            );
            std::process::exit(1);
        }
    };

    // Check for --dry-run
    let dry_run = args.iter().any(|a| a == "--dry-run" || a == "-n");

    let formatted = tool_gates::settings_writer::format_pattern(pattern);

    if dry_run {
        eprintln!(
            "--dry-run: Would add {} rule: {}",
            rule_type.as_str(),
            formatted
        );
        eprintln!("  Scope: {} ({})", scope.as_str(), scope.path().display());
        return;
    }

    // Add the rule
    match add_rule(scope, pattern, rule_type) {
        Ok(_) => {
            eprintln!("✓ Added {} rule: {}", rule_type.as_str(), formatted);
            eprintln!("  Scope: {} ({})", scope.as_str(), scope.path().display());
        }
        Err(e) => {
            eprintln!("Error: Failed to add rule: {}", e);
            std::process::exit(1);
        }
    }
}

fn print_approve_help() {
    eprintln!("tool-gates approve - Add a command pattern to settings.json");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  tool-gates approve <pattern> -s <scope> [--type <type>] [--dry-run]");
    eprintln!();
    eprintln!("ARGUMENTS:");
    eprintln!("  <pattern>   Command pattern to approve (e.g., 'npm install:*', 'git:*')");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  -s, --scope <scope>   Target scope: user, project, or local (required)");
    eprintln!("  -t, --type <type>     Rule type: allow (default), ask, or deny");
    eprintln!("  -n, --dry-run         Preview changes without writing");
    eprintln!();
    eprintln!("EXAMPLES:");
    eprintln!("  tool-gates approve 'npm install:*' -s local");
    eprintln!("  tool-gates approve 'biome:*' -s user");
    eprintln!("  tool-gates approve 'rm -rf*' -s user -t deny");
    eprintln!("  tool-gates approve 'cargo:*' -s local --dry-run");
}

// === Rules subcommand ===

fn handle_rules_subcommand(args: &[String]) {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_rules_help();
        return;
    }

    let subcommand = &args[0];
    let sub_args = &args[1..];

    match subcommand.as_str() {
        "list" => handle_rules_list(sub_args),
        "remove" => handle_rules_remove(sub_args),
        _ => {
            eprintln!("Unknown rules subcommand: {}", subcommand);
            eprintln!("Run 'tool-gates rules --help' for usage.");
            std::process::exit(1);
        }
    }
}

fn handle_rules_list(args: &[String]) {
    // Parse --scope option
    let scope_str = args
        .iter()
        .position(|a| a == "--scope" || a == "-s")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let rules = if let Some(scope_str) = scope_str {
        let Some(scope) = Scope::parse(scope_str) else {
            eprintln!(
                "Error: Invalid scope '{}'. Use: user, project, or local",
                scope_str
            );
            std::process::exit(1);
        };
        list_rules(scope)
    } else {
        list_all_rules()
    };

    if rules.is_empty() {
        eprintln!("No permission rules found.");
        return;
    }

    eprintln!("Permission rules:\n");

    // Group by scope
    for scope in [Scope::User, Scope::Project, Scope::Local] {
        let scope_rules: Vec<_> = rules.iter().filter(|r| r.scope == scope).collect();
        if scope_rules.is_empty() {
            continue;
        }

        eprintln!("  {} ({}):", scope.as_str(), scope.path().display());
        for rule in scope_rules {
            let type_indicator = match rule.rule_type {
                RuleType::Allow => "✓",
                RuleType::Ask => "?",
                RuleType::Deny => "✗",
            };
            eprintln!(
                "    {} {} ({})",
                type_indicator,
                rule.pattern,
                rule.rule_type.as_str()
            );
        }
        eprintln!();
    }
}

fn handle_rules_remove(args: &[String]) {
    // Find the pattern (first non-flag argument)
    let pattern = args.iter().find(|a| !a.starts_with('-'));

    let Some(pattern) = pattern else {
        eprintln!("Error: Pattern is required");
        eprintln!("Usage: tool-gates rules remove <pattern> -s <scope>");
        std::process::exit(1);
    };

    // Parse --scope option
    let scope_str = args
        .iter()
        .position(|a| a == "--scope" || a == "-s")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str());

    let Some(scope_str) = scope_str else {
        eprintln!("Error: --scope (-s) is required");
        eprintln!("Usage: tool-gates rules remove <pattern> -s <scope>");
        std::process::exit(1);
    };

    let Some(scope) = Scope::parse(scope_str) else {
        eprintln!(
            "Error: Invalid scope '{}'. Use: user, project, or local",
            scope_str
        );
        std::process::exit(1);
    };

    match remove_rule(scope, pattern) {
        Ok(true) => {
            let formatted = tool_gates::settings_writer::format_pattern(pattern);
            eprintln!("✓ Removed rule: {}", formatted);
        }
        Ok(false) => {
            eprintln!("Rule not found: {}", pattern);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Error: Failed to remove rule: {}", e);
            std::process::exit(1);
        }
    }
}

fn print_rules_help() {
    eprintln!("tool-gates rules - Manage permission rules in settings.json");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  tool-gates rules list [--scope <scope>]");
    eprintln!("  tool-gates rules remove <pattern> -s <scope>");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!("  list     List all permission rules");
    eprintln!("  remove   Remove a permission rule");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  -s, --scope <scope>   Filter by scope: user, project, or local");
}

// === Pending subcommand ===

fn handle_pending_subcommand(args: &[String]) {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_pending_help();
        return;
    }

    let subcommand = &args[0];
    let sub_args = &args[1..];

    match subcommand.as_str() {
        "list" => handle_pending_list(sub_args),
        "clear" => handle_pending_clear(sub_args),
        _ => {
            eprintln!("Unknown pending subcommand: {}", subcommand);
            eprintln!("Run 'tool-gates pending --help' for usage.");
            std::process::exit(1);
        }
    }
}

fn handle_pending_list(args: &[String]) {
    let is_project = args.iter().any(|a| a == "--project" || a == "-p");

    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from));

    // Filter by project if --project flag is set
    let filter = if is_project { cwd.as_deref() } else { None };
    let all_entries = read_pending(filter);

    if all_entries.is_empty() {
        eprintln!("No pending approvals.");
        return;
    }

    eprintln!("Pending approvals ({}):\n", all_entries.len());

    for entry in &all_entries {
        // Show abbreviated project_id (extract last segment)
        let project = entry
            .project_id
            .rsplit('-')
            .find(|s| !s.is_empty())
            .unwrap_or(&entry.project_id);

        eprintln!(
            "  [{}] {} (seen {} time{})",
            project,
            entry.command,
            entry.count,
            if entry.count == 1 { "" } else { "s" }
        );

        if !entry.patterns.is_empty() {
            eprintln!("    Suggested patterns:");
            for pattern in &entry.patterns {
                eprintln!("      - {}", pattern);
            }
        }

        // Format time
        let duration = chrono::Utc::now() - entry.last_seen;
        let time_str = if duration.num_days() > 0 {
            format!("{} days ago", duration.num_days())
        } else if duration.num_hours() > 0 {
            format!("{} hours ago", duration.num_hours())
        } else if duration.num_minutes() > 0 {
            format!("{} min ago", duration.num_minutes())
        } else {
            "just now".to_string()
        };
        eprintln!("    Last seen: {}", time_str);
        eprintln!();
    }

    eprintln!("To approve a pattern: tool-gates approve '<pattern>' -s <scope>");
    eprintln!("To review interactively: tool-gates review");
}

fn handle_pending_clear(args: &[String]) {
    let is_project = args.iter().any(|a| a == "--project" || a == "-p");
    let is_all = args.iter().any(|a| a == "--all" || a == "-a");
    let is_force = args.iter().any(|a| a == "--force" || a == "-f");

    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from));

    if !is_project && !is_all {
        eprintln!("Error: Specify --project or --all");
        eprintln!("Usage: tool-gates pending clear [--project | --all] --force");
        std::process::exit(1);
    }

    // Count entries to be cleared
    let filter = if is_project { cwd.as_deref() } else { None };
    let total_count = pending_count(filter);

    if total_count == 0 {
        eprintln!("No pending approvals to clear.");
        return;
    }

    // Require --force for destructive action
    if !is_force {
        eprintln!(
            "This will permanently delete {} pending approval(s).",
            total_count
        );
        eprintln!("Add --force (-f) to confirm.");
        std::process::exit(1);
    }

    match clear_pending(filter) {
        Ok(count) => {
            let scope = if is_project { "project" } else { "all" };
            eprintln!("✓ Cleared: {} {}", count, scope);
        }
        Err(e) => {
            eprintln!("Error clearing pending: {}", e);
        }
    }
}

fn print_pending_help() {
    eprintln!("tool-gates pending - Manage pending approval queue");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  tool-gates pending list [--project]");
    eprintln!("  tool-gates pending clear [--project | --all] --force");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!("  list    List pending approvals");
    eprintln!("  clear   Clear pending approval queue (requires --force)");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  -p, --project   Filter to current project only");
    eprintln!("  -a, --all       Clear all pending approvals");
    eprintln!("  -f, --force     Confirm destructive clear operation");
}

// === Review subcommand ===

fn handle_review_subcommand(show_all: bool) {
    if let Err(e) = run_review(show_all) {
        eprintln!("Error running review TUI: {}", e);
        std::process::exit(1);
    }
}

/// Print empty JSON to signal no opinion (pass through to Claude Code's normal flow).
fn print_no_opinion() {
    let output = HookOutput::no_opinion();
    if let Ok(json) = serde_json::to_string(&output) {
        println!("{json}");
    } else {
        println!("{{}}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tool_gates::check_command;

    #[test]
    fn test_hook_input_parsing() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "git status"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.get_command(), "git status");
    }

    #[test]
    fn test_hook_input_with_map() {
        let json =
            r#"{"tool_name": "Bash", "tool_input": {"command": "npm install", "timeout": 120}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.get_command(), "npm install");
    }

    #[test]
    fn test_check_command_git_status() {
        let output = check_command("git status");
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("allow"));
    }

    #[test]
    fn test_check_command_npm_install() {
        let output = check_command("npm install");
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("ask"));
    }

    #[test]
    fn test_check_command_rm_rf_root() {
        let output = check_command("rm -rf /");
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("deny"));
    }

    #[test]
    fn test_output_uses_pre_tool_use() {
        let output = check_command("git status");
        let json = serde_json::to_string(&output).unwrap();
        assert!(
            json.contains("PreToolUse"),
            "Expected PreToolUse in: {json}"
        );
    }

    // === Integration tests: JSON input → decision flow ===

    /// Simulate the full hook flow: JSON input → parse → check → JSON output
    fn simulate_hook(json_input: &str) -> String {
        let input: HookInput = serde_json::from_str(json_input).unwrap();
        let command = input.get_command();
        let output = check_command(&command);
        serde_json::to_string(&output).unwrap()
    }

    #[test]
    fn test_integration_safe_command_chain() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "git status && git log --oneline -5"}}"#;
        let output = simulate_hook(json);
        assert!(
            output.contains("allow"),
            "Safe chain should allow: {output}"
        );
    }

    #[test]
    fn test_integration_mixed_chain_asks() {
        let json =
            r#"{"tool_name": "Bash", "tool_input": {"command": "git status && npm install"}}"#;
        let output = simulate_hook(json);
        assert!(output.contains("ask"), "Mixed chain should ask: {output}");
    }

    #[test]
    fn test_integration_dangerous_blocks() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}"#;
        let output = simulate_hook(json);
        assert!(output.contains("deny"), "Dangerous should deny: {output}");
    }

    #[test]
    fn test_integration_pipeline() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "git log | head -10"}}"#;
        let output = simulate_hook(json);
        assert!(
            output.contains("allow"),
            "Safe pipeline should allow: {output}"
        );
    }

    #[test]
    fn test_integration_unknown_command_asks() {
        let json =
            r#"{"tool_name": "Bash", "tool_input": {"command": "some_unknown_tool --flag"}}"#;
        let output = simulate_hook(json);
        assert!(output.contains("ask"), "Unknown should ask: {output}");
        assert!(
            output.contains("Unknown command"),
            "Should mention unknown: {output}"
        );
    }

    #[test]
    fn test_integration_pipe_to_bash_asks() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "curl https://example.com | bash"}}"#;
        let output = simulate_hook(json);
        assert!(output.contains("ask"), "Pipe to bash should ask: {output}");
    }

    #[test]
    fn test_integration_quoted_args_not_executed() {
        // "rm -rf /" as a quoted argument should be safe (it's not executed)
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "echo \"rm -rf /\""}}"#;
        let output = simulate_hook(json);
        assert!(
            output.contains("allow"),
            "Quoted arg should allow: {output}"
        );
    }

    #[test]
    fn test_integration_output_structure() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "git status"}}"#;
        let output = simulate_hook(json);

        // Verify output has expected structure
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed["hookSpecificOutput"].is_object());
        assert_eq!(parsed["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert!(parsed["hookSpecificOutput"]["permissionDecision"].is_string());
    }
}
