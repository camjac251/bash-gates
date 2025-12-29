//! Main router that combines all gates.

use crate::gates::GATES;
use crate::mise::{
    extract_task_commands, find_mise_config, load_mise_config, parse_mise_invocation,
};
use crate::models::{
    CommandInfo, Decision, GateResult, HookOutput, Suggestion, SuggestionBehavior,
    SuggestionDestination, SuggestionRule,
};
use crate::package_json::{
    find_package_json, get_script_command, load_package_json, parse_script_invocation,
};
use crate::parser::extract_commands;
use crate::settings::{Settings, SettingsDecision};
use regex::Regex;

/// Check a bash command string and return the appropriate hook output.
///
/// Handles compound commands (&&, ||, |, ;) by checking each command
/// and applying the strictest decision.
///
/// Priority: BLOCK > ASK > ALLOW
pub fn check_command(command_string: &str) -> HookOutput {
    if command_string.trim().is_empty() {
        return HookOutput::approve();
    }

    // Check for patterns at the raw string level
    // These require approval regardless of how they're parsed
    if let Some(result) = check_raw_string_patterns(command_string) {
        return result;
    }

    // Parse the command into individual commands
    let commands = extract_commands(command_string);

    if commands.is_empty() {
        return HookOutput::approve();
    }

    // Collect results from all commands
    let mut block_reasons: Vec<String> = Vec::new();
    let mut ask_reasons: Vec<String> = Vec::new();
    let mut command_decisions: Vec<(CommandInfo, Decision)> = Vec::new();

    for cmd in &commands {
        let result = check_single_command(cmd);

        // Track decisions for suggestion generation
        command_decisions.push((cmd.clone(), result.decision));

        match result.decision {
            Decision::Block => {
                if let Some(reason) = result.reason {
                    block_reasons.push(reason);
                }
            }
            Decision::Ask => {
                if let Some(reason) = result.reason {
                    ask_reasons.push(reason);
                }
            }
            Decision::Allow => {
                // Explicitly allowed - no action needed
            }
            Decision::Skip => {
                // No gate handled this command - requires approval
                ask_reasons.push(format!("Unknown command: {}", cmd.program));
            }
        }
    }

    // Apply priority: block > ask > allow
    if !block_reasons.is_empty() {
        let combined = if block_reasons.len() == 1 {
            block_reasons.remove(0)
        } else {
            format!(
                "Multiple checks blocked:\n{}",
                block_reasons
                    .iter()
                    .map(|r| format!("• {r}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        };
        return HookOutput::deny(&combined);
    }

    if !ask_reasons.is_empty() {
        let combined = if ask_reasons.len() == 1 {
            ask_reasons.remove(0)
        } else {
            format!(
                "Approval needed:\n{}",
                ask_reasons
                    .iter()
                    .map(|r| format!("• {r}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        };

        // Generate suggestions for the ask decision
        let suggestions = generate_suggestions_for_commands(&commands, &command_decisions);
        return HookOutput::ask_with_suggestions(&combined, suggestions);
    }

    // All checks passed - explicitly allow
    HookOutput::allow(Some("Read-only operation"))
}

/// Check a bash command with settings.json awareness and permission mode detection.
///
/// Loads settings from user (~/.claude/settings.json) and project (.claude/settings.json),
/// and combines with gate analysis.
///
/// Priority order:
/// 1. Gate blocks → deny directly (dangerous commands always blocked)
/// 2. Settings.json deny → deny (user's explicit deny rules always respected)
/// 3. acceptEdits mode + file-editing command → allow automatically
/// 4. Settings.json ask → ask (defer to Claude Code)
/// 5. Settings.json allow → allow
/// 6. Gate result (allow/ask)
pub fn check_command_with_settings(
    command_string: &str,
    cwd: &str,
    permission_mode: &str,
) -> HookOutput {
    if command_string.trim().is_empty() {
        return HookOutput::approve();
    }

    // Check for mise task invocation and expand to underlying commands
    if let Some(task_name) = parse_mise_invocation(command_string) {
        return check_mise_task(&task_name, command_string, cwd, permission_mode);
    }

    // Check for package.json script invocation (npm run, pnpm run, etc.)
    if let Some((pm, script_name)) = parse_script_invocation(command_string) {
        return check_package_script(pm, &script_name, command_string, cwd, permission_mode);
    }

    // Run gate analysis first - blocks take priority
    let gate_result = check_command(command_string);

    // If gates block, deny directly (dangerous commands should never be deferred)
    if let Some(ref output) = gate_result.hook_specific_output {
        if output.permission_decision == "deny" {
            return gate_result;
        }
    }

    // Load settings.json (user + project) - needed for deny check, acceptEdits check, and rule matching
    let settings = Settings::load(cwd);

    // Check settings.json deny rules FIRST - user's explicit deny rules always respected
    // This must happen before acceptEdits to prevent acceptEdits from bypassing deny rules
    if settings.is_denied(command_string) {
        return HookOutput::deny("Matched settings.json deny rule");
    }

    // In acceptEdits mode, auto-allow file-editing commands that:
    // - Are file-editing commands
    // - Don't target sensitive paths (system files, credentials)
    // - Don't target paths outside allowed directories (cwd + additionalDirectories)
    if permission_mode == "acceptEdits" {
        if let Some(ref output) = gate_result.hook_specific_output {
            if output.permission_decision == "ask" {
                let commands = extract_commands(command_string);
                let allowed_dirs = settings.allowed_directories(cwd);
                if should_auto_allow_in_accept_edits(&commands, &allowed_dirs) {
                    return HookOutput::allow(Some("Auto-allowed in acceptEdits mode"));
                }
            }
        }
    }

    // Check remaining settings.json rules (ask/allow) - deny already checked above
    match settings.check_command_excluding_deny(command_string) {
        SettingsDecision::Ask => {
            // User wants to be asked - defer to Claude Code
            return HookOutput::ask("Matched settings.json ask rule");
        }
        SettingsDecision::Allow => {
            // User explicitly allows - return allow immediately
            return HookOutput::allow(Some("Matched settings.json allow rule"));
        }
        SettingsDecision::Deny => {
            // Should not happen since we use check_command_excluding_deny
            unreachable!("check_command_excluding_deny should not return Deny");
        }
        SettingsDecision::NoMatch => {
            // No match - use gate result
        }
    }

    // Return gate result (allow or ask)
    gate_result
}

/// Generate suggestions for a wrapper command (mise task or npm script).
/// Returns suggestions for both canonical and shorthand patterns if they differ.
/// - `canonical_pattern`: The normalized form, e.g., "pnpm run lint" or "mise run build"
/// - `original_pattern`: The original invocation form, e.g., "pnpm lint" or "mise build"
fn generate_wrapper_suggestions(
    canonical_pattern: &str,
    original_pattern: &str,
) -> Vec<Suggestion> {
    let mut rules = vec![SuggestionRule {
        tool_name: "Bash".to_string(),
        rule_content: Some(format!("{canonical_pattern}:*")),
    }];

    // If original differs from canonical (shorthand form), add that pattern too
    // This ensures "pnpm lint" gets both "pnpm run lint:*" and "pnpm lint:*"
    if original_pattern != canonical_pattern {
        rules.push(SuggestionRule {
            tool_name: "Bash".to_string(),
            rule_content: Some(format!("{original_pattern}:*")),
        });
    }

    // Wrapper commands are always project-specific (scripts/tasks vary per project)
    vec![
        Suggestion::AddRules {
            rules: rules.clone(),
            behavior: SuggestionBehavior::Allow,
            destination: SuggestionDestination::Session,
        },
        Suggestion::AddRules {
            rules,
            behavior: SuggestionBehavior::Allow,
            destination: SuggestionDestination::LocalSettings,
        },
    ]
}

/// Check a mise task by expanding it to its underlying commands.
///
/// Finds the mise config file, extracts the task's run commands (including dependencies),
/// and checks each command through the gate engine.
/// - `task_name`: The task name (e.g., "lint", "build:prod")
/// - `original_cmd`: The original command string (e.g., "mise lint" or "mise run lint")
/// - `permission_mode`: The permission mode (e.g., "default", "acceptEdits")
fn check_mise_task(
    task_name: &str,
    original_cmd: &str,
    cwd: &str,
    permission_mode: &str,
) -> HookOutput {
    // Find mise config file
    let Some(config_path) = find_mise_config(cwd) else {
        return HookOutput::ask(&format!("mise {task_name}: No mise.toml found"));
    };

    // Load and parse the config
    let Some(config) = load_mise_config(&config_path) else {
        return HookOutput::ask(&format!("mise {task_name}: Failed to parse mise.toml"));
    };

    // Extract all commands for this task (including dependencies)
    let commands = extract_task_commands(&config, task_name);

    if commands.is_empty() {
        return HookOutput::ask(&format!(
            "mise {task_name}: Task not found or has no commands"
        ));
    }

    // Check each command through the gate engine
    let mut block_reasons: Vec<String> = Vec::new();
    let mut ask_reasons: Vec<String> = Vec::new();

    for cmd_string in &commands {
        // Check each extracted command, with package.json expansion support
        let result = check_command_expanded(cmd_string, cwd, permission_mode);

        if let Some(ref output) = result.hook_specific_output {
            match output.permission_decision.as_str() {
                "deny" => {
                    if let Some(reason) = &output.permission_decision_reason {
                        block_reasons.push(format!("mise {task_name}: {reason}"));
                    } else {
                        block_reasons.push(format!("mise {task_name}: Blocked"));
                    }
                }
                "ask" => {
                    if let Some(reason) = &output.permission_decision_reason {
                        ask_reasons.push(format!("mise {task_name}: {reason}"));
                    } else {
                        ask_reasons.push(format!("mise {task_name}: Requires approval"));
                    }
                }
                _ => {}
            }
        }
    }

    // Apply priority: block > ask > allow
    if !block_reasons.is_empty() {
        let combined = if block_reasons.len() == 1 {
            block_reasons.remove(0)
        } else {
            block_reasons.join("; ")
        };
        return HookOutput::deny(&combined);
    }

    if !ask_reasons.is_empty() {
        let combined = if ask_reasons.len() == 1 {
            ask_reasons.remove(0)
        } else {
            ask_reasons.join("; ")
        };
        // Generate suggestions for the mise wrapper command
        // Extract original pattern from the original command (handles "mise lint" vs "mise run lint")
        let original_pattern = original_cmd
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        let suggestions =
            generate_wrapper_suggestions(&format!("mise run {task_name}"), &original_pattern);
        return HookOutput::ask_with_suggestions(&combined, suggestions);
    }

    // All commands are safe
    HookOutput::allow(Some(&format!("mise {task_name}: All commands safe")))
}

/// Check a package.json script by expanding it to its underlying command.
///
/// Finds package.json, extracts the script's command, and checks it through the gate engine.
/// - `pm`: The package manager name (e.g., "pnpm", "npm")
/// - `script_name`: The script name (e.g., "lint", "build")
/// - `original_cmd`: The original command string (e.g., "pnpm lint" or "pnpm run lint")
/// - `permission_mode`: The permission mode (e.g., "default", "acceptEdits")
fn check_package_script(
    pm: &str,
    script_name: &str,
    original_cmd: &str,
    cwd: &str,
    permission_mode: &str,
) -> HookOutput {
    // Find package.json
    let Some(pkg_path) = find_package_json(cwd) else {
        // No package.json found - fall back to normal gate check
        // This handles cases like running in a subdirectory
        return HookOutput::ask(&format!("{pm} run {script_name}: No package.json found"));
    };

    // Load and parse package.json
    let Some(pkg) = load_package_json(&pkg_path) else {
        return HookOutput::ask(&format!(
            "{pm} run {script_name}: Failed to parse package.json"
        ));
    };

    // Get the script command
    let Some(script_cmd) = get_script_command(&pkg, script_name) else {
        return HookOutput::ask(&format!("{pm} run {script_name}: Script not found"));
    };

    // Check the underlying command through the gate engine
    let result = check_command(&script_cmd);

    if let Some(ref output) = result.hook_specific_output {
        match output.permission_decision.as_str() {
            "deny" => {
                let reason = output
                    .permission_decision_reason
                    .as_deref()
                    .unwrap_or("Blocked");
                return HookOutput::deny(&format!("{pm} run {script_name}: {reason}"));
            }
            "ask" => {
                // In acceptEdits mode, check if the underlying command is a file-editing command
                if permission_mode == "acceptEdits" {
                    let commands = extract_commands(&script_cmd);
                    let settings = Settings::load(cwd);
                    let allowed_dirs = settings.allowed_directories(cwd);
                    if should_auto_allow_in_accept_edits(&commands, &allowed_dirs) {
                        return HookOutput::allow(Some(&format!(
                            "{pm} run {script_name}: Auto-allowed in acceptEdits mode"
                        )));
                    }
                }

                let reason = output
                    .permission_decision_reason
                    .as_deref()
                    .unwrap_or("Requires approval");
                // Generate suggestions for the package manager wrapper command
                // Extract original pattern from the original command (handles "pnpm lint" vs "pnpm run lint")
                let original_pattern = original_cmd
                    .split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ");
                let suggestions = generate_wrapper_suggestions(
                    &format!("{pm} run {script_name}"),
                    &original_pattern,
                );
                return HookOutput::ask_with_suggestions(
                    &format!("{pm} run {script_name}: {reason}"),
                    suggestions,
                );
            }
            "allow" => {
                return HookOutput::allow(Some(&format!(
                    "{pm} run {script_name}: {}",
                    output
                        .permission_decision_reason
                        .as_deref()
                        .unwrap_or("Safe")
                )));
            }
            _ => {}
        }
    }

    // Fallback
    HookOutput::ask(&format!("{pm} run {script_name}"))
}

/// Check a command with package.json script expansion.
/// Used by mise task expansion to handle commands like "pnpm lint" properly.
fn check_command_expanded(command_string: &str, cwd: &str, permission_mode: &str) -> HookOutput {
    if command_string.trim().is_empty() {
        return HookOutput::approve();
    }

    // First do raw string security checks
    if let Some(output) = check_raw_string_patterns(command_string) {
        return output;
    }

    // Parse the command with tree-sitter to extract individual commands
    let commands = extract_commands(command_string);

    if commands.is_empty() {
        return HookOutput::ask(&format!("Unknown command: {command_string}"));
    }

    // Check each parsed command, tracking cwd changes from "cd" commands
    let mut block_reasons: Vec<String> = Vec::new();
    let mut ask_reasons: Vec<String> = Vec::new();
    let mut effective_cwd = std::path::PathBuf::from(cwd);

    for cmd in &commands {
        // Track "cd" commands to update effective cwd
        if cmd.program == "cd" && !cmd.args.is_empty() {
            let target = &cmd.args[0];
            if !target.starts_with('/') {
                // Relative path
                effective_cwd.push(target);
            } else {
                // Absolute path
                effective_cwd = std::path::PathBuf::from(target);
            }
            continue; // cd itself is always safe
        }

        let cwd_str = effective_cwd.to_string_lossy();
        // Try package.json script expansion for this individual command
        if let Some((pm, script_name)) = parse_script_invocation(&cmd.raw) {
            let result =
                check_package_script(pm, &script_name, &cmd.raw, &cwd_str, permission_mode);
            if let Some(ref output) = result.hook_specific_output {
                match output.permission_decision.as_str() {
                    "deny" => {
                        block_reasons.push(
                            output
                                .permission_decision_reason
                                .clone()
                                .unwrap_or_else(|| "Blocked".to_string()),
                        );
                    }
                    "ask" => {
                        ask_reasons.push(
                            output
                                .permission_decision_reason
                                .clone()
                                .unwrap_or_else(|| "Requires approval".to_string()),
                        );
                    }
                    _ => {}
                }
            }
        } else {
            // Run through gates
            let result = check_single_command(cmd);
            match result.decision {
                Decision::Block => {
                    block_reasons.push(result.reason.unwrap_or_else(|| "Blocked".to_string()));
                }
                Decision::Ask => {
                    // In acceptEdits mode, check if this is a file-editing command
                    if permission_mode == "acceptEdits" {
                        let settings = Settings::load(&cwd_str);
                        let allowed_dirs = settings.allowed_directories(&cwd_str);
                        if should_auto_allow_in_accept_edits(std::slice::from_ref(cmd), &allowed_dirs) {
                            // Auto-allow file-editing command in acceptEdits mode
                            continue;
                        }
                    }
                    ask_reasons.push(
                        result
                            .reason
                            .unwrap_or_else(|| "Requires approval".to_string()),
                    );
                }
                Decision::Allow => {}
                Decision::Skip => {
                    ask_reasons.push(format!("Unknown command: {}", cmd.program));
                }
            }
        }
    }

    // Apply priority: block > ask > allow
    if !block_reasons.is_empty() {
        let combined = if block_reasons.len() == 1 {
            block_reasons.remove(0)
        } else {
            block_reasons.join("; ")
        };
        return HookOutput::deny(&combined);
    }

    if !ask_reasons.is_empty() {
        let combined = if ask_reasons.len() == 1 {
            ask_reasons.remove(0)
        } else {
            ask_reasons.join("; ")
        };
        return HookOutput::ask(&combined);
    }

    HookOutput::approve()
}

/// Check raw string patterns before parsing.
fn check_raw_string_patterns(command_string: &str) -> Option<HookOutput> {
    // Dangerous pipe patterns - use regex with word boundaries to avoid false positives
    // like "|shell=True" matching "|sh"
    let pipe_patterns: &[(&str, &str)] = &[
        // Shell interpreters (word boundary prevents matching "shell", "bash_script", etc.)
        (r"\|\s*bash\b", "Piping to bash"),
        (r"\|\s*/bin/bash\b", "Piping to bash"),
        (r"\|\s*/usr/bin/bash\b", "Piping to bash"),
        (r"\|\s*sh\b", "Piping to sh"),
        (r"\|\s*/bin/sh\b", "Piping to sh"),
        (r"\|\s*/usr/bin/sh\b", "Piping to sh"),
        (r"\|\s*zsh\b", "Piping to zsh"),
        (r"\|\s*/bin/zsh\b", "Piping to zsh"),
        (r"\|\s*/usr/bin/zsh\b", "Piping to zsh"),
        // Privilege escalation
        (r"\|\s*sudo\b", "Piping to sudo"),
        (r"\|\s*/usr/bin/sudo\b", "Piping to sudo"),
        (r"\|\s*doas\b", "Piping to doas"),
        // Script interpreters
        (r"\|\s*python[0-9.]*\b", "Piping to python"),
        (r"\|\s*perl\b", "Piping to perl"),
        (r"\|\s*ruby\b", "Piping to ruby"),
        (r"\|\s*node\b", "Piping to node"),
    ];

    for (pattern, reason) in pipe_patterns {
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(command_string) {
                return Some(HookOutput::ask(reason));
            }
        }
    }

    // Check for eval command (arbitrary code execution)
    if let Ok(re) = Regex::new(r"(^|[;&|])\s*eval\s") {
        if re.is_match(command_string) {
            return Some(HookOutput::ask("eval: Arbitrary code execution"));
        }
    }

    // Check for source / . command (sourcing scripts can modify environment)
    // Match: source <file> or . <file> (but not .. or ./)
    if let Ok(re) = Regex::new(r"(^|[;&|])\s*source\s+\S") {
        if re.is_match(command_string) {
            return Some(HookOutput::ask("source: Sourcing external script"));
        }
    }
    // Match standalone . followed by space and non-dot (to avoid matching .. or ./)
    if let Ok(re) = Regex::new(r"(^|[;&|])\s*\.\s+[^.]") {
        if re.is_match(command_string) {
            return Some(HookOutput::ask(".: Sourcing external script"));
        }
    }

    // xargs with dangerous commands
    if command_string.contains("xargs") {
        let dangerous_xargs = ["rm", "mv", "cp", "chmod", "chown", "dd", "shred"];
        for cmd in dangerous_xargs {
            let pattern = format!(r"xargs\s+.*{cmd}|xargs\s+{cmd}");
            if let Ok(re) = Regex::new(&pattern) {
                if re.is_match(command_string) {
                    return Some(HookOutput::ask(&format!("xargs piping to {cmd}")));
                }
            }
        }
    }

    // find with destructive actions
    if command_string.contains("find ") || command_string.contains("find\t") {
        let destructive_find = ["-delete", "-exec rm", "-exec mv", "-execdir rm"];
        for action in destructive_find {
            if command_string.contains(action) {
                return Some(HookOutput::ask(&format!("find with {action}")));
            }
        }
    }

    // fd with -x/--exec executing dangerous commands
    if command_string.contains("fd ") || command_string.contains("fd\t") {
        // Check for -x or --exec flags
        if command_string.contains(" -x ")
            || command_string.contains("\t-x ")
            || command_string.contains(" -x\t")
            || command_string.contains(" --exec ")
            || command_string.contains("\t--exec ")
            || command_string.contains(" --exec\t")
            || command_string.contains(" -X ")
            || command_string.contains("\t-X ")
            || command_string.contains(" -X\t")
            || command_string.contains(" --exec-batch ")
            || command_string.contains("\t--exec-batch ")
            || command_string.contains(" --exec-batch\t")
        {
            let dangerous_exec = ["rm", "mv", "chmod", "chown", "dd", "shred"];
            for cmd in dangerous_exec {
                // Check for the command following exec flags
                let patterns = [
                    format!("-x {cmd}"),
                    format!("-x\t{cmd}"),
                    format!("--exec {cmd}"),
                    format!("--exec\t{cmd}"),
                    format!("-X {cmd}"),
                    format!("-X\t{cmd}"),
                    format!("--exec-batch {cmd}"),
                    format!("--exec-batch\t{cmd}"),
                ];
                for pattern in &patterns {
                    if command_string.contains(pattern) {
                        return Some(HookOutput::ask(&format!("fd executing {cmd}")));
                    }
                }
            }
        }
    }

    // Command substitution with dangerous commands
    let dangerous_in_subst = ["rm ", "rm\t", "mv ", "chmod ", "chown ", "dd "];

    // $() substitution
    if let Ok(re) = Regex::new(r"\$\([^)]+\)") {
        for cap in re.captures_iter(command_string) {
            let subst = cap.get(0).map_or("", |m| m.as_str());
            for danger in dangerous_in_subst {
                if subst.contains(danger) {
                    let truncated = if subst.len() > 30 {
                        &subst[..30]
                    } else {
                        subst
                    };
                    return Some(HookOutput::ask(&format!(
                        "Dangerous command in substitution: {truncated}"
                    )));
                }
            }
        }
    }

    // Backtick substitution
    if let Ok(re) = Regex::new(r"`[^`]+`") {
        for cap in re.captures_iter(command_string) {
            let subst = cap.get(0).map_or("", |m| m.as_str());
            for danger in dangerous_in_subst {
                if subst.contains(danger) {
                    let truncated = if subst.len() > 30 {
                        &subst[..30]
                    } else {
                        subst
                    };
                    return Some(HookOutput::ask(&format!(
                        "Dangerous command in backticks: {truncated}"
                    )));
                }
            }
        }
    }

    // Leading semicolon (potential injection)
    if command_string.trim().starts_with(';') {
        return Some(HookOutput::ask("Command starts with semicolon"));
    }

    // Output redirections (file writes)
    // Matches: > file, >> file, &> file, but not 2> (stderr only)
    // Excludes /dev/null (discarding output, not writing)
    // Note: [^0-9&=/$] excludes = for => (arrow operators), / for /> (JSX self-closing tags),
    //       and $ for ast-grep metavariables like $$>
    if let Ok(re) = Regex::new(r"(^|[^0-9&=/$])>{1,2}\s*([^>&\s]+)") {
        for cap in re.captures_iter(command_string) {
            if let Some(target) = cap.get(2) {
                let target_str = target.as_str();
                // Skip /dev/null - it's just discarding output
                if target_str != "/dev/null" {
                    return Some(HookOutput::ask("Output redirection (writes to file)"));
                }
            }
        }
    }
    if let Ok(re) = Regex::new(r"&>\s*([^\s]+)") {
        for cap in re.captures_iter(command_string) {
            if let Some(target) = cap.get(1) {
                let target_str = target.as_str();
                if target_str != "/dev/null" {
                    return Some(HookOutput::ask("Output redirection (writes to file)"));
                }
            }
        }
    }

    None
}

/// Check a single command against all gates.
pub fn check_single_command(cmd: &crate::models::CommandInfo) -> GateResult {
    let mut strictest = GateResult::skip();

    for (_gate_name, gate_func) in GATES {
        let result = gate_func(cmd);

        // Track the strictest decision (Block > Ask > Allow > Skip)
        if result.decision > strictest.decision {
            strictest = result;
        }

        // Early return on Block (can't get stricter)
        if strictest.decision == Decision::Block {
            return strictest;
        }
    }

    strictest
}

// === Accept Edits Mode ===

/// Check if commands should be auto-allowed in acceptEdits mode.
/// Returns true if all commands are file-editing operations that:
/// - Don't target sensitive paths (system files, credentials)
/// - Don't target paths outside allowed directories
fn should_auto_allow_in_accept_edits(commands: &[CommandInfo], allowed_dirs: &[String]) -> bool {
    if commands.is_empty() {
        return false;
    }
    let all_file_edits = commands.iter().all(is_file_editing_command);
    let any_sensitive = commands.iter().any(targets_sensitive_path);
    let any_outside = commands
        .iter()
        .any(|cmd| targets_outside_allowed_dirs(cmd, allowed_dirs));
    all_file_edits && !any_sensitive && !any_outside
}

/// Check if a command targets sensitive paths that should not be auto-allowed.
/// Returns true if any argument looks like a sensitive system path.
///
/// This function distinguishes between:
/// 1. System paths (always blocked): /etc, /usr, /bin, etc.
/// 2. Security-critical user paths (always blocked): ~/.ssh, ~/.gnupg, ~/.aws, etc.
/// 3. Regular user dotfiles (allowed): ~/.bashrc, ~/.prettierrc, ~/.config/app.yaml
fn targets_sensitive_path(cmd: &CommandInfo) -> bool {
    // System directories - always blocked (system-wide impact)
    const BLOCKED_SYSTEM_PREFIXES: &[&str] = &[
        "/etc/", "/usr/", "/bin/", "/sbin/", "/var/", "/opt/", "/boot/", "/root/", "/lib/",
        "/lib64/", "/proc/", "/sys/", "/dev/",
    ];

    // Security-critical directories in home - always blocked (credentials/keys)
    // These contain authentication material that could be exfiltrated or modified
    const BLOCKED_SECURITY_DIRS: &[&str] = &[
        "/.ssh/",           // SSH keys
        "/.ssh",            // The directory itself (exact match for ssh dir operations)
        "/.gnupg/",         // GPG keys
        "/.gnupg",          // The directory itself
        "/.aws/",           // AWS credentials
        "/.kube/",          // Kubernetes configs with tokens
        "/.docker/",        // Docker auth configs
        "/.config/gh/",     // GitHub CLI tokens
        "/.password-store/", // pass password manager
        "/.vault-token",    // HashiCorp Vault token
    ];

    // Specific credential files - always blocked
    // These files often contain tokens/passwords even if not in security dirs
    const BLOCKED_CREDENTIAL_FILES: &[&str] = &[
        "/.npmrc",          // npm tokens
        "/.netrc",          // FTP/HTTP credentials
        "/.pypirc",         // PyPI tokens
        "/.gem/credentials", // RubyGems tokens
        "/.m2/settings.xml", // Maven credentials
        "/.gradle/gradle.properties", // Gradle credentials
        "/.nuget/NuGet.Config", // NuGet credentials
        "/id_rsa",          // SSH private key (anywhere in path)
        "/id_ed25519",      // SSH private key (anywhere in path)
        "/id_ecdsa",        // SSH private key (anywhere in path)
        "/id_dsa",          // SSH private key (anywhere in path)
    ];

    // Git hook paths - could be used for code execution attacks
    // Use patterns without leading slash to match both absolute and relative paths
    const BLOCKED_GIT_PATTERNS: &[&str] = &[".git/hooks/", ".githooks/"];

    // Lock files that affect dependency resolution
    const LOCK_FILES: &[&str] = &[
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Cargo.lock",
        "poetry.lock",
        "Pipfile.lock",
        "composer.lock",
        "Gemfile.lock",
    ];

    for arg in &cmd.args {
        // Skip flags
        if arg.starts_with('-') {
            continue;
        }

        // Expand ~ to detect home directory paths
        let expanded = if arg.starts_with("~/") {
            format!("/home/user{}", &arg[1..])
        } else {
            arg.clone()
        };

        // Check system directory prefixes (always blocked)
        for prefix in BLOCKED_SYSTEM_PREFIXES {
            if expanded.starts_with(prefix) {
                return true;
            }
        }

        // Check security-critical directories (always blocked)
        for pattern in BLOCKED_SECURITY_DIRS {
            if expanded.contains(pattern) || arg.contains(pattern) {
                return true;
            }
        }

        // Check specific credential files (always blocked)
        for pattern in BLOCKED_CREDENTIAL_FILES {
            if expanded.contains(pattern) || arg.contains(pattern) {
                return true;
            }
        }

        // Check git hook patterns (always blocked)
        for pattern in BLOCKED_GIT_PATTERNS {
            if expanded.contains(pattern) || arg.contains(pattern) {
                return true;
            }
        }

        // Check lock files (exact filename match at end of path)
        for lock_file in LOCK_FILES {
            if arg.ends_with(lock_file) {
                return true;
            }
        }

        // Note: Regular dotfiles like ~/.bashrc, ~/.zshrc, ~/.prettierrc,
        // ~/.config/app.yaml are now ALLOWED for editing in acceptEdits mode.
        // The targets_outside_allowed_dirs check will still apply if the user
        // hasn't added their home directory to additionalDirectories.
    }

    false
}

/// Check if a command targets paths outside the allowed directories.
/// This prevents acceptEdits mode from modifying files outside the project.
/// Allowed directories include cwd and any additionalDirectories from settings.json.
fn targets_outside_allowed_dirs(cmd: &CommandInfo, allowed_dirs: &[String]) -> bool {
    // Normalize all allowed directories - remove trailing slashes
    let normalized_dirs: Vec<String> = allowed_dirs
        .iter()
        .map(|d| d.trim_end_matches('/').to_string())
        .collect();

    for arg in &cmd.args {
        // Skip flags
        if arg.starts_with('-') {
            continue;
        }

        // Skip empty args
        if arg.is_empty() {
            continue;
        }

        // Tilde paths - expand and check against allowed dirs
        if arg.starts_with("~/") || arg == "~" {
            let expanded = if let Some(home) = dirs::home_dir() {
                if arg == "~" {
                    home.to_string_lossy().to_string()
                } else {
                    home.join(&arg[2..]).to_string_lossy().to_string()
                }
            } else {
                continue; // Can't expand, skip
            };
            // Resolve symlinks in the expanded path
            let resolved = resolve_path(&expanded);
            if !is_under_any_dir(&resolved, &normalized_dirs) {
                return true;
            }
            continue;
        }

        // Absolute paths must be under one of the allowed directories
        if arg.starts_with('/') {
            let resolved = resolve_path(arg);
            if !is_under_any_dir(&resolved, &normalized_dirs) {
                return true;
            }
        }

        // Relative paths with .. that escape cwd (first allowed dir)
        // Note: relative paths are relative to cwd, not other allowed dirs
        if arg.contains("..") {
            let mut depth: i32 = 0;
            let mut min_depth: i32 = 0;
            for part in arg.split('/') {
                if part == ".." {
                    depth -= 1;
                    min_depth = min_depth.min(depth);
                } else if !part.is_empty() && part != "." {
                    depth += 1;
                }
            }
            // If we ever go negative, we're escaping cwd
            if min_depth < 0 {
                return true;
            }
        }

        // For relative paths (not starting with / or ~), resolve symlinks
        // by joining with cwd (first allowed dir) and canonicalizing.
        // This catches symlink escapes like `escape/passwd` where `escape -> /etc`.
        if !arg.starts_with('/') && !arg.starts_with('~') && !normalized_dirs.is_empty() {
            let cwd = &normalized_dirs[0];
            let full_path = std::path::Path::new(cwd).join(arg);
            let resolved = resolve_path(&full_path.to_string_lossy());
            if !is_under_any_dir(&resolved, &normalized_dirs) {
                return true;
            }
        }
    }

    false
}

/// Resolve a path by canonicalizing symlinks, `.` and `..` components.
/// Uses std::fs::canonicalize() when the path exists to resolve symlinks.
/// For non-existent paths, tries to canonicalize the parent directory.
/// Falls back to manual resolution if canonicalization fails.
fn resolve_path(path: &str) -> String {
    use std::path::Path;

    let path_obj = Path::new(path);

    // First, try to canonicalize the full path (resolves symlinks)
    if let Ok(canonical) = std::fs::canonicalize(path_obj) {
        return canonical.to_string_lossy().to_string();
    }

    // If full path doesn't exist, try to canonicalize the parent directory
    // This handles cases like `/home/user/project/symlink/newfile` where
    // `symlink` exists but `newfile` doesn't
    if let Some(parent) = path_obj.parent() {
        if let Ok(canonical_parent) = std::fs::canonicalize(parent) {
            if let Some(filename) = path_obj.file_name() {
                return canonical_parent
                    .join(filename)
                    .to_string_lossy()
                    .to_string();
            }
        }
    }

    // Fall back to manual resolution (handles . and .. but not symlinks)
    resolve_path_manual(path)
}

/// Manual path resolution that handles `.` and `..` components but not symlinks.
/// Used as fallback when filesystem-based canonicalization fails.
fn resolve_path_manual(path: &str) -> String {
    use std::path::Path;

    let path = Path::new(path);
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => components.push("/".to_string()),
            std::path::Component::Normal(s) => {
                if let Some(s) = s.to_str() {
                    components.push(s.to_string());
                }
            }
            std::path::Component::ParentDir => {
                if components.len() > 1 {
                    components.pop();
                }
            }
            std::path::Component::CurDir => {}
            std::path::Component::Prefix(_) => {}
        }
    }
    if components.len() == 1 {
        "/".to_string()
    } else {
        components.join("/").replacen("//", "/", 1)
    }
}

/// Check if a path is under any of the allowed directories.
fn is_under_any_dir(path: &str, allowed_dirs: &[String]) -> bool {
    let path_normalized = path.trim_end_matches('/');
    for dir in allowed_dirs {
        // Must either equal the dir exactly OR start with dir/
        if path_normalized == dir || path_normalized.starts_with(&format!("{}/", dir)) {
            return true;
        }
    }
    false
}

// File-editing detection is now generated from TOML rules with accept_edits_auto_allow = true.
// See src/generated/rules.rs for the generated is_file_editing_command function.
use crate::generated::rules::is_file_editing_command;

// === Suggestion Generation ===

/// Commands that should NEVER get "always allow" suggestions.
/// These are too dangerous to encourage blanket approval.
const NO_SUGGESTION_PROGRAMS: &[&str] = &[
    "rm", "rmdir", "mv", "dd", "shred", "mkfs", "fdisk", "parted",
    "truncate", // Destructive filesystem
    "shutdown", "reboot", "poweroff", "halt", "init", // System control
    "sudo", "doas", "su", "pkexec", // Privilege escalation
    "kill", "pkill", "killall", "skill", "slay", "xkill", // Process control
    "chmod", "chown", "chgrp", // Permission changes
];

/// Commands that are project-specific and shouldn't get global suggestions.
/// These only get session and localSettings destinations.
const PROJECT_SPECIFIC_PROGRAMS: &[&str] = &[
    // Build systems - targets are project-specific
    "make",
    "rake",
    "nx",
    "turbo",
    "bazel",
    "buck",
    "pants",
    "just", // justfile task runner
    // JVM build tools - project-specific build files
    "gradle",
    "gradlew",
    "mvn",
    "ant",
    "sbt",
    "lein", // Clojure
    // Other language build/package tools with project-specific configs
    "composer", // PHP
    "bundle",   // Ruby
    "mix",      // Elixir
    "dotnet",   // .NET
    "swift",    // Swift package manager
    // Cloud infrastructure - too risky for blanket global allows
    "aws",
    "gcloud",
    "az", // Cloud CLIs
    "terraform",
    "tofu",
    "pulumi", // IaC tools
    "kubectl",
    "k",
    "helm", // Kubernetes
    "docker",
    "podman", // Containers (can mount host filesystem)
    // Remote access - hosts differ per project
    "ssh",
    "scp",
    "sftp",
    "rsync",
    // Database clients - connection strings/hosts are project-specific
    "psql",
    "mysql",
    "mongo",
    "mongosh",
    "redis-cli",
    "sqlite3",
    // Database migrations - config is project-specific
    "migrate",
    "goose",
    "dbmate",
    "flyway",
    "alembic",
    // OS package managers - affect system, not project
    "apt",
    "apt-get",
    "dnf",
    "yum",
    "pacman",
    "zypper",
    "apk",
    "brew",
    "nix",
    "nix-env",
    "flatpak",
    "snap",
];

/// Build a rule pattern for a command.
/// Returns the pattern like "git push:*" for use in settings.json rules.
fn build_rule_pattern(cmd: &CommandInfo) -> String {
    let program = &cmd.program;

    // Strip path prefixes (e.g., /usr/bin/npm -> npm)
    let base_program = program.rsplit('/').next().unwrap_or(program);

    if cmd.args.is_empty() {
        // No args - just the program with :* suffix for any invocation
        return format!("{base_program}:*");
    }

    // Programs with two-level subcommand hierarchies (e.g., "gh pr create", "aws s3 cp")
    // For these, include both subcommand levels to avoid overly permissive patterns
    // Example: "gh pr create:*" instead of "gh pr:*" (which would allow gh pr close)
    const TWO_LEVEL_SUBCOMMAND_PROGRAMS: &[&str] = &[
        "gh",      // gh pr create, gh issue list, gh repo clone
        "aws",     // aws s3 cp, aws ec2 describe-instances
        "gcloud",  // gcloud compute instances create
        "az",      // az vm create, az storage blob upload
        "kubectl", // kubectl get pods, kubectl apply -f
        "docker",  // docker container run, docker image build
        "podman",  // podman container run, podman image build
    ];

    // Get the first non-flag arg
    let first_arg_idx = cmd.args.iter().position(|a| !a.starts_with('-'));
    let Some(first_idx) = first_arg_idx else {
        // All args are flags
        return format!("{base_program}:*");
    };

    let first_arg = &cmd.args[first_idx];

    // For two-level subcommand programs, try to include second subcommand
    if TWO_LEVEL_SUBCOMMAND_PROGRAMS.contains(&base_program) {
        // Look for second non-flag arg
        let second_arg_idx = cmd.args[first_idx + 1..]
            .iter()
            .position(|a| !a.starts_with('-'))
            .map(|i| i + first_idx + 1);

        if let Some(second_idx) = second_arg_idx {
            let second_arg = &cmd.args[second_idx];
            // Only include if it looks like a subcommand (not a file path or argument)
            if !second_arg.contains('/') && !second_arg.contains('.') {
                return format!("{base_program} {first_arg} {second_arg}:*");
            }
        }
    }

    format!("{base_program} {first_arg}:*")
}

/// Check if a command should get suggestions.
/// Returns true if we should generate "always allow" suggestions.
fn should_generate_suggestions(cmd: &CommandInfo, decision: Decision) -> bool {
    // Only generate suggestions for Ask decisions
    if decision != Decision::Ask {
        return false;
    }

    // Never suggest for dangerous programs
    let base_program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);
    if NO_SUGGESTION_PROGRAMS.contains(&base_program) {
        return false;
    }

    // Check for dangerous flags even on otherwise-suggestible commands
    if has_dangerous_flags(cmd) {
        return false;
    }

    true
}

/// Check if command has dangerous flags that should prevent suggestions.
fn has_dangerous_flags(cmd: &CommandInfo) -> bool {
    let base_program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);

    // Flags that are always dangerous regardless of program
    // Note: --force-with-lease is intentionally excluded - it's a SAFETY mechanism
    // that prevents force push if remote has been updated since last fetch
    let always_dangerous = [
        "--force",
        "--hard",
        "--delete",
        "--del", // rsync alias for --delete-during
        "--delete-force",
        "--no-preserve-root",
    ];

    // Programs where -f means "force" (dangerous)
    // For others like kubectl, helm, docker, tar, -f means "file" (safe)
    // Note: tar/zip/unzip -f means "file/archive", touch/mkdir have no -f flag
    let f_means_force = [
        "git", "rm", "cp", "mv", "ln", "gzip", "bzip2", "xz", "zstd", "lz4", "pigz",
    ];

    for arg in &cmd.args {
        // Check for combined short flags containing both 'r' and 'f' (like -rf, -rfv, -Rf, -fR)
        // This catches rm -rf style flags in any order with any additional flags
        if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 1 {
            let chars: Vec<char> = arg.chars().skip(1).collect();
            let has_r = chars.iter().any(|&c| c == 'r' || c == 'R');
            let has_f = chars.contains(&'f');
            if has_r && has_f {
                return true;
            }
        }

        // Check always-dangerous flags
        for flag in always_dangerous {
            if arg == flag {
                return true;
            }
        }

        // Check -f only for programs where it means "force"
        if arg == "-f" && f_means_force.contains(&base_program) {
            return true;
        }

        // Check -D for git branch (force delete without merge check)
        if arg == "-D" && base_program == "git" {
            return true;
        }
    }

    false
}

/// Check if a program is project-specific (should not get userSettings suggestions).
fn is_project_specific(cmd: &CommandInfo) -> bool {
    let base_program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);
    PROJECT_SPECIFIC_PROGRAMS.contains(&base_program)
}

/// Generate suggestions for a command.
/// Returns a vec of suggestions for different scopes (session, project, global).
pub fn generate_suggestions(cmd: &CommandInfo, decision: Decision) -> Vec<Suggestion> {
    if !should_generate_suggestions(cmd, decision) {
        return vec![];
    }

    let pattern = build_rule_pattern(cmd);
    let rule = SuggestionRule {
        tool_name: "Bash".to_string(),
        rule_content: Some(pattern),
    };

    let mut suggestions = vec![
        // Session-level (temporary)
        Suggestion::AddRules {
            rules: vec![rule.clone()],
            behavior: SuggestionBehavior::Allow,
            destination: SuggestionDestination::Session,
        },
        // Project-level (persisted to .claude/settings.json)
        Suggestion::AddRules {
            rules: vec![rule.clone()],
            behavior: SuggestionBehavior::Allow,
            destination: SuggestionDestination::LocalSettings,
        },
    ];

    // Add global suggestion for non-project-specific commands
    if !is_project_specific(cmd) {
        suggestions.push(Suggestion::AddRules {
            rules: vec![rule],
            behavior: SuggestionBehavior::Allow,
            destination: SuggestionDestination::UserSettings,
        });
    }

    suggestions
}

/// Generate suggestions for multiple commands, combining patterns.
pub fn generate_suggestions_for_commands(
    _commands: &[CommandInfo],
    decisions: &[(CommandInfo, Decision)],
) -> Vec<Suggestion> {
    // Collect all suggestible commands
    let mut patterns: Vec<String> = Vec::new();
    let mut any_project_specific = false;

    for (cmd, decision) in decisions {
        if should_generate_suggestions(cmd, *decision) {
            patterns.push(build_rule_pattern(cmd));
            if is_project_specific(cmd) {
                any_project_specific = true;
            }
        }
    }

    if patterns.is_empty() {
        return vec![];
    }

    // Build rules for each pattern
    let rules: Vec<SuggestionRule> = patterns
        .into_iter()
        .map(|pattern| SuggestionRule {
            tool_name: "Bash".to_string(),
            rule_content: Some(pattern),
        })
        .collect();

    let mut suggestions = vec![
        Suggestion::AddRules {
            rules: rules.clone(),
            behavior: SuggestionBehavior::Allow,
            destination: SuggestionDestination::Session,
        },
        Suggestion::AddRules {
            rules: rules.clone(),
            behavior: SuggestionBehavior::Allow,
            destination: SuggestionDestination::LocalSettings,
        },
    ];

    // Add global only if none are project-specific
    if !any_project_specific {
        suggestions.push(Suggestion::AddRules {
            rules,
            behavior: SuggestionBehavior::Allow,
            destination: SuggestionDestination::UserSettings,
        });
    }

    suggestions
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to get permission decision
    fn get_decision(result: &HookOutput) -> &str {
        result
            .hook_specific_output
            .as_ref()
            .map_or(result.decision.as_deref().unwrap_or("unknown"), |o| {
                o.permission_decision.as_str()
            })
    }

    fn get_reason(result: &HookOutput) -> &str {
        result
            .hook_specific_output
            .as_ref()
            .and_then(|o| o.permission_decision_reason.as_deref())
            .unwrap_or("")
    }

    fn get_suggestions(result: &HookOutput) -> &Option<Vec<Suggestion>> {
        result
            .hook_specific_output
            .as_ref()
            .map_or(&None, |o| &o.suggestions)
    }

    fn has_suggestions(result: &HookOutput) -> bool {
        get_suggestions(result)
            .as_ref()
            .is_some_and(|s| !s.is_empty())
    }

    // === Suggestion Generation ===

    // === Accept Edits Mode ===

    mod accept_edits_mode {
        use super::*;

        #[test]
        fn test_sd_allowed_in_accept_edits() {
            let result =
                check_command_with_settings("sd 'old' 'new' file.txt", "/tmp", "acceptEdits");
            assert_eq!(get_decision(&result), "allow");
            assert!(get_reason(&result).contains("acceptEdits"));
        }

        #[test]
        fn test_sd_asks_in_default_mode() {
            let result = check_command_with_settings("sd 'old' 'new' file.txt", "/tmp", "default");
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn test_prettier_write_allowed_in_accept_edits() {
            let result =
                check_command_with_settings("prettier --write src/", "/tmp", "acceptEdits");
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_prettier_check_allowed_as_readonly() {
            // prettier --check is read-only, so it's allowed by the devtools gate
            let result =
                check_command_with_settings("prettier --check src/", "/tmp", "acceptEdits");
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_ast_grep_u_allowed_in_accept_edits() {
            let result = check_command_with_settings(
                "ast-grep -p 'old' -r 'new' -U src/",
                "/tmp",
                "acceptEdits",
            );
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_ast_grep_search_asks_in_accept_edits() {
            // ast-grep without -U is read-only search
            let result =
                check_command_with_settings("ast-grep -p 'pattern' src/", "/tmp", "acceptEdits");
            // Should still be allowed (read-only), let me check the gate
            assert_eq!(get_decision(&result), "allow"); // ast-grep search is allowed by devtools gate
        }

        #[test]
        fn test_sed_i_allowed_in_accept_edits() {
            let result =
                check_command_with_settings("sed -i 's/old/new/g' file.txt", "/tmp", "acceptEdits");
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_black_allowed_in_accept_edits() {
            let result = check_command_with_settings("black src/", "/tmp", "acceptEdits");
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_rustfmt_allowed_in_accept_edits() {
            let result = check_command_with_settings("rustfmt src/main.rs", "/tmp", "acceptEdits");
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_npm_install_still_asks_in_accept_edits() {
            // npm install is NOT a file-editing command - it's package management
            let result = check_command_with_settings("npm install", "/tmp", "acceptEdits");
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn test_git_push_still_asks_in_accept_edits() {
            // git push is NOT a file-editing command
            let result = check_command_with_settings("git push", "/tmp", "acceptEdits");
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn test_rm_still_asks_in_accept_edits() {
            // rm is deletion, not editing - should still ask
            let result = check_command_with_settings("rm file.txt", "/tmp", "acceptEdits");
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn test_blocked_still_blocks_in_accept_edits() {
            // Dangerous commands should still be blocked
            let result = check_command_with_settings("rm -rf /", "/tmp", "acceptEdits");
            assert_eq!(get_decision(&result), "deny");
        }

        #[test]
        fn test_yq_i_allowed_in_accept_edits() {
            let result = check_command_with_settings(
                "yq -i '.key = \"value\"' file.yaml",
                "/tmp",
                "acceptEdits",
            );
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_eslint_fix_allowed_in_accept_edits() {
            let result = check_command_with_settings("eslint --fix src/", "/tmp", "acceptEdits");
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_ruff_format_allowed_in_accept_edits() {
            let result = check_command_with_settings("ruff format src/", "/tmp", "acceptEdits");
            assert_eq!(get_decision(&result), "allow");
        }

        // === Outside CWD Tests ===

        #[test]
        fn test_absolute_path_outside_cwd_asks() {
            // sd editing a file outside cwd should ask, not auto-allow
            let result = check_command_with_settings(
                "sd 'old' 'new' /etc/config",
                "/home/user/project",
                "acceptEdits",
            );
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn test_absolute_path_inside_cwd_allows() {
            // sd editing a file inside cwd should be auto-allowed
            let result = check_command_with_settings(
                "sd 'old' 'new' /home/user/project/file.txt",
                "/home/user/project",
                "acceptEdits",
            );
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_tilde_path_asks() {
            // Tilde paths are outside cwd
            let result = check_command_with_settings(
                "sd 'old' 'new' ~/file.txt",
                "/home/user/project",
                "acceptEdits",
            );
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn test_parent_escape_asks() {
            // ../.. escapes cwd
            let result = check_command_with_settings(
                "sd 'old' 'new' ../../file.txt",
                "/home/user/project",
                "acceptEdits",
            );
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn test_parent_escape_deep_asks() {
            // Even deeper escapes
            let result = check_command_with_settings(
                "sd 'old' 'new' foo/../../../bar.txt",
                "/home/user/project",
                "acceptEdits",
            );
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn test_parent_within_cwd_allows() {
            // foo/../bar stays within cwd
            let result = check_command_with_settings(
                "sd 'old' 'new' foo/../bar.txt",
                "/home/user/project",
                "acceptEdits",
            );
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_relative_path_allows() {
            // Plain relative paths are fine
            let result = check_command_with_settings(
                "sd 'old' 'new' src/file.txt",
                "/home/user/project",
                "acceptEdits",
            );
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_dot_relative_allows() {
            // ./foo is still within cwd
            let result = check_command_with_settings(
                "sd 'old' 'new' ./file.txt",
                "/home/user/project",
                "acceptEdits",
            );
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_absolute_with_traversal_outside_asks() {
            // Absolute path with .. that resolves outside cwd
            let result = check_command_with_settings(
                "sd 'old' 'new' /home/user/project/../other/file.txt",
                "/home/user/project",
                "acceptEdits",
            );
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn test_similar_prefix_dir_asks() {
            // /home/user/projectX is NOT inside /home/user/project
            let result = check_command_with_settings(
                "sd 'old' 'new' /home/user/projectX/file.txt",
                "/home/user/project",
                "acceptEdits",
            );
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn test_exact_cwd_path_allows() {
            // Exact cwd path should be allowed
            let result = check_command_with_settings(
                "rustfmt /home/user/project",
                "/home/user/project",
                "acceptEdits",
            );
            assert_eq!(get_decision(&result), "allow");
        }
    }

    mod additional_directories {
        use super::*;
        use crate::models::CommandInfo;

        fn cmd(program: &str, args: &[&str]) -> CommandInfo {
            CommandInfo {
                program: program.to_string(),
                args: args.iter().map(|s| s.to_string()).collect(),
                raw: format!(
                    "{} {}",
                    program,
                    args.iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            }
        }

        #[test]
        fn test_path_in_additional_dir_allowed() {
            let allowed = vec![
                "/home/user/project".to_string(),
                "/home/user/other-project".to_string(),
            ];
            // Path in additional directory should be allowed
            let result = targets_outside_allowed_dirs(
                &cmd("sd", &["old", "new", "/home/user/other-project/file.txt"]),
                &allowed,
            );
            assert!(!result, "Path in additional directory should be allowed");
        }

        #[test]
        fn test_path_outside_all_dirs_rejected() {
            let allowed = vec![
                "/home/user/project".to_string(),
                "/home/user/other-project".to_string(),
            ];
            // Path outside all allowed directories should be rejected
            let result = targets_outside_allowed_dirs(
                &cmd("sd", &["old", "new", "/tmp/file.txt"]),
                &allowed,
            );
            assert!(
                result,
                "Path outside all allowed directories should be rejected"
            );
        }

        #[test]
        fn test_tilde_path_in_additional_dir() {
            // If ~/projects is in allowed dirs, ~/projects/foo should be allowed
            let home = dirs::home_dir().unwrap().to_string_lossy().to_string();
            let allowed = vec![
                "/home/user/project".to_string(),
                format!("{}/projects", home),
            ];
            let result = targets_outside_allowed_dirs(
                &cmd("sd", &["old", "new", "~/projects/file.txt"]),
                &allowed,
            );
            assert!(
                !result,
                "Tilde path in additional directory should be allowed"
            );
        }

        #[test]
        fn test_tilde_path_outside_all_dirs() {
            let allowed = vec!["/home/user/project".to_string()];
            let result = targets_outside_allowed_dirs(
                &cmd("sd", &["old", "new", "~/other/file.txt"]),
                &allowed,
            );
            assert!(
                result,
                "Tilde path outside allowed directories should be rejected"
            );
        }

        #[test]
        fn test_multiple_allowed_dirs_any_match() {
            let allowed = vec![
                "/home/user/project1".to_string(),
                "/home/user/project2".to_string(),
                "/home/user/project3".to_string(),
            ];
            // Path in any of the allowed directories should work
            assert!(!targets_outside_allowed_dirs(
                &cmd("sd", &["old", "new", "/home/user/project2/src/file.txt"]),
                &allowed
            ));
            assert!(!targets_outside_allowed_dirs(
                &cmd("sd", &["old", "new", "/home/user/project3/file.txt"]),
                &allowed
            ));
        }

        /// Test that settings.json deny rules take precedence over acceptEdits mode.
        /// Regression test for bug: acceptEdits override was happening BEFORE settings.json
        /// deny rules were checked, allowing denied commands to bypass user's explicit deny rules.
        #[test]
        fn test_settings_deny_overrides_accept_edits() {
            use std::fs;
            use tempfile::TempDir;

            // Create a temp directory with .claude/settings.json containing deny rules
            let temp_dir = TempDir::new().unwrap();
            let claude_dir = temp_dir.path().join(".claude");
            fs::create_dir(&claude_dir).unwrap();

            // Create settings.json with deny rule for sd
            let settings_content = r#"{
                "permissions": {
                    "deny": ["Bash(sd:*)"]
                }
            }"#;
            fs::write(claude_dir.join("settings.json"), settings_content).unwrap();

            let cwd = temp_dir.path().to_str().unwrap();

            // In acceptEdits mode, sd would normally be auto-allowed
            // But with deny rule, it should be denied
            let result = check_command_with_settings("sd 'old' 'new' file.txt", cwd, "acceptEdits");
            assert_eq!(
                get_decision(&result),
                "deny",
                "Settings deny should override acceptEdits auto-allow"
            );
            assert!(
                get_reason(&result).contains("settings.json deny"),
                "Should mention settings.json deny rule"
            );
        }

        /// Test that settings.json deny rules also work with other file-editing commands
        #[test]
        fn test_settings_deny_prettier_overrides_accept_edits() {
            use std::fs;
            use tempfile::TempDir;

            let temp_dir = TempDir::new().unwrap();
            let claude_dir = temp_dir.path().join(".claude");
            fs::create_dir(&claude_dir).unwrap();

            let settings_content = r#"{
                "permissions": {
                    "deny": ["Bash(prettier --write:*)"]
                }
            }"#;
            fs::write(claude_dir.join("settings.json"), settings_content).unwrap();

            let cwd = temp_dir.path().to_str().unwrap();

            // prettier --write would normally be auto-allowed in acceptEdits
            // But with deny rule, it should be denied
            let result = check_command_with_settings("prettier --write src/", cwd, "acceptEdits");
            assert_eq!(
                get_decision(&result),
                "deny",
                "Settings deny should override acceptEdits for prettier"
            );
        }

        /// Test that without deny rules, acceptEdits still works normally
        #[test]
        fn test_accept_edits_works_without_deny_rules() {
            use std::fs;
            use tempfile::TempDir;

            let temp_dir = TempDir::new().unwrap();
            let claude_dir = temp_dir.path().join(".claude");
            fs::create_dir(&claude_dir).unwrap();

            // Settings with only allow rules (no deny)
            let settings_content = r#"{
                "permissions": {
                    "allow": ["Bash(git:*)"]
                }
            }"#;
            fs::write(claude_dir.join("settings.json"), settings_content).unwrap();

            let cwd = temp_dir.path().to_str().unwrap();

            // sd should be auto-allowed in acceptEdits mode (no deny rule)
            let result = check_command_with_settings("sd 'old' 'new' file.txt", cwd, "acceptEdits");
            assert_eq!(
                get_decision(&result),
                "allow",
                "acceptEdits should work when no deny rule matches"
            );
            assert!(
                get_reason(&result).contains("acceptEdits"),
                "Should be auto-allowed by acceptEdits"
            );
        }
    }

    /// Tests for targets_sensitive_path function.
    /// Verifies that system paths and security-critical files are blocked,
    /// while regular user dotfiles are allowed.
    mod sensitive_paths {
        use super::*;
        use crate::models::CommandInfo;

        fn cmd(program: &str, args: &[&str]) -> CommandInfo {
            CommandInfo {
                program: program.to_string(),
                args: args.iter().map(|s| s.to_string()).collect(),
                raw: format!(
                    "{} {}",
                    program,
                    args.iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            }
        }

        // === System paths should always be blocked ===

        #[test]
        fn test_etc_passwd_blocked() {
            assert!(
                targets_sensitive_path(&cmd("sd", &["old", "new", "/etc/passwd"])),
                "/etc/passwd should be blocked"
            );
        }

        #[test]
        fn test_etc_config_blocked() {
            assert!(
                targets_sensitive_path(&cmd("yq", &["-i", ".key = val", "/etc/config.yaml"])),
                "/etc/config.yaml should be blocked"
            );
        }

        #[test]
        fn test_usr_local_blocked() {
            assert!(
                targets_sensitive_path(&cmd("sd", &["old", "new", "/usr/local/bin/script"])),
                "/usr/local paths should be blocked"
            );
        }

        #[test]
        fn test_var_log_blocked() {
            assert!(
                targets_sensitive_path(&cmd("sd", &["old", "new", "/var/log/app.log"])),
                "/var/log paths should be blocked"
            );
        }

        // === Security-critical user files should be blocked ===

        #[test]
        fn test_ssh_id_rsa_blocked() {
            assert!(
                targets_sensitive_path(&cmd("sd", &["old", "new", "~/.ssh/id_rsa"])),
                "~/.ssh/id_rsa should be blocked"
            );
        }

        #[test]
        fn test_ssh_config_blocked() {
            assert!(
                targets_sensitive_path(&cmd("sd", &["old", "new", "~/.ssh/config"])),
                "~/.ssh/config should be blocked"
            );
        }

        #[test]
        fn test_gnupg_blocked() {
            assert!(
                targets_sensitive_path(&cmd("sd", &["old", "new", "~/.gnupg/gpg.conf"])),
                "~/.gnupg should be blocked"
            );
        }

        #[test]
        fn test_aws_credentials_blocked() {
            assert!(
                targets_sensitive_path(&cmd("sd", &["old", "new", "~/.aws/credentials"])),
                "~/.aws/credentials should be blocked"
            );
        }

        #[test]
        fn test_kube_config_blocked() {
            assert!(
                targets_sensitive_path(&cmd("sd", &["old", "new", "~/.kube/config"])),
                "~/.kube/config should be blocked"
            );
        }

        #[test]
        fn test_docker_config_blocked() {
            assert!(
                targets_sensitive_path(&cmd("sd", &["old", "new", "~/.docker/config.json"])),
                "~/.docker/config.json should be blocked"
            );
        }

        #[test]
        fn test_npmrc_blocked() {
            assert!(
                targets_sensitive_path(&cmd("sd", &["old", "new", "~/.npmrc"])),
                "~/.npmrc should be blocked (may contain tokens)"
            );
        }

        #[test]
        fn test_netrc_blocked() {
            assert!(
                targets_sensitive_path(&cmd("sd", &["old", "new", "~/.netrc"])),
                "~/.netrc should be blocked (contains credentials)"
            );
        }

        #[test]
        fn test_gh_config_blocked() {
            assert!(
                targets_sensitive_path(&cmd("sd", &["old", "new", "~/.config/gh/hosts.yml"])),
                "~/.config/gh should be blocked (GitHub tokens)"
            );
        }

        #[test]
        fn test_git_hooks_blocked() {
            assert!(
                targets_sensitive_path(&cmd("sd", &["old", "new", ".git/hooks/pre-commit"])),
                ".git/hooks should be blocked (code execution)"
            );
        }

        // === Regular user dotfiles should be ALLOWED ===

        #[test]
        fn test_bashrc_allowed() {
            assert!(
                !targets_sensitive_path(&cmd("sd", &["old", "new", "~/.bashrc"])),
                "~/.bashrc should be allowed for editing"
            );
        }

        #[test]
        fn test_zshrc_allowed() {
            assert!(
                !targets_sensitive_path(&cmd("sd", &["old", "new", "~/.zshrc"])),
                "~/.zshrc should be allowed for editing"
            );
        }

        #[test]
        fn test_profile_allowed() {
            assert!(
                !targets_sensitive_path(&cmd("sd", &["old", "new", "~/.profile"])),
                "~/.profile should be allowed for editing"
            );
        }

        #[test]
        fn test_bash_profile_allowed() {
            assert!(
                !targets_sensitive_path(&cmd("sd", &["old", "new", "~/.bash_profile"])),
                "~/.bash_profile should be allowed for editing"
            );
        }

        #[test]
        fn test_prettierrc_allowed() {
            assert!(
                !targets_sensitive_path(&cmd("sd", &["old", "new", "~/.prettierrc"])),
                "~/.prettierrc should be allowed for editing"
            );
        }

        #[test]
        fn test_eslintrc_allowed() {
            assert!(
                !targets_sensitive_path(&cmd("sd", &["old", "new", "~/.eslintrc"])),
                "~/.eslintrc should be allowed for editing"
            );
        }

        #[test]
        fn test_gitconfig_allowed() {
            assert!(
                !targets_sensitive_path(&cmd("sd", &["old", "new", "~/.gitconfig"])),
                "~/.gitconfig should be allowed for editing"
            );
        }

        #[test]
        fn test_config_app_yaml_allowed() {
            assert!(
                !targets_sensitive_path(&cmd("yq", &["-i", ".key = val", "~/.config/app.yaml"])),
                "~/.config/app.yaml should be allowed for editing"
            );
        }

        #[test]
        fn test_config_nvim_allowed() {
            assert!(
                !targets_sensitive_path(&cmd("sd", &["old", "new", "~/.config/nvim/init.lua"])),
                "~/.config/nvim should be allowed for editing"
            );
        }

        #[test]
        fn test_vimrc_allowed() {
            assert!(
                !targets_sensitive_path(&cmd("sd", &["old", "new", "~/.vimrc"])),
                "~/.vimrc should be allowed for editing"
            );
        }

        // === Edge cases ===

        #[test]
        fn test_flags_skipped() {
            // Flags should not be checked as paths
            assert!(
                !targets_sensitive_path(&cmd("sd", &["-F", "old", "new", "file.txt"])),
                "Flags should be skipped when checking paths"
            );
        }

        #[test]
        fn test_lock_files_still_blocked() {
            assert!(
                targets_sensitive_path(&cmd("sd", &["old", "new", "package-lock.json"])),
                "Lock files should still be blocked"
            );
        }

        #[test]
        fn test_private_key_anywhere_blocked() {
            // id_rsa anywhere in path should be blocked
            assert!(
                targets_sensitive_path(&cmd("sd", &["old", "new", "/some/path/id_rsa"])),
                "id_rsa anywhere in path should be blocked"
            );
        }
    }

    /// Tests for symlink resolution in targets_outside_allowed_dirs.
    /// These tests use actual filesystem symlinks to verify that the function
    /// correctly resolves symlinks and rejects paths that escape via symlink.
    #[cfg(unix)]
    mod symlink_resolution {
        use super::*;
        use crate::models::CommandInfo;
        use std::os::unix::fs::symlink;
        use tempfile::TempDir;

        fn cmd(program: &str, args: &[&str]) -> CommandInfo {
            CommandInfo {
                program: program.to_string(),
                args: args.iter().map(|s| s.to_string()).collect(),
                raw: format!(
                    "{} {}",
                    program,
                    args.iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            }
        }

        /// Test that a symlink pointing outside the allowed directory is detected.
        /// Attack scenario: symlink inside project pointing to /etc
        #[test]
        fn test_symlink_escape_absolute_path_detected() {
            let temp_dir = TempDir::new().unwrap();
            let project_dir = temp_dir.path();

            // Create a symlink: project_dir/escape -> /tmp (outside project)
            let escape_link = project_dir.join("escape");
            symlink("/tmp", &escape_link).unwrap();

            let allowed = vec![project_dir.to_string_lossy().to_string()];

            // Absolute path through symlink should be detected as escaping
            let escape_path = escape_link.to_string_lossy().to_string();
            let result = targets_outside_allowed_dirs(
                &cmd("sd", &["old", "new", &format!("{}/file.txt", escape_path)]),
                &allowed,
            );
            assert!(result, "Symlink escape via absolute path should be detected");
        }

        /// Test that a relative path through a symlink is detected.
        /// Attack scenario: `sd 'old' 'new' escape/passwd` where escape -> /etc
        #[test]
        fn test_symlink_escape_relative_path_detected() {
            let temp_dir = TempDir::new().unwrap();
            let project_dir = temp_dir.path();

            // Create a symlink: project_dir/escape -> /tmp (outside project)
            let escape_link = project_dir.join("escape");
            symlink("/tmp", &escape_link).unwrap();

            let allowed = vec![project_dir.to_string_lossy().to_string()];

            // Relative path through symlink should be detected as escaping
            let result = targets_outside_allowed_dirs(
                &cmd("sd", &["old", "new", "escape/file.txt"]),
                &allowed,
            );
            assert!(
                result,
                "Symlink escape via relative path should be detected"
            );
        }

        /// Test that symlinks within the allowed directory are fine.
        #[test]
        fn test_symlink_within_allowed_dir_ok() {
            let temp_dir = TempDir::new().unwrap();
            let project_dir = temp_dir.path();

            // Create subdirectory and symlink pointing to it
            let subdir = project_dir.join("subdir");
            std::fs::create_dir(&subdir).unwrap();
            let link_to_subdir = project_dir.join("link_to_subdir");
            symlink(&subdir, &link_to_subdir).unwrap();

            let allowed = vec![project_dir.to_string_lossy().to_string()];

            // Path through symlink that stays within allowed dir should be OK
            let link_path = link_to_subdir.to_string_lossy().to_string();
            let result = targets_outside_allowed_dirs(
                &cmd("sd", &["old", "new", &format!("{}/file.txt", link_path)]),
                &allowed,
            );
            assert!(
                !result,
                "Symlink within allowed directory should be OK"
            );
        }

        /// Test that relative path through symlink to /etc/passwd is detected.
        /// This is the exact attack scenario from the bug report.
        #[test]
        fn test_etc_passwd_symlink_attack() {
            let temp_dir = TempDir::new().unwrap();
            let project_dir = temp_dir.path();

            // Create symlink: project_dir/escape -> /etc
            let escape_link = project_dir.join("escape");
            symlink("/etc", &escape_link).unwrap();

            let allowed = vec![project_dir.to_string_lossy().to_string()];

            // This is the exact attack: escape/passwd looks like it's under project
            // but actually resolves to /etc/passwd
            let result = targets_outside_allowed_dirs(
                &cmd("sd", &["old", "new", "escape/passwd"]),
                &allowed,
            );
            assert!(result, "/etc/passwd via symlink escape should be detected");
        }

        /// Test that non-existent file through existing symlink is detected.
        /// The parent (symlink target) is resolved, catching the escape.
        #[test]
        fn test_nonexistent_file_through_symlink_detected() {
            let temp_dir = TempDir::new().unwrap();
            let project_dir = temp_dir.path();

            // Create symlink: project_dir/escape -> /tmp
            let escape_link = project_dir.join("escape");
            symlink("/tmp", &escape_link).unwrap();

            let allowed = vec![project_dir.to_string_lossy().to_string()];

            // Non-existent file through symlink - parent exists, so should be detected
            let result = targets_outside_allowed_dirs(
                &cmd("sd", &["old", "new", "escape/nonexistent_new_file.txt"]),
                &allowed,
            );
            assert!(
                result,
                "Non-existent file through symlink should be detected"
            );
        }

        /// Test that tilde paths with symlinks are resolved.
        #[test]
        fn test_tilde_path_with_symlink() {
            // This test only works if we can write to home directory
            // Skip if home dir is not writable
            let home = match dirs::home_dir() {
                Some(h) => h,
                None => return, // Skip test
            };

            let temp_dir = TempDir::new().unwrap();
            let project_dir = temp_dir.path();

            // Create a symlink in home pointing outside project
            let home_link = home.join(".bash_gates_test_symlink");
            if home_link.exists() {
                std::fs::remove_file(&home_link).ok();
            }

            // Create symlink: ~/.bash_gates_test_symlink -> /tmp
            if symlink("/tmp", &home_link).is_err() {
                return; // Skip if we can't create symlink in home
            }

            // Cleanup on scope exit
            struct Cleanup(std::path::PathBuf);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    std::fs::remove_file(&self.0).ok();
                }
            }
            let _cleanup = Cleanup(home_link.clone());

            let allowed = vec![project_dir.to_string_lossy().to_string()];

            // Tilde path through symlink should be detected
            let result = targets_outside_allowed_dirs(
                &cmd("sd", &["old", "new", "~/.bash_gates_test_symlink/file.txt"]),
                &allowed,
            );
            assert!(
                result,
                "Tilde path through symlink should be detected as escaping"
            );
        }

        /// Test resolve_path function directly
        #[test]
        fn test_resolve_path_with_symlink() {
            let temp_dir = TempDir::new().unwrap();
            let project_dir = temp_dir.path();

            // Create a symlink: project_dir/link -> /tmp
            let link_path = project_dir.join("link");
            symlink("/tmp", &link_path).unwrap();

            // resolve_path should follow the symlink
            let resolved = resolve_path(&link_path.to_string_lossy());
            assert_eq!(resolved, "/tmp", "resolve_path should resolve symlink");
        }

        /// Test resolve_path with non-existent file but existing parent symlink
        #[test]
        fn test_resolve_path_nonexistent_file_with_symlink_parent() {
            let temp_dir = TempDir::new().unwrap();
            let project_dir = temp_dir.path();

            // Create a symlink: project_dir/link -> /tmp
            let link_path = project_dir.join("link");
            symlink("/tmp", &link_path).unwrap();

            // Resolve non-existent file through symlink
            let file_through_link = link_path.join("newfile.txt");
            let resolved = resolve_path(&file_through_link.to_string_lossy());
            assert_eq!(
                resolved, "/tmp/newfile.txt",
                "resolve_path should resolve parent symlink for non-existent file"
            );
        }

        /// Test that resolve_path falls back to manual resolution for non-existent paths
        #[test]
        fn test_resolve_path_fallback() {
            // Path that doesn't exist at all
            let resolved = resolve_path("/nonexistent/path/to/file.txt");
            assert_eq!(
                resolved, "/nonexistent/path/to/file.txt",
                "resolve_path should fall back to manual resolution for non-existent paths"
            );
        }

        /// Test resolve_path with .. components
        #[test]
        fn test_resolve_path_with_dotdot() {
            let resolved = resolve_path("/home/user/../other/file.txt");
            assert_eq!(
                resolved, "/home/other/file.txt",
                "resolve_path should resolve .. components"
            );
        }
    }

    mod suggestions {
        use super::*;

        #[test]
        fn test_npm_install_gets_suggestions() {
            let result = check_command("npm install");
            assert_eq!(get_decision(&result), "ask");
            assert!(
                has_suggestions(&result),
                "npm install should have suggestions"
            );

            let suggestions = get_suggestions(&result).as_ref().unwrap();
            assert_eq!(
                suggestions.len(),
                3,
                "Should have session, local, and user suggestions"
            );

            // Check first suggestion is session
            if let Suggestion::AddRules {
                destination, rules, ..
            } = &suggestions[0]
            {
                assert!(matches!(destination, SuggestionDestination::Session));
                assert_eq!(rules[0].rule_content, Some("npm install:*".to_string()));
            } else {
                panic!("Expected AddRules suggestion");
            }
        }

        #[test]
        fn test_git_push_gets_suggestions() {
            let result = check_command("git push");
            assert_eq!(get_decision(&result), "ask");
            assert!(has_suggestions(&result), "git push should have suggestions");

            let suggestions = get_suggestions(&result).as_ref().unwrap();
            assert_eq!(suggestions.len(), 3);
        }

        #[test]
        fn test_rm_no_suggestions() {
            let result = check_command("rm file.txt");
            assert_eq!(get_decision(&result), "ask");
            assert!(!has_suggestions(&result), "rm should NOT have suggestions");
        }

        #[test]
        fn test_git_push_force_no_suggestions() {
            let result = check_command("git push --force");
            assert_eq!(get_decision(&result), "ask");
            assert!(
                !has_suggestions(&result),
                "git push --force should NOT have suggestions"
            );
        }

        #[test]
        fn test_make_no_user_settings() {
            let result = check_command("make deploy");
            assert_eq!(get_decision(&result), "ask");
            assert!(has_suggestions(&result), "make should have suggestions");

            let suggestions = get_suggestions(&result).as_ref().unwrap();
            assert_eq!(
                suggestions.len(),
                2,
                "make should only have session and local (no user)"
            );

            // Verify no userSettings
            for suggestion in suggestions {
                if let Suggestion::AddRules { destination, .. } = suggestion {
                    assert!(!matches!(destination, SuggestionDestination::UserSettings));
                }
            }
        }

        #[test]
        fn test_compound_command_combines_suggestions() {
            let result = check_command("npm install && git push");
            assert_eq!(get_decision(&result), "ask");
            assert!(has_suggestions(&result));

            let suggestions = get_suggestions(&result).as_ref().unwrap();
            // Should have 3 suggestions (session, local, user) with 2 rules each
            if let Suggestion::AddRules { rules, .. } = &suggestions[0] {
                assert_eq!(rules.len(), 2, "Should combine rules from both commands");
            }
        }

        #[test]
        fn test_allowed_command_no_suggestions() {
            let result = check_command("git status");
            assert_eq!(get_decision(&result), "allow");
            assert!(
                !has_suggestions(&result),
                "allowed commands don't need suggestions"
            );
        }

        #[test]
        fn test_blocked_command_no_suggestions() {
            let result = check_command("rm -rf /");
            assert_eq!(get_decision(&result), "deny");
            assert!(
                !has_suggestions(&result),
                "blocked commands don't need suggestions"
            );
        }

        #[test]
        fn test_rule_pattern_strips_path() {
            let cmd = CommandInfo {
                raw: "/usr/bin/npm install".to_string(),
                program: "/usr/bin/npm".to_string(),
                args: vec!["install".to_string()],
            };
            let pattern = build_rule_pattern(&cmd);
            assert_eq!(pattern, "npm install:*");
        }

        #[test]
        fn test_rule_pattern_handles_flags() {
            let cmd = CommandInfo {
                raw: "npm -g install".to_string(),
                program: "npm".to_string(),
                args: vec!["-g".to_string(), "install".to_string()],
            };
            let pattern = build_rule_pattern(&cmd);
            // Skips leading flags to find actual subcommand
            assert_eq!(pattern, "npm install:*");
        }

        #[test]
        fn test_rule_pattern_all_flags() {
            let cmd = CommandInfo {
                raw: "npm -g -v".to_string(),
                program: "npm".to_string(),
                args: vec!["-g".to_string(), "-v".to_string()],
            };
            let pattern = build_rule_pattern(&cmd);
            // All flags means generic pattern
            assert_eq!(pattern, "npm:*");
        }

        #[test]
        fn test_kubectl_f_gets_suggestions() {
            // -f means "file" for kubectl, not "force"
            let result = check_command("kubectl apply -f deployment.yaml");
            assert_eq!(get_decision(&result), "ask");
            assert!(
                has_suggestions(&result),
                "kubectl -f should have suggestions"
            );
        }

        #[test]
        fn test_helm_f_gets_suggestions() {
            // -f means "values file" for helm, not "force"
            let result = check_command("helm install release chart -f values.yaml");
            assert_eq!(get_decision(&result), "ask");
            assert!(has_suggestions(&result), "helm -f should have suggestions");
        }

        #[test]
        fn test_git_f_no_suggestions() {
            // -f means "force" for git
            let result = check_command("git checkout -f branch");
            assert_eq!(get_decision(&result), "ask");
            assert!(
                !has_suggestions(&result),
                "git -f should NOT have suggestions"
            );
        }

        #[test]
        fn test_git_force_with_lease_gets_suggestions() {
            // --force-with-lease is a SAFETY mechanism, should get suggestions
            let result = check_command("git push --force-with-lease");
            assert_eq!(get_decision(&result), "ask");
            assert!(
                has_suggestions(&result),
                "git --force-with-lease should have suggestions (it's safer than --force)"
            );
        }

        #[test]
        fn test_git_force_delete_no_suggestions() {
            // -D means force delete without merge check
            let result = check_command("git branch -D feature");
            assert_eq!(get_decision(&result), "ask");
            assert!(
                !has_suggestions(&result),
                "git -D should NOT have suggestions"
            );
        }

        #[test]
        fn test_combined_rf_variants_no_suggestions() {
            // Various -rf combinations should block suggestions
            for cmd in [
                "rm -rf /tmp/foo",
                "rm -rfv /tmp/foo",
                "rm -Rf /tmp/foo",
                "rm -fR /tmp/foo",
                "rm -rfi /tmp/foo",
            ] {
                let result = check_command(cmd);
                assert!(
                    !has_suggestions(&result),
                    "{cmd} should NOT have suggestions"
                );
            }
        }

        #[test]
        fn test_two_level_subcommand_patterns() {
            // gh pr create should generate "gh pr create:*" not "gh pr:*"
            let cmd = CommandInfo {
                raw: "gh pr create".to_string(),
                program: "gh".to_string(),
                args: vec!["pr".to_string(), "create".to_string()],
            };
            let pattern = build_rule_pattern(&cmd);
            assert_eq!(pattern, "gh pr create:*");

            // aws s3 cp should generate "aws s3 cp:*"
            let cmd = CommandInfo {
                raw: "aws s3 cp file s3://bucket/".to_string(),
                program: "aws".to_string(),
                args: vec![
                    "s3".to_string(),
                    "cp".to_string(),
                    "file".to_string(),
                    "s3://bucket/".to_string(),
                ],
            };
            let pattern = build_rule_pattern(&cmd);
            assert_eq!(pattern, "aws s3 cp:*");

            // kubectl get pods should generate "kubectl get pods:*"
            let cmd = CommandInfo {
                raw: "kubectl get pods".to_string(),
                program: "kubectl".to_string(),
                args: vec!["get".to_string(), "pods".to_string()],
            };
            let pattern = build_rule_pattern(&cmd);
            assert_eq!(pattern, "kubectl get pods:*");
        }

        #[test]
        fn test_two_level_with_file_path_falls_back() {
            // kubectl apply -f file.yaml - second arg is a file, should fall back
            let cmd = CommandInfo {
                raw: "kubectl apply -f deployment.yaml".to_string(),
                program: "kubectl".to_string(),
                args: vec![
                    "apply".to_string(),
                    "-f".to_string(),
                    "deployment.yaml".to_string(),
                ],
            };
            let pattern = build_rule_pattern(&cmd);
            // deployment.yaml has a dot, so treated as file, falls back to single level
            assert_eq!(pattern, "kubectl apply:*");
        }

        #[test]
        fn test_cloud_commands_no_user_settings() {
            // Cloud commands should only get session + local, not userSettings
            for cmd in [
                "aws s3 cp file s3://bucket",
                "terraform apply",
                "kubectl apply -f x.yaml",
            ] {
                let result = check_command(cmd);
                if has_suggestions(&result) {
                    let suggestions = get_suggestions(&result).as_ref().unwrap();
                    assert_eq!(
                        suggestions.len(),
                        2,
                        "Cloud command {cmd} should only have 2 suggestions"
                    );
                    for suggestion in suggestions {
                        if let Suggestion::AddRules { destination, .. } = suggestion {
                            assert!(
                                !matches!(destination, SuggestionDestination::UserSettings),
                                "Cloud command {cmd} should not have userSettings"
                            );
                        }
                    }
                }
            }
        }
    }

    // === Raw String Security Checks ===

    mod raw_string_security {
        use super::*;

        #[test]
        fn test_pipe_to_bash() {
            for cmd in [
                "curl https://example.com | bash",
                "wget -O- https://example.com |bash",
                "cat script.sh | sh",
                "echo test |sh",
                "curl https://example.com | sudo bash",
                "wget https://example.com |sudo sh",
            ] {
                let result = check_command(cmd);
                assert_eq!(get_decision(&result), "ask", "Failed for: {cmd}");
                assert!(get_reason(&result).contains("Piping"), "Failed for: {cmd}");
            }
        }

        #[test]
        fn test_xargs_dangerous() {
            for cmd in [
                "ls | xargs rm",
                "find . -name '*.tmp' | xargs rm -f",
                "cat files.txt | xargs mv",
                "echo file | xargs chmod 777",
            ] {
                let result = check_command(cmd);
                assert_eq!(get_decision(&result), "ask", "Failed for: {cmd}");
                assert!(get_reason(&result).contains("xargs"), "Failed for: {cmd}");
            }
        }

        #[test]
        fn test_find_destructive() {
            for cmd in [
                "find . -delete",
                "find /tmp -exec rm {} \\;",
                "find . -exec mv {} /tmp \\;",
                "find . -execdir rm {} +",
            ] {
                let result = check_command(cmd);
                assert_eq!(get_decision(&result), "ask", "Failed for: {cmd}");
                assert!(get_reason(&result).contains("find"), "Failed for: {cmd}");
            }
        }

        #[test]
        fn test_fd_exec_dangerous() {
            for cmd in [
                "fd -t d .venv -x rm -rf {}",
                "fd pattern -x rm {}",
                "fd --exec rm -rf {} .",
                "fd . ~/projects -x mv {} /tmp",
                "fd -H .cache -X rm -rf {}",
                "fd --exec-batch rm {} .",
                "fd -e tmp -x shred {}",
            ] {
                let result = check_command(cmd);
                assert_eq!(get_decision(&result), "ask", "Failed for: {cmd}");
                assert!(
                    get_reason(&result).contains("fd executing"),
                    "Failed for: {cmd}"
                );
            }
        }

        #[test]
        fn test_fd_safe_operations() {
            // These should NOT trigger the fd exec check
            // They'll be handled by gates (likely allowed as safe fd operations)
            for cmd in [
                "fd -t f pattern",
                "fd -e rs . src/",
                "fd -H .gitignore",
                "fd --type file .",
            ] {
                let result = check_command(cmd);
                // These should not be caught by the raw string check
                // (they'll pass through to gates)
                assert!(
                    !get_reason(&result).contains("fd executing"),
                    "False positive for: {cmd}"
                );
            }
        }

        #[test]
        fn test_command_substitution_dangerous() {
            for cmd in [
                "echo $(rm file.txt)",
                "VAR=$(rm -rf /tmp/test)",
                "echo `rm file.txt`",
                "result=`mv old new`",
            ] {
                let result = check_command(cmd);
                assert_eq!(get_decision(&result), "ask", "Failed for: {cmd}");
            }
        }

        #[test]
        fn test_leading_semicolon() {
            let result = check_command(";rm -rf /");
            assert_eq!(get_decision(&result), "ask");
            assert!(get_reason(&result).contains("semicolon"));
        }

        #[test]
        fn test_output_redirection() {
            for cmd in [
                "echo hello > output.txt",
                "cat file >> log.txt",
                "ls -la > files.txt",
                "command &> output.txt",
            ] {
                let result = check_command(cmd);
                assert_eq!(get_decision(&result), "ask", "Failed for: {cmd}");
                assert!(
                    get_reason(&result).contains("redirection"),
                    "Failed for: {cmd}"
                );
            }
        }

        #[test]
        fn test_dev_null_redirection_allowed() {
            // Redirecting to /dev/null is just discarding output, not writing
            for cmd in [
                "command > /dev/null",
                "command 2>/dev/null",
                "command > /dev/null 2>&1",
                "command &>/dev/null",
                "command &> /dev/null",
                "rg pattern 2>/dev/null",
                "grep foo 2>/dev/null | grep -v bar > /dev/null",
            ] {
                let result = check_command(cmd);
                // Should NOT be flagged for output redirection
                let reason = get_reason(&result);
                assert!(
                    !reason.contains("Output redirection"),
                    "False positive for: {cmd}"
                );
            }
        }

        #[test]
        fn test_arrow_operators_not_redirection() {
            // Arrow operators (=>, ->) in regex patterns or code should not be flagged
            for cmd in [
                r#"rg "case.*output_style|output_style.*=>" file.js"#,
                r#"rg "foo => bar" src/"#,
                r#"ast-grep -p '$X => $Y' src/"#,
                r#"grep "=>" file.ts"#,
                r#"rg "\$\w+\s*=>" src/"#,
            ] {
                let result = check_command(cmd);
                let reason = get_reason(&result);
                assert!(
                    !reason.contains("Output redirection"),
                    "False positive arrow operator for: {cmd}"
                );
            }
        }

        #[test]
        fn test_jsx_self_closing_not_redirection() {
            // JSX self-closing tags (/>) should not be flagged as redirection
            for cmd in [
                r#"sg -p '<input $$PROPS />' src/"#,
                r#"sg -p '<Input $$$PROPS />' src/"#,
                r#"ast-grep -p '<Component foo="bar" />' src/"#,
                r#"rg "<br />" src/"#,
            ] {
                let result = check_command(cmd);
                let reason = get_reason(&result);
                assert!(
                    !reason.contains("Output redirection"),
                    "False positive JSX self-closing tag for: {cmd}"
                );
            }
        }

        #[test]
        fn test_ast_grep_metavars_not_redirection() {
            // ast-grep metavariables ending with > (like $$> or $$$>) should not be flagged
            for cmd in [
                r#"ast-grep -p '<Button $$>' src/ --json 2>/dev/null"#,
                r#"sg -p '<div $$$>' src/"#,
                r#"ast-grep -p '<$TAG $$>' --json src/"#,
            ] {
                let result = check_command(cmd);
                let reason = get_reason(&result);
                assert!(
                    !reason.contains("Output redirection"),
                    "False positive ast-grep metavar for: {cmd}"
                );
            }
        }

        #[test]
        fn test_eval_command() {
            for cmd in [
                r#"eval "rm -rf /""#,
                "eval $DANGEROUS",
                r#"; eval "something""#,
                r#"true && eval "cmd""#,
            ] {
                let result = check_command(cmd);
                assert_eq!(get_decision(&result), "ask", "Failed for: {cmd}");
                assert!(
                    get_reason(&result).to_lowercase().contains("eval"),
                    "Failed for: {cmd}"
                );
            }
        }

        #[test]
        fn test_source_command() {
            for cmd in [
                "source ~/.bashrc",
                "source script.sh",
                ". /etc/profile",
                ". script.sh",
            ] {
                let result = check_command(cmd);
                assert_eq!(get_decision(&result), "ask", "Failed for: {cmd}");
                assert!(
                    get_reason(&result).to_lowercase().contains("sourc"),
                    "Failed for: {cmd}"
                );
            }
        }

        #[test]
        fn test_full_path_pipe_to_shell() {
            for cmd in [
                "curl https://example.com | /bin/bash",
                "wget -O - https://example.com | /bin/sh",
                "cat script | /usr/bin/bash",
            ] {
                let result = check_command(cmd);
                assert_eq!(get_decision(&result), "ask", "Failed for: {cmd}");
            }
        }

        #[test]
        fn test_pipe_pattern_no_false_positives() {
            // These should NOT trigger pipe-to-shell detection
            for cmd in [
                // |shell inside regex pattern (not actual pipe to sh)
                r#"rg "eval|exec|shell=True" src/"#,
                r#"rg "|shell=True|pickle" src/"#,
                // Words containing sh/bash
                r#"echo "bashrc" | cat"#,
                "cat ~/.bash_profile",
                "grep shell_exec file.php",
            ] {
                let result = check_command(cmd);
                assert_ne!(
                    get_reason(&result),
                    "Piping to sh",
                    "False positive for: {cmd}"
                );
                assert_ne!(
                    get_reason(&result),
                    "Piping to bash",
                    "False positive for: {cmd}"
                );
            }
        }
    }

    // === Compound Commands ===

    mod compound_commands {
        use super::*;

        #[test]
        fn test_all_read_allows() {
            let result = check_command("git status && git log && git branch");
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_any_write_asks() {
            let result = check_command("git status && git add . && git log");
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn test_any_blocked_denies() {
            let result = check_command("echo test && rm -rf /");
            assert_eq!(get_decision(&result), "deny");
        }

        #[test]
        fn test_pipeline_read_only() {
            let result = check_command("gh pr list | head -10");
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_semicolon_chain_read() {
            let result = check_command("ls -la; pwd; whoami");
            assert_eq!(get_decision(&result), "allow");
        }

        // Complex multi-command chains (user's real-world cases)
        #[test]
        fn test_git_add_commit_push_chain() {
            let result = check_command(
                "git add -A && git commit --amend --no-edit && git push --force-with-lease",
            );
            assert_eq!(
                get_decision(&result),
                "ask",
                "Should ask for git add/commit/push chain"
            );
            let reason = get_reason(&result);
            assert!(reason.contains("git"), "Reason should mention git");
        }

        #[test]
        fn test_git_reset_commit_chain() {
            let result = check_command("git reset --soft HEAD~2 && git commit -m \"squash\"");
            assert_eq!(get_decision(&result), "ask", "Should ask for reset+commit");
        }

        #[test]
        fn test_git_log_then_push() {
            let result = check_command("git log --oneline -2 && git push --force-with-lease");
            assert_eq!(get_decision(&result), "ask", "Should ask due to force push");
        }

        // || operator tests
        #[test]
        fn test_or_chain_all_read() {
            let result = check_command("git status || git log || pwd");
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_or_chain_with_write() {
            let result = check_command("git pull || git fetch && git merge");
            assert_eq!(get_decision(&result), "ask");
        }

        // Mixed operators
        #[test]
        fn test_mixed_and_or() {
            let result = check_command("git fetch && git status || git pull");
            assert_eq!(get_decision(&result), "ask", "pull should trigger ask");
        }

        // Semicolon with writes
        #[test]
        fn test_semicolon_with_writes() {
            let result = check_command("npm install; npm run build; npm test");
            assert_eq!(get_decision(&result), "ask", "install should trigger ask");
        }

        // Multiple risky operations
        #[test]
        fn test_multiple_risky_ops() {
            let result = check_command("rm -rf node_modules && npm install && npm run build");
            assert_eq!(get_decision(&result), "ask");
            let reason = get_reason(&result);
            // Should mention multiple operations
            assert!(
                reason.contains("rm") || reason.contains("npm"),
                "Should mention operations"
            );
        }

        // Pipeline with write at end
        #[test]
        fn test_pipeline_with_write() {
            let result = check_command("cat file.txt | grep pattern | tee output.txt");
            // tee writes to file, so it should ask for permission
            assert_eq!(get_decision(&result), "ask");
        }

        // Block wins over ask
        #[test]
        fn test_block_wins_in_chain() {
            let result = check_command("npm install && rm -rf / && git push");
            assert_eq!(get_decision(&result), "deny", "Block should win");
        }

        // cd before command (common pattern)
        #[test]
        fn test_cd_then_command() {
            let result = check_command("cd /tmp && git clone https://github.com/test/repo");
            assert_eq!(get_decision(&result), "ask", "clone should trigger ask");
        }

        // echo with dangerous-looking content (should allow - it's just echo)
        #[test]
        fn test_echo_safe() {
            let result = check_command("echo 'rm -rf /' && pwd");
            assert_eq!(
                get_decision(&result),
                "allow",
                "echo of dangerous text is safe"
            );
        }
    }

    // === Priority Order ===

    mod priority_order {
        use super::*;

        #[test]
        fn test_block_wins_over_ask() {
            let result = check_command("npm install && rm -rf /");
            assert_eq!(get_decision(&result), "deny");
        }

        #[test]
        fn test_ask_wins_over_allow() {
            let result = check_command("git status && rm file.txt");
            assert_eq!(get_decision(&result), "ask");
        }
    }

    // === Empty and Invalid ===

    mod empty_and_invalid {
        use super::*;

        #[test]
        fn test_empty_string_approves() {
            let result = check_command("");
            assert_eq!(result.decision.as_deref(), Some("approve"));
        }

        #[test]
        fn test_whitespace_only_approves() {
            let result = check_command("   ");
            assert_eq!(result.decision.as_deref(), Some("approve"));
        }

        #[test]
        fn test_unknown_command_asks() {
            let result = check_command("someunknowncommand --flag");
            assert_eq!(
                get_decision(&result),
                "ask",
                "Unknown commands should ask for approval"
            );
        }
    }

    // === Integration ===

    #[test]
    fn test_git_status_allows() {
        let result = check_command("git status");
        assert_eq!(get_decision(&result), "allow");
    }

    #[test]
    fn test_rm_rf_root_blocks() {
        let result = check_command("rm -rf /");
        assert_eq!(get_decision(&result), "deny");
    }

    #[test]
    fn test_echo_quoted_command_allows() {
        let result = check_command(r#"echo "gh pr create""#);
        assert_eq!(get_decision(&result), "allow");
    }

    // === Mise Task Expansion ===

    mod mise_tasks {
        use super::*;
        use crate::mise::{extract_task_commands, parse_mise_invocation, parse_mise_toml_str};

        #[test]
        fn test_parse_mise_run_task() {
            assert_eq!(
                parse_mise_invocation("mise run test"),
                Some("test".to_string())
            );
            assert_eq!(
                parse_mise_invocation("mise run lint:fix"),
                Some("lint:fix".to_string())
            );
        }

        #[test]
        fn test_parse_mise_shorthand() {
            assert_eq!(
                parse_mise_invocation("mise build"),
                Some("build".to_string())
            );
            assert_eq!(
                parse_mise_invocation("mise dev:frontend"),
                Some("dev:frontend".to_string())
            );
        }

        #[test]
        fn test_parse_mise_subcommands_not_tasks() {
            // These are mise built-in subcommands, not tasks
            assert_eq!(parse_mise_invocation("mise install"), None);
            assert_eq!(parse_mise_invocation("mise use node@20"), None);
            assert_eq!(parse_mise_invocation("mise ls"), None);
            assert_eq!(parse_mise_invocation("mise exec -- node"), None);
        }

        #[test]
        fn test_extract_safe_task_commands() {
            let toml = r#"
[tasks.status]
run = "git status"
"#;
            let config = parse_mise_toml_str(toml).unwrap();
            let commands = extract_task_commands(&config, "status");
            assert_eq!(commands, vec!["git status"]);

            // The underlying command is safe
            let result = check_command(&commands[0]);
            assert_eq!(get_decision(&result), "allow");
        }

        #[test]
        fn test_extract_risky_task_commands() {
            let toml = r#"
[tasks.deploy]
run = "npm publish"
"#;
            let config = parse_mise_toml_str(toml).unwrap();
            let commands = extract_task_commands(&config, "deploy");

            // The underlying command requires approval
            let result = check_command(&commands[0]);
            assert_eq!(get_decision(&result), "ask");
        }

        #[test]
        fn test_extract_blocked_task_commands() {
            let toml = r#"
[tasks.danger]
run = "rm -rf /"
"#;
            let config = parse_mise_toml_str(toml).unwrap();
            let commands = extract_task_commands(&config, "danger");

            // The underlying command is blocked
            let result = check_command(&commands[0]);
            assert_eq!(get_decision(&result), "deny");
        }

        #[test]
        fn test_task_with_depends_checks_all() {
            let toml = r#"
[tasks.build]
run = "npm run build"

[tasks.test]
run = "npm run test"
depends = ["build"]

[tasks.ci]
run = "npm publish"
depends = ["test"]
"#;
            let config = parse_mise_toml_str(toml).unwrap();
            let commands = extract_task_commands(&config, "ci");

            // Should include all commands from dependency chain
            assert_eq!(commands.len(), 3);

            // All npm commands require approval
            for cmd in &commands {
                let result = check_command(cmd);
                assert_eq!(get_decision(&result), "ask", "Failed for: {cmd}");
            }
        }

        #[test]
        fn test_task_with_dir_prepends_cd() {
            let toml = r#"
[tasks."dev:web"]
dir = "frontend"
run = "pnpm dev"
"#;
            let config = parse_mise_toml_str(toml).unwrap();
            let commands = extract_task_commands(&config, "dev:web");

            assert_eq!(commands.len(), 1);
            assert!(commands[0].starts_with("cd frontend &&"));
        }
    }
}
