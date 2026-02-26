//! Basic shell commands that are safe (read-only or display-only).
//!
//! Mostly declarative via rules/basics.toml which defines safe_commands list
//! and conditional_allow for sed/perl without -i flag.
//!
//! Custom handlers needed for complex validation:
//!
//! 1. `check_xargs` - xargs safety depends on the target command being safe.
//!    TOML can't express "allow if args contain a command from safe_commands".
//!    Also handles `xargs sh -c 'script'` by parsing the inner script.
//!
//! 2. `check_shell_c` - bash/sh/zsh -c 'script' requires parsing the script
//!    string and checking each command in it. TOML can't parse embedded scripts.

use crate::generated::rules::{SAFE_COMMANDS, check_conditional_allow, check_safe_command};
use crate::models::{CommandInfo, Decision, GateResult};
use crate::parser::extract_commands;
use crate::router::check_single_command;

/// Check if a shell -c command is safe by parsing and checking the inner script.
/// Handles: bash -c 'script', sh -c 'script', zsh -c 'script'
fn check_shell_c(cmd: &CommandInfo) -> Option<GateResult> {
    let args = &cmd.args;

    // Need at least -c and a script
    if args.len() < 2 {
        return None;
    }

    // Find -c flag and get the script
    let mut script: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-c" {
            if i + 1 < args.len() {
                script = Some(&args[i + 1]);
            }
            break;
        }
        i += 1;
    }

    let script = script?;

    // Parse the script and check each command
    let inner_commands = extract_commands(script);
    if inner_commands.is_empty() {
        return Some(GateResult::allow()); // Empty script is safe
    }

    // Check each command in the script
    for inner_cmd in &inner_commands {
        let result = check_single_command(inner_cmd);
        match result.decision {
            Decision::Block => {
                return Some(GateResult::block(format!(
                    "Shell script contains blocked command: {}",
                    result.reason.unwrap_or_else(|| inner_cmd.program.clone())
                )));
            }
            Decision::Ask => {
                return Some(GateResult::ask(format!(
                    "Shell script: {}",
                    result.reason.unwrap_or_else(|| inner_cmd.program.clone())
                )));
            }
            Decision::Skip => {
                // Unknown command in script
                return Some(GateResult::ask(format!(
                    "Shell script contains unknown command: {}",
                    inner_cmd.program
                )));
            }
            Decision::Allow => {
                // This command is safe, continue checking others
            }
        }
    }

    // All commands in the script are safe
    Some(GateResult::allow())
}

/// Check if xargs is running a safe command
fn check_xargs(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Find the target command (first non-flag argument)
    // xargs flags can have arguments, so we need to be careful
    let mut i = 0;
    let mut target_idx = None;

    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with('-') {
            // Flags that take an argument: -I, -L, -n, -P, -s, -E, -d
            // These consume the next argument or are combined (e.g., -I{})
            if arg == "-I"
                || arg == "-L"
                || arg == "-n"
                || arg == "-P"
                || arg == "-s"
                || arg == "-E"
                || arg == "-d"
            {
                i += 2; // Skip flag and its argument
                continue;
            }
            // Combined form like -I{} or -n1
            i += 1;
            continue;
        }
        // Found the target command
        target_idx = Some(i);
        break;
    }

    let Some(idx) = target_idx else {
        return GateResult::skip(); // No target found
    };

    let target_cmd = &args[idx];
    // Strip path prefix to handle /usr/bin/cat etc.
    let target_base = target_cmd.rsplit('/').next().unwrap_or(target_cmd);

    // Case 1: Direct safe command (xargs cat, xargs rg, etc.)
    if SAFE_COMMANDS.contains(&target_base) {
        return GateResult::allow();
    }

    // Case 2: Shell with -c (xargs sh -c 'script')
    if matches!(target_base, "sh" | "bash" | "zsh") {
        // Look for -c flag and script
        if idx + 2 < args.len() && args[idx + 1] == "-c" {
            let script = &args[idx + 2];
            return check_shell_script_safety(script);
        }
    }

    // Unknown target - skip to let router handle
    GateResult::skip()
}

/// Parse a shell script and check if all commands are safe
fn check_shell_script_safety(script: &str) -> GateResult {
    let commands = extract_commands(script);

    if commands.is_empty() {
        return GateResult::skip(); // Couldn't parse
    }

    // Check each command - all must be allowed for the script to be safe
    for cmd in &commands {
        let result = check_single_command(cmd);
        match result.decision {
            Decision::Allow => continue,
            Decision::Skip => {
                // Unknown command in script - not safe
                return GateResult::skip();
            }
            Decision::Ask | Decision::Block => {
                // Risky or dangerous command in script
                return GateResult::skip();
            }
        }
    }

    // All commands in script are safe
    GateResult::allow()
}

/// Check `command` builtin.
/// - `command -v`/`-V` (with optional `-p`): read-only lookup, always allow
/// - `command <cmd> args...`: transparent wrapper, evaluate the inner command
fn check_command_builtin(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    if args.is_empty() {
        return GateResult::allow();
    }

    let mut i = 0;
    let mut is_lookup = false;

    // Skip option flags (-p, -v, -V, or combined like -pv)
    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with('-') {
            if arg.contains('v') || arg.contains('V') {
                is_lookup = true;
            }
            i += 1;
            continue;
        }
        break;
    }

    if is_lookup {
        return GateResult::allow();
    }

    // command <cmd> args... -> evaluate the inner command through gates
    if i < args.len() {
        let inner = CommandInfo {
            program: args[i].clone(),
            args: args[i + 1..].to_vec(),
            raw: cmd.raw.clone(),
        };
        return check_single_command(&inner);
    }

    GateResult::allow()
}

/// Commands that are safe only with certain conditions
pub fn check_basics(cmd: &CommandInfo) -> GateResult {
    // Strip path prefix to handle /usr/bin/sed etc.
    let program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);

    // Shell with -c flag - parse and check the inner script
    if matches!(program, "bash" | "sh" | "zsh") {
        if let Some(result) = check_shell_c(cmd) {
            return result;
        }
        // No -c flag or couldn't parse - ask for manual review
        return GateResult::ask(format!(
            "{program}: Interactive shell or complex invocation"
        ));
    }

    // command builtin - lookup or transparent wrapper
    if program == "command" {
        return check_command_builtin(cmd);
    }

    // sed is special - safe without -i flag
    if program == "sed" {
        if cmd
            .args
            .iter()
            .any(|a| a == "-i" || a.starts_with("-i") || a.starts_with("--in-place"))
        {
            return GateResult::skip(); // Let filesystem gate handle -i
        }
        return GateResult::allow();
    }

    // Note: perl removed from special handling - even without -i it can execute
    // arbitrary code via -e, system(), etc. Handled by filesystem gate (always asks).

    // xargs with safe target command
    if program == "xargs" {
        return check_xargs(cmd);
    }

    // Try conditional allow rules (e.g., sed without -i)
    if let Some(result) = check_conditional_allow(cmd) {
        return result;
    }

    // Check if in safe commands list
    if let Some(result) = check_safe_command(cmd) {
        return result;
    }

    GateResult::skip()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;

    #[test]
    fn test_safe_commands_allow() {
        for program in [
            "echo", "cat", "ls", "grep", "ps", "whoami", "date", "base64", "xxd", "read",
        ] {
            let result = check_basics(&cmd(program, &[]));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {program}");
        }
    }

    #[test]
    fn test_sed_without_i_allows() {
        let result = check_basics(&cmd("sed", &["s/foo/bar/", "file.txt"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_sed_with_i_skips() {
        let result = check_basics(&cmd("sed", &["-i", "s/foo/bar/", "file.txt"]));
        assert_eq!(result.decision, Decision::Skip);
    }

    #[test]
    fn test_unknown_command_skips() {
        let result = check_basics(&cmd("mamba", &["env", "create"]));
        assert_eq!(result.decision, Decision::Skip);
    }

    // === bash -c / sh -c / zsh -c ===

    #[test]
    fn test_bash_c_safe_script_allows() {
        let result = check_basics(&cmd("bash", &["-c", "echo hello && ls"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bash_c_loop_allows() {
        let result = check_basics(&cmd("bash", &["-c", "for i in 1 2 3; do echo $i; done"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bash_c_unsafe_script_asks() {
        let result = check_basics(&cmd("bash", &["-c", "rm -rf /tmp/test"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.unwrap().contains("rm"));
    }

    #[test]
    fn test_sh_c_safe_allows() {
        let result = check_basics(&cmd("sh", &["-c", "git status"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_zsh_c_safe_allows() {
        let result = check_basics(&cmd("zsh", &["-c", "echo test | grep test"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_bash_interactive_asks() {
        // bash without -c should ask (interactive shell)
        let result = check_basics(&cmd("bash", &[]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_bash_c_unknown_command_asks() {
        let result = check_basics(&cmd("bash", &["-c", "some_unknown_command"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.unwrap().contains("unknown"));
    }

    #[test]
    fn test_xargs_with_safe_command_allows() {
        // xargs followed by safe commands should allow
        for (target, args) in [
            ("bat", &["bat"][..]),
            ("rg", &["rg", "pattern"][..]),
            ("cat", &["cat"][..]),
            ("grep", &["-0", "grep", "TODO"][..]), // flags before target
        ] {
            let result = check_basics(&cmd("xargs", args));
            assert_eq!(
                result.decision,
                Decision::Allow,
                "xargs {} should allow",
                target
            );
        }
    }

    #[test]
    fn test_xargs_with_unsafe_command_skips() {
        // xargs followed by unknown/dangerous commands should skip
        for args in [&["rm", "-f"][..], &["mv"][..], &["unknown_cmd"][..]] {
            let result = check_basics(&cmd("xargs", args));
            assert_eq!(
                result.decision,
                Decision::Skip,
                "xargs {:?} should skip",
                args
            );
        }
    }

    #[test]
    fn test_xargs_no_target_skips() {
        // xargs with only flags (no target command) should skip
        let result = check_basics(&cmd("xargs", &["-0", "-n", "1"]));
        assert_eq!(result.decision, Decision::Skip);
    }

    #[test]
    fn test_xargs_sh_c_with_safe_commands_allows() {
        // xargs sh -c with only safe commands should allow
        for script in [
            "echo hello",
            "cat file && head -10",
            "echo {} && rg pattern {} | head -30",
            "bat -n {} 2>/dev/null",
        ] {
            let result = check_basics(&cmd("xargs", &["-I{}", "sh", "-c", script]));
            assert_eq!(
                result.decision,
                Decision::Allow,
                "xargs sh -c '{}' should allow",
                script
            );
        }
    }

    #[test]
    fn test_xargs_sh_c_with_unsafe_commands_skips() {
        // xargs sh -c with risky commands should skip
        for script in ["rm -rf {}", "mv {} /tmp/", "npm install"] {
            let result = check_basics(&cmd("xargs", &["-I{}", "sh", "-c", script]));
            assert_eq!(
                result.decision,
                Decision::Skip,
                "xargs sh -c '{}' should skip",
                script
            );
        }
    }

    // === command builtin ===

    #[test]
    fn test_command_v_allows() {
        let result = check_basics(&cmd("command", &["-v", "bat"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_command_capital_v_allows() {
        let result = check_basics(&cmd("command", &["-V", "bat"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_command_pv_allows() {
        let result = check_basics(&cmd("command", &["-pv", "ls"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_command_p_v_allows() {
        let result = check_basics(&cmd("command", &["-p", "-v", "ls"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_command_bare_allows() {
        let result = check_basics(&cmd("command", &[]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_command_safe_inner_allows() {
        let result = check_basics(&cmd("command", &["ls", "-la"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_command_unsafe_inner_propagates() {
        let result = check_basics(&cmd("command", &["rm", "-rf", "/tmp/test"]));
        assert_ne!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_xargs_bash_c_also_works() {
        // bash -c should work the same as sh -c
        let result = check_basics(&cmd("xargs", &["-I{}", "bash", "-c", "echo hello"]));
        assert_eq!(result.decision, Decision::Allow);

        let result = check_basics(&cmd("xargs", &["-I{}", "bash", "-c", "rm -rf {}"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}
