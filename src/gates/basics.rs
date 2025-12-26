//! Basic shell commands that are safe (read-only or display-only).
//!
//! Uses generated SAFE_COMMANDS list with custom logic for:
//! - sed/perl with -i flag (delegate to filesystem gate)
//! - xargs with safe/unsafe target commands
//! - xargs sh -c 'script' where script contains only safe commands

use crate::generated::rules::{SAFE_COMMANDS, check_conditional_allow, check_safe_command};
use crate::models::{CommandInfo, Decision, GateResult};
use crate::parser::extract_commands;
use crate::router::check_single_command;

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

    // Case 1: Direct safe command (xargs cat, xargs rg, etc.)
    if SAFE_COMMANDS.contains(target_cmd.as_str()) {
        return GateResult::allow();
    }

    // Case 2: Shell with -c (xargs sh -c 'script')
    let shells = ["sh", "bash", "zsh", "/bin/sh", "/bin/bash", "/bin/zsh"];
    if shells.contains(&target_cmd.as_str()) {
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

/// Commands that are safe only with certain conditions
pub fn check_basics(cmd: &CommandInfo) -> GateResult {
    let program = cmd.program.as_str();

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
            "echo", "cat", "ls", "grep", "ps", "whoami", "date", "base64", "xxd",
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

    #[test]
    fn test_xargs_bash_c_also_works() {
        // bash -c should work the same as sh -c
        let result = check_basics(&cmd("xargs", &["-I{}", "bash", "-c", "echo hello"]));
        assert_eq!(result.decision, Decision::Allow);

        let result = check_basics(&cmd("xargs", &["-I{}", "bash", "-c", "rm -rf {}"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}
