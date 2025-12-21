//! Basic shell commands that are safe (read-only or display-only).
//!
//! Uses generated SAFE_COMMANDS list with custom logic for:
//! - sed/perl with -i flag (delegate to filesystem gate)
//! - xargs with safe/unsafe target commands

use crate::generated::rules::{SAFE_COMMANDS, check_conditional_allow, check_safe_command};
use crate::models::{CommandInfo, GateResult};

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
        // Find the target command (first non-flag argument)
        let target = cmd.args.iter().find(|a| !a.starts_with('-'));
        if let Some(target_cmd) = target {
            if SAFE_COMMANDS.contains(target_cmd.as_str()) {
                return GateResult::allow();
            }
        }
        // No target or unknown target - skip to let router handle
        return GateResult::skip();
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
}
