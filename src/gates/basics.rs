//! Basic shell commands that are safe (read-only or display-only).

use crate::models::{CommandInfo, GateResult};

/// Safe read-only shell commands
const SAFE_COMMANDS: &[&str] = &[
    // Display/output
    "echo",
    "printf",
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "bat",
    "batcat",
    // Listing/finding
    "ls",
    "eza",
    "lsd",
    "tree",
    "find",
    "fd",
    "locate",
    "which",
    "whereis",
    "type",
    // Text processing (read-only)
    "grep",
    "rg",
    "ripgrep",
    "awk",
    "cut",
    "sort",
    "uniq",
    "wc",
    "tr",
    "tee",
    "column",
    "paste",
    "join",
    "comm",
    "diff",
    "cmp",
    "fold",
    "fmt",
    "nl",
    "rev",
    "tac",
    "expand",
    "unexpand",
    "pr",
    "split",
    "csplit",
    // File info
    "file",
    "stat",
    "du",
    "df",
    "lsof",
    "readlink",
    "realpath",
    "basename",
    "dirname",
    // Process/system info
    "ps",
    "top",
    "htop",
    "btop",
    "procs",
    "pgrep",
    "pidof",
    "uptime",
    "w",
    "who",
    "whoami",
    "id",
    "groups",
    "uname",
    "hostname",
    "hostnamectl",
    "date",
    "cal",
    "free",
    "vmstat",
    "iostat",
    "nproc",
    "lscpu",
    "lsmem",
    "lsblk",
    "lspci",
    "lsusb",
    // Network info (read-only)
    "ping",
    "traceroute",
    "tracepath",
    "mtr",
    "dig",
    "nslookup",
    "host",
    "whois",
    "ss",
    "netstat",
    "ip",
    "ifconfig",
    "route",
    "arp",
    // Archive listing (not extraction)
    "zipinfo",
    "unrar",
    // Dev tools (read-only)
    "git", // handled by git gate but fallback here
    "tokei",
    "cloc",
    "scc",
    "loc",
    "jq",
    "yq",
    "gron",
    "fx", // JSON/YAML viewers
    "hexdump",
    "xxd",
    "base64",
    "od",
    "hexyl",
    "strings",
    // Help/docs
    "man",
    "info",
    "help",
    "tldr",
    "tealdeer",
    "cheat",
    // Misc safe
    "true",
    "false",
    "yes",
    "seq",
    "expr",
    "bc",
    "dc",
    "factor",
    "sleep",
    "wait",
    "time",
    "timeout",
    "env",
    "printenv",
    "export",
    "set",
    "pwd",
    "cd",
    "pushd",
    "popd",
    "dirs",
    "alias",
    "unalias",
    "hash",
    "test",
    "[",
    "[[",
    // Rust/cargo read-only
    "rustc",
    "rustup",
    // Python read-only
    "python",
    "python3",
    "python2",
    // Node read-only
    "node",
    "deno",
];

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

    // awk/gawk/mawk - always safe (read-only by design)
    if program == "awk" || program == "gawk" || program == "mawk" || program == "nawk" {
        return GateResult::allow();
    }

    // perl without -i is safe for one-liners
    if program == "perl" {
        if cmd.args.iter().any(|a| a == "-i" || a.starts_with("-i")) {
            return GateResult::skip(); // Let filesystem gate handle
        }
        return GateResult::allow();
    }

    // xargs with safe target command
    if program == "xargs" {
        // Find the target command (first non-flag argument)
        let target = cmd.args.iter().find(|a| !a.starts_with('-'));
        if let Some(target_cmd) = target {
            if SAFE_COMMANDS.contains(&target_cmd.as_str()) {
                return GateResult::allow();
            }
        }
        // No target or unknown target - skip to let router handle
        return GateResult::skip();
    }

    // Check if in safe list
    if SAFE_COMMANDS.contains(&program) {
        return GateResult::allow();
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
