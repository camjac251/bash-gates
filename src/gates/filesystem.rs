//! Filesystem command permission gate.
//!
//! Uses declarative rules with custom logic for:
//! - Path normalization and traversal detection (security critical)
//! - tar flag parsing (combined flags like -xzf)

use crate::gates::helpers::{is_suspicious_path, normalize_path};
use crate::generated::rules::{
    check_chmod_declarative, check_cp_declarative, check_ln_declarative, check_mkdir_declarative,
    check_mv_declarative, check_perl_declarative, check_rm_declarative, check_touch_declarative,
};
use crate::models::{CommandInfo, Decision, GateResult};

/// Check filesystem commands.
pub fn check_filesystem(cmd: &CommandInfo) -> GateResult {
    let program = cmd.program.as_str();
    let args = &cmd.args;

    match program {
        "rm" => check_rm(cmd),
        "mv" => check_mv_declarative(cmd).unwrap_or_else(|| GateResult::ask("mv: Moving files")),
        "cp" => check_cp_declarative(cmd).unwrap_or_else(|| GateResult::ask("cp: Copying files")),
        "mkdir" => check_mkdir_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("mkdir: Creating directory")),
        "touch" => check_touch_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("touch: Creating/updating file")),
        "chmod" | "chown" | "chgrp" => check_chmod_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask(format!("{program}: Changing permissions"))),
        "ln" => check_ln_declarative(cmd).unwrap_or_else(|| GateResult::ask("ln: Creating link")),
        "sed" if args.iter().any(|a| a == "-i") => GateResult::ask("sed -i: In-place edit"),
        // perl can execute arbitrary code even without -i (via -e, system(), etc.)
        "perl" => check_perl_declarative(cmd)
            .unwrap_or_else(|| GateResult::ask("perl: can execute arbitrary code")),
        "tar" => check_tar(cmd),
        "unzip" => check_unzip(cmd),
        "zip" => check_zip(cmd),
        _ => GateResult::skip(),
    }
}

/// Check rm command - requires custom path normalization.
fn check_rm(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Try declarative first for blocks
    if let Some(result) = check_rm_declarative(cmd) {
        if matches!(result.decision, Decision::Block) {
            return result;
        }
    }

    // Catastrophic paths - blocked (with normalization)
    let catastrophic_paths = ["/", "/*", "~", "~/"];
    for arg in args {
        let normalized = normalize_path(arg);
        if catastrophic_paths.contains(&arg.as_str())
            || catastrophic_paths.contains(&normalized.as_str())
        {
            return GateResult::block(format!("rm '{arg}' blocked (catastrophic data loss)"));
        }

        if is_suspicious_path(arg) {
            return GateResult::block(format!("rm '{arg}' blocked (path traversal to root)"));
        }
    }

    // High-risk paths - ask with warning
    let risky_paths = ["../", "..", "*"];
    for arg in args {
        if risky_paths.contains(&arg.as_str()) {
            return GateResult::ask(format!("rm: Target '{arg}' (verify intended)"));
        }
    }

    // Recursive delete - ask
    if args
        .iter()
        .any(|a| a == "-r" || a == "-rf" || a == "-fr" || a == "--recursive")
    {
        return GateResult::ask("rm: Recursive delete");
    }

    GateResult::ask("rm: Deleting file(s)")
}

/// Check tar command - custom flag parsing for combined flags.
fn check_tar(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // List contents is safe (check combined flags like -tvf)
    if args.iter().any(|a| a == "-t" || a == "--list") {
        return GateResult::allow();
    }
    for arg in args {
        if arg.starts_with('-') && !arg.starts_with("--") && arg.contains('t') {
            return GateResult::allow();
        }
    }

    // Extraction or creation (handle combined flags like -xf, -cf, -xzf)
    for arg in args {
        if arg.starts_with('-')
            && !arg.starts_with("--")
            && (arg.contains('x') || arg.contains('c'))
        {
            return GateResult::ask("tar: Archive operation");
        }
    }

    if args.iter().any(|a| a == "--extract" || a == "--create") {
        return GateResult::ask("tar: Archive operation");
    }

    GateResult::allow()
}

/// Check unzip command.
fn check_unzip(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // List contents is safe
    if args.iter().any(|a| a == "-l") {
        return GateResult::allow();
    }

    GateResult::ask("unzip: Extracting archive")
}

/// Check zip command.
/// Note: -l flag converts line endings (CR-LF to Unix), it does NOT list contents.
/// Use zipinfo to list zip contents (which is in basics safe_commands).
fn check_zip(_cmd: &CommandInfo) -> GateResult {
    GateResult::ask("zip: Creating/modifying archive")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;

    // === rm ===

    #[test]
    fn test_rm_catastrophic_blocks() {
        for path in ["/", "/*", "~", "~/"] {
            let result = check_filesystem(&cmd("rm", &[path]));
            assert_eq!(result.decision, Decision::Block, "Failed for: {path}");
        }
    }

    #[test]
    fn test_rm_normalized_paths_block() {
        // Paths that normalize to root
        for path in ["//", "/./", "///"] {
            let result = check_filesystem(&cmd("rm", &["-rf", path]));
            assert_eq!(result.decision, Decision::Block, "Failed for: {path}");
        }
    }

    #[test]
    fn test_rm_traversal_blocks() {
        let result = check_filesystem(&cmd("rm", &["-rf", "/tmp/../"]));
        assert_eq!(result.decision, Decision::Block);
    }

    #[test]
    fn test_rm_recursive_asks() {
        let result = check_filesystem(&cmd("rm", &["-rf", "dir"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_rm_single_file_asks() {
        let result = check_filesystem(&cmd("rm", &["file.txt"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === tar ===

    #[test]
    fn test_tar_list_allows() {
        let allow_cmds = [
            &["-tf", "file.tar"][..],
            &["-tvf", "file.tar"],
            &["--list", "-f", "file.tar"],
        ];

        for args in allow_cmds {
            let result = check_filesystem(&cmd("tar", args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_tar_extract_asks() {
        let ask_cmds = [
            &["-xf", "file.tar"][..],
            &["-xzf", "file.tar.gz"],
            &["--extract", "-f", "file.tar"],
        ];

        for args in ask_cmds {
            let result = check_filesystem(&cmd("tar", args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
        }
    }

    // === unzip ===

    #[test]
    fn test_unzip_list_allows() {
        let result = check_filesystem(&cmd("unzip", &["-l", "file.zip"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_unzip_extract_asks() {
        let result = check_filesystem(&cmd("unzip", &["file.zip"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Other ===

    #[test]
    fn test_mv_asks() {
        let result = check_filesystem(&cmd("mv", &["old", "new"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_sed_inplace_asks() {
        let result = check_filesystem(&cmd("sed", &["-i", "s/old/new/", "file"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_non_filesystem_skips() {
        let result = check_filesystem(&cmd("git", &["status"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}
