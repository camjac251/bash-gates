//! Filesystem command permission gate.

use crate::models::{CommandInfo, GateResult};

/// Check filesystem commands.
pub fn check_filesystem(cmd: &CommandInfo) -> GateResult {
    let program = cmd.program.as_str();
    let args = &cmd.args;

    match program {
        "rm" => check_rm(cmd),
        "mv" => GateResult::ask("mv: Moving files"),
        "cp" => GateResult::ask("cp: Copying files"),
        "mkdir" => GateResult::ask("mkdir: Creating directory"),
        "touch" => GateResult::ask("touch: Creating/updating file"),
        "chmod" | "chown" | "chgrp" => GateResult::ask(format!("{program}: Changing permissions")),
        "ln" => GateResult::ask("ln: Creating link"),
        "sed" if args.iter().any(|a| a == "-i") => GateResult::ask("sed -i: In-place edit"),
        "perl" if args.iter().any(|a| a == "-i") => GateResult::ask("perl -i: In-place edit"),
        "tar" => check_tar(cmd),
        "unzip" => check_unzip(cmd),
        "zip" => check_zip(cmd),
        _ => GateResult::skip(),
    }
}

/// Normalize a path for security checking.
/// Collapses multiple slashes, removes trailing slashes/dots.
fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    // Collapse multiple slashes
    let mut result: String = path.chars().fold(String::new(), |mut acc, c| {
        if c == '/' && acc.ends_with('/') {
            // Skip duplicate slash
        } else {
            acc.push(c);
        }
        acc
    });

    // Remove trailing /. sequences and trailing slashes
    loop {
        if result.ends_with("/.") {
            result.truncate(result.len() - 2);
        } else if result.len() > 1 && result.ends_with('/') {
            result.pop();
        } else {
            break;
        }
    }

    // Empty result from root path normalization should become /
    if result.is_empty() {
        return "/".to_string();
    }

    result
}

/// Check if path could traverse to root via ..
fn is_suspicious_traversal(path: &str) -> bool {
    // Any absolute path with .. could potentially reach root
    if path.starts_with('/') && path.contains("..") {
        return true;
    }
    false
}

/// Check rm command.
fn check_rm(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Catastrophic paths - blocked
    let catastrophic_paths = ["/", "/*", "~", "~/"];
    for arg in args {
        // Check both original and normalized path
        let normalized = normalize_path(arg);
        if catastrophic_paths.contains(&arg.as_str())
            || catastrophic_paths.contains(&normalized.as_str())
        {
            return GateResult::block(format!("rm '{arg}' blocked (catastrophic data loss)"));
        }

        // Check for suspicious path traversal
        if is_suspicious_traversal(arg) {
            return GateResult::block(format!("rm '{arg}' blocked (path traversal to root)"));
        }
    }

    // High-risk paths - ask with warning
    let risky_paths = ["../", "..", "*"];
    for arg in args {
        if risky_paths.contains(&arg.as_str()) {
            return GateResult::ask(format!("rm with '{arg}' (verify target)"));
        }
    }

    // Recursive delete - ask
    if args
        .iter()
        .any(|a| a == "-r" || a == "-rf" || a == "-fr" || a == "--recursive")
    {
        return GateResult::ask("rm: Recursive delete");
    }

    // Single file delete
    GateResult::ask("rm: Deleting file(s)")
}

/// Check tar command.
fn check_tar(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // List contents is safe
    if args.iter().any(|a| a == "-t" || a == "--list") {
        return GateResult::allow();
    }

    // Check for t in combined flags (e.g., -tvf)
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
fn check_zip(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // List is safe
    if args.iter().any(|a| a == "-l") {
        return GateResult::allow();
    }

    GateResult::ask("zip: Creating archive")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Decision;

    fn cmd(program: &str, args: &[&str]) -> CommandInfo {
        CommandInfo {
            raw: format!("{} {}", program, args.join(" ")),
            program: program.to_string(),
            args: args.iter().map(std::string::ToString::to_string).collect(),
            is_subshell: false,
            is_pipeline: false,
            pipeline_position: 0,
        }
    }

    // === rm ===

    mod rm {
        use super::*;

        #[test]
        fn test_catastrophic_rm_blocks() {
            for args in ["/", "/*", "~", "~/"] {
                let result = check_filesystem(&cmd("rm", &["-rf", args]));
                assert_eq!(result.decision, Decision::Block, "Failed for: {args}");
                assert!(
                    result
                        .reason
                        .as_ref()
                        .unwrap()
                        .to_lowercase()
                        .contains("catastrophic")
                );
            }
        }

        #[test]
        fn test_path_bypass_double_slash_blocks() {
            let result = check_filesystem(&cmd("rm", &["-rf", "//"]));
            assert_eq!(result.decision, Decision::Block, "// should normalize to /");
        }

        #[test]
        fn test_path_bypass_trailing_dot_blocks() {
            let result = check_filesystem(&cmd("rm", &["-rf", "/."]));
            assert_eq!(result.decision, Decision::Block, "/. should normalize to /");
        }

        #[test]
        fn test_path_bypass_trailing_slash_blocks() {
            let result = check_filesystem(&cmd("rm", &["-rf", "//./"]));
            assert_eq!(
                result.decision,
                Decision::Block,
                "//./  should normalize to /"
            );
        }

        #[test]
        fn test_path_traversal_blocks() {
            for path in ["/home/..", "/tmp/../..", "/var/log/../../.."] {
                let result = check_filesystem(&cmd("rm", &["-rf", path]));
                assert_eq!(
                    result.decision,
                    Decision::Block,
                    "Path traversal {path} should block"
                );
            }
        }

        #[test]
        fn test_risky_rm_asks() {
            for args in ["../", "..", "*"] {
                let result = check_filesystem(&cmd("rm", &[args]));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args}");
            }
        }

        #[test]
        fn test_recursive_rm_asks() {
            for args in [
                &["-rf", "node_modules"][..],
                &["-r", "build/"],
                &["--recursive", "dist"],
            ] {
                let result = check_filesystem(&cmd("rm", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(result.reason.as_ref().unwrap().contains("Recursive"));
            }
        }

        #[test]
        fn test_single_file_rm_asks() {
            let result = check_filesystem(&cmd("rm", &["file.txt"]));
            assert_eq!(result.decision, Decision::Ask);
            assert!(result.reason.as_ref().unwrap().contains("Deleting"));
        }
    }

    // === mv, cp ===

    #[test]
    fn test_mv_asks() {
        let result = check_filesystem(&cmd("mv", &["old.txt", "new.txt"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Moving"));
    }

    #[test]
    fn test_cp_asks() {
        let result = check_filesystem(&cmd("cp", &["src.txt", "dst.txt"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("Copying"));
    }

    // === Directory commands ===

    #[test]
    fn test_mkdir_asks() {
        let result = check_filesystem(&cmd("mkdir", &["new_dir"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(
            result
                .reason
                .as_ref()
                .unwrap()
                .contains("Creating directory")
        );
    }

    #[test]
    fn test_touch_asks() {
        let result = check_filesystem(&cmd("touch", &["new_file.txt"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_ln_asks() {
        let result = check_filesystem(&cmd("ln", &["-s", "target", "link"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(
            result
                .reason
                .as_ref()
                .unwrap()
                .to_lowercase()
                .contains("link")
        );
    }

    // === Permission commands ===

    #[test]
    fn test_permission_commands_ask() {
        for program in ["chmod", "chown", "chgrp"] {
            let result = check_filesystem(&cmd(program, &["755", "file.txt"]));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {program}");
            assert!(
                result
                    .reason
                    .as_ref()
                    .unwrap()
                    .to_lowercase()
                    .contains("permission")
            );
        }
    }

    // === In-place editors ===

    #[test]
    fn test_sed_inplace_asks() {
        let result = check_filesystem(&cmd("sed", &["-i", "s/old/new/g", "file.txt"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("In-place"));
    }

    #[test]
    fn test_perl_inplace_asks() {
        let result = check_filesystem(&cmd("perl", &["-i", "-pe", "s/old/new/", "file.txt"]));
        assert_eq!(result.decision, Decision::Ask);
        assert!(result.reason.as_ref().unwrap().contains("In-place"));
    }

    #[test]
    fn test_sed_no_inplace_skips() {
        // sed without -i is handled by basics gate, not filesystem
        let result = check_filesystem(&cmd("sed", &["s/old/new/g", "file.txt"]));
        assert_eq!(result.decision, Decision::Skip);
    }

    // === Archive commands ===

    mod archives {
        use super::*;

        #[test]
        fn test_tar_list_allows() {
            let result = check_filesystem(&cmd("tar", &["-tf", "archive.tar"]));
            assert_eq!(result.decision, Decision::Allow);
        }

        #[test]
        fn test_tar_extract_asks() {
            let result = check_filesystem(&cmd("tar", &["-xf", "archive.tar"]));
            assert_eq!(result.decision, Decision::Ask);
        }

        #[test]
        fn test_tar_create_asks() {
            let result = check_filesystem(&cmd("tar", &["-cf", "archive.tar", "dir/"]));
            assert_eq!(result.decision, Decision::Ask);
        }

        #[test]
        fn test_unzip_list_allows() {
            let result = check_filesystem(&cmd("unzip", &["-l", "archive.zip"]));
            assert_eq!(result.decision, Decision::Allow);
        }

        #[test]
        fn test_unzip_extract_asks() {
            let result = check_filesystem(&cmd("unzip", &["archive.zip"]));
            assert_eq!(result.decision, Decision::Ask);
        }

        #[test]
        fn test_zip_create_asks() {
            let result = check_filesystem(&cmd("zip", &["archive.zip", "file.txt"]));
            assert_eq!(result.decision, Decision::Ask);
        }
    }

    // === Non-filesystem command ===

    #[test]
    fn test_non_fs_skips() {
        let result = check_filesystem(&CommandInfo {
            raw: "git status".to_string(),
            program: "git".to_string(),
            args: vec!["status".to_string()],
            is_subshell: false,
            is_pipeline: false,
            pipeline_position: 0,
        });
        assert_eq!(result.decision, Decision::Skip);
    }
}
