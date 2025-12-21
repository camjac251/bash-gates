//! Network command permission gate (curl, wget, ssh, etc.).
//!
//! Uses declarative rules for simple cases, custom logic for complex flag parsing.

use crate::gates::helpers::{get_flag_value, has_any_flag};
use crate::generated::rules::{
    check_curl_declarative, check_nc_declarative, check_rsync_declarative, check_scp_declarative,
    check_sftp_declarative, check_ssh_declarative, check_wget_declarative,
};
use crate::models::{CommandInfo, GateResult};

/// Check network commands.
pub fn check_network(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "curl" => check_curl(cmd),
        "wget" => check_wget(cmd),
        "ssh" => check_ssh(cmd),
        "scp" => check_scp(cmd),
        "sftp" => check_sftp(cmd),
        "rsync" => check_rsync(cmd),
        "nc" | "ncat" | "netcat" => check_netcat(cmd),
        "http" | "https" | "xh" => check_httpie(cmd),
        _ => GateResult::skip(),
    }
}

/// Check curl command - complex flag parsing for HTTP methods and data.
fn check_curl(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Version/help - try declarative
    if has_any_flag(args, &["--version", "-h", "--help"]) {
        return check_curl_declarative(cmd).unwrap_or_else(GateResult::allow);
    }

    // HEAD requests are always safe
    if has_any_flag(args, &["-I", "--head"]) {
        return GateResult::allow();
    }

    // Get HTTP method (defaults to GET)
    let method = get_flag_value(args, &["-X", "--request"]).unwrap_or("GET");

    // Data flags imply mutation
    let data_flags = [
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-urlencode",
        "-F",
        "--form",
        "-T",
        "--upload-file",
        "--json",
    ];
    let has_data = has_any_flag(args, &data_flags);

    if has_data {
        return GateResult::ask(format!("curl: {} with data", method.to_uppercase()));
    }

    // Non-GET methods
    let method_upper = method.to_uppercase();
    if matches!(method_upper.as_str(), "POST" | "PUT" | "DELETE" | "PATCH") {
        return GateResult::ask(format!("curl: {method_upper} request"));
    }

    // Downloading to file
    if has_any_flag(args, &["-o", "--output", "-O", "--remote-name"]) {
        return GateResult::ask("curl: Downloading file");
    }

    // Simple GET - allow
    GateResult::allow()
}

/// Check wget command.
fn check_wget(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Version/help - try declarative
    if args
        .iter()
        .any(|a| a == "--version" || a == "-h" || a == "--help")
    {
        return check_wget_declarative(cmd).unwrap_or_else(GateResult::allow);
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

/// Check ssh command.
fn check_ssh(cmd: &CommandInfo) -> GateResult {
    check_ssh_declarative(cmd).unwrap_or_else(|| GateResult::ask("ssh: Remote connection"))
}

/// Check scp command.
fn check_scp(cmd: &CommandInfo) -> GateResult {
    check_scp_declarative(cmd).unwrap_or_else(|| GateResult::ask("scp: File transfer"))
}

/// Check sftp command.
fn check_sftp(cmd: &CommandInfo) -> GateResult {
    check_sftp_declarative(cmd).unwrap_or_else(|| GateResult::ask("sftp: File transfer"))
}

/// Check rsync command.
fn check_rsync(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Dry-run is safe
    if args.iter().any(|a| a == "-n" || a == "--dry-run") {
        return GateResult::allow();
    }

    // Use declarative for version/help
    if let Some(result) = check_rsync_declarative(cmd) {
        if matches!(result.decision, crate::models::Decision::Allow) {
            return result;
        }
    }

    GateResult::ask("rsync: File sync")
}

/// Check netcat commands.
fn check_netcat(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Execute mode - blocked (reverse shell pattern)
    if args.iter().any(|a| a == "-e") {
        return GateResult::block("Netcat -e blocked (reverse shell risk)");
    }

    // Use declarative for blocks
    if let Some(result) = check_nc_declarative(cmd) {
        if matches!(result.decision, crate::models::Decision::Block) {
            return result;
        }
    }

    // Listen mode - ask
    if args.iter().any(|a| a == "-l") {
        return GateResult::ask("netcat: Listen mode (opens port)");
    }

    // Regular connection - ask
    GateResult::ask("netcat: Network connection")
}

/// Check HTTPie-style clients (http, https, xh).
fn check_httpie(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::ask("httpie: No URL specified");
    }

    // Check for non-GET methods
    let methods = ["POST", "PUT", "DELETE", "PATCH"];
    if args
        .iter()
        .any(|a| methods.contains(&a.to_uppercase().as_str()))
    {
        return GateResult::ask("httpie: Mutating request");
    }

    // Check for data (key=value or key:=value)
    if args.iter().any(|a| a.contains('=')) {
        return GateResult::ask("httpie: Request with data");
    }

    // Check for download
    if args.iter().any(|a| a == "-d" || a == "--download") {
        return GateResult::ask("httpie: Downloading file");
    }

    // Simple GET - allow
    GateResult::allow()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd as make_cmd;
    use crate::models::Decision;

    fn curl(args: &[&str]) -> CommandInfo {
        make_cmd("curl", args)
    }

    fn wget(args: &[&str]) -> CommandInfo {
        make_cmd("wget", args)
    }

    fn rsync(args: &[&str]) -> CommandInfo {
        make_cmd("rsync", args)
    }

    fn nc(args: &[&str]) -> CommandInfo {
        make_cmd("nc", args)
    }

    // === curl ===

    #[test]
    fn test_curl_get_allows() {
        let allow_cmds = [
            &["https://example.com"][..],
            &["-I", "https://example.com"],
            &["--head", "https://example.com"],
            &["--version"],
        ];

        for args in allow_cmds {
            let result = check_network(&curl(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_curl_mutating_asks() {
        let ask_cmds = [
            &["-X", "POST", "https://example.com"][..],
            &["-X", "PUT", "https://example.com"],
            &["-XDELETE", "https://example.com"],
            &["-d", "data", "https://example.com"],
            &["--json", "{}", "https://example.com"],
            &["-o", "file", "https://example.com"],
            &["-O", "https://example.com/file"],
        ];

        for args in ask_cmds {
            let result = check_network(&curl(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
        }
    }

    // === wget ===

    #[test]
    fn test_wget_spider_allows() {
        let result = check_network(&wget(&["--spider", "https://example.com"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_wget_download_asks() {
        let ask_cmds = [
            &["https://example.com/file"][..],
            &["-O", "file", "https://example.com"],
            &["-r", "https://example.com"],
            &["-m", "https://example.com"],
        ];

        for args in ask_cmds {
            let result = check_network(&wget(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
        }
    }

    // === rsync ===

    #[test]
    fn test_rsync_dry_run_allows() {
        let result = check_network(&rsync(&["-n", "src/", "dst/"]));
        assert_eq!(result.decision, Decision::Allow);

        let result = check_network(&rsync(&["--dry-run", "src/", "dst/"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_rsync_sync_asks() {
        let result = check_network(&rsync(&["-av", "src/", "dst/"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === netcat ===

    #[test]
    fn test_netcat_execute_blocked() {
        let result = check_network(&nc(&["-e", "/bin/bash", "host", "1234"]));
        assert_eq!(result.decision, Decision::Block);
    }

    #[test]
    fn test_netcat_listen_asks() {
        let result = check_network(&nc(&["-l", "1234"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_netcat_connect_asks() {
        let result = check_network(&nc(&["host", "1234"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Non-network ===

    #[test]
    fn test_non_network_skips() {
        let result = check_network(&make_cmd("git", &["status"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}
