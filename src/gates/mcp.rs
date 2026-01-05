//! MCP CLI (mcp-cli) permission gate.
//!
//! Handles `mcp-cli` commands for interacting with MCP (Model Context Protocol) servers.
//! Discovery commands are always allowed; `call` commands check settings.json MCP permissions.
//!
//! Commands:
//! - servers: List connected MCP servers (read-only)
//! - tools [server]: List available tools (read-only)
//! - info <server>/<tool>: Get tool information (read-only)
//! - grep <pattern>: Search tools (read-only)
//! - resources [server]: List MCP resources (read-only)
//! - read <resource>: Read MCP resource (read-only)
//! - call <server>/<tool> <args>: Invoke an MCP tool (checks settings.json)

use crate::models::{CommandInfo, GateResult};
use crate::settings::{Settings, SettingsDecision};

/// Check an mcp-cli command for permission requirements.
///
/// This is the main gate function called by the router for regular gate checks.
/// For `call` commands, it returns `ask` - the router should use `check_mcp_call`
/// for settings-aware handling.
pub fn check_mcp(cmd: &CommandInfo) -> GateResult {
    if cmd.program != "mcp-cli" {
        return GateResult::skip();
    }

    let subcmd = cmd.args.first().map(String::as_str).unwrap_or("");

    // Discovery commands are always allowed (read-only)
    if let Some(reason) = get_discovery_reason(subcmd) {
        return GateResult::allow_with_reason(reason);
    }

    // `call` command requires further checking (handled by router with settings)
    if subcmd == "call" {
        if let Some((server, tool)) = parse_call_args(&cmd.args) {
            return GateResult::ask(format!("mcp-cli: Invoking {}/{}", server, tool));
        }
        return GateResult::ask("mcp-cli: Invoking MCP tool");
    }

    // Unknown subcommand - ask for approval
    GateResult::ask(format!("mcp-cli: {}", subcmd))
}

/// Check an mcp-cli `call` command against settings.json MCP permissions.
///
/// Called by the router for mcp-cli commands with cwd context.
///
/// Returns:
/// - Allow if the MCP tool is allowed in settings.json
/// - Ask if no match or explicitly in ask list
/// - Deny if explicitly denied in settings.json
pub fn check_mcp_call(cmd: &CommandInfo, cwd: &str) -> GateResult {
    if cmd.program != "mcp-cli" {
        return GateResult::skip();
    }

    let subcmd = cmd.args.first().map(String::as_str).unwrap_or("");

    // Discovery commands are always allowed (read-only)
    if let Some(reason) = get_discovery_reason(subcmd) {
        return GateResult::allow_with_reason(reason);
    }

    // Handle `call` command
    if subcmd == "call" {
        if let Some((server, tool)) = parse_call_args(&cmd.args) {
            let settings = Settings::load(cwd);
            match settings.check_mcp_tool(&server, &tool) {
                SettingsDecision::Allow => {
                    return GateResult::allow_with_reason(format!(
                        "mcp-cli: {}/{} (allowed by settings.json)",
                        server, tool
                    ));
                }
                SettingsDecision::Deny => {
                    return GateResult::block(format!(
                        "mcp-cli: {}/{} (denied by settings.json)",
                        server, tool
                    ));
                }
                SettingsDecision::Ask => {
                    return GateResult::ask(format!(
                        "mcp-cli: {}/{} (requires approval)",
                        server, tool
                    ));
                }
                SettingsDecision::NoMatch => {
                    // No match in settings - ask for approval
                    return GateResult::ask(format!("mcp-cli: Invoking {}/{}", server, tool));
                }
            }
        }
        return GateResult::ask("mcp-cli: Invoking MCP tool (invalid format)");
    }

    // Unknown subcommand - ask for approval
    GateResult::ask(format!("mcp-cli: {}", subcmd))
}

/// Get the reason string for discovery commands.
/// Returns None if the subcommand is not a discovery command.
fn get_discovery_reason(subcmd: &str) -> Option<String> {
    match subcmd {
        "servers" => Some("mcp-cli: Listing connected servers".to_string()),
        "tools" => Some("mcp-cli: Listing available tools".to_string()),
        "info" => Some("mcp-cli: Getting tool information".to_string()),
        "grep" => Some("mcp-cli: Searching tools".to_string()),
        "resources" => Some("mcp-cli: Listing MCP resources".to_string()),
        "read" => Some("mcp-cli: Reading MCP resource".to_string()),
        "help" => Some("mcp-cli: Displaying help".to_string()),
        _ => None,
    }
}

/// Parse `call` command args to extract server and tool names.
///
/// Format: `call <server>/<tool> <json_args>`
/// Example: `call my-server/my_tool '{"param": "value"}'`
///
/// Returns (server, tool) if valid format, None otherwise.
fn parse_call_args(args: &[String]) -> Option<(String, String)> {
    // args[0] = "call", args[1] = "server/tool"
    if args.len() < 2 {
        return None;
    }

    let tool_spec = &args[1];
    let parts: Vec<&str> = tool_spec.splitn(2, '/').collect();
    if parts.len() != 2 {
        return None;
    }

    Some((parts[0].to_string(), parts[1].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;

    // === Discovery Commands ===

    #[test]
    fn test_discovery_commands_allow() {
        let discovery_cmds = [
            &["servers"][..],
            &["tools"],
            &["tools", "test-server"],
            &["info", "test-server/test_tool"],
            &["grep", "search-pattern"],
            &["resources"],
            &["resources", "docs-server"],
            &["read", "docs-server/readme"],
            &["help"],
        ];

        for args in discovery_cmds {
            let result = check_mcp(&cmd("mcp-cli", args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {:?}", args);
        }
    }

    // === Call Commands ===

    #[test]
    fn test_call_command_asks() {
        let result = check_mcp(&cmd(
            "mcp-cli",
            &["call", "test-server/test_tool", r#"{"param": "value"}"#],
        ));
        assert_eq!(result.decision, Decision::Ask);
        assert!(
            result
                .reason
                .as_ref()
                .unwrap()
                .contains("test-server/test_tool")
        );
    }

    #[test]
    fn test_call_invalid_format_asks() {
        let result = check_mcp(&cmd("mcp-cli", &["call"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    #[test]
    fn test_call_missing_tool_asks() {
        let result = check_mcp(&cmd("mcp-cli", &["call", "test-server"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Unknown Commands ===

    #[test]
    fn test_unknown_command_asks() {
        let result = check_mcp(&cmd("mcp-cli", &["unknown"]));
        assert_eq!(result.decision, Decision::Ask);
    }

    // === Non-mcp-cli Commands ===

    #[test]
    fn test_non_mcp_cli_skips() {
        let result = check_mcp(&cmd("git", &["status"]));
        assert_eq!(result.decision, Decision::Skip);
    }

    // === Parse Call Args ===

    #[test]
    fn test_parse_call_args_valid() {
        let args = vec![
            "call".to_string(),
            "test-server/test_tool".to_string(),
            r#"{"param": "value"}"#.to_string(),
        ];
        let result = parse_call_args(&args);
        assert_eq!(
            result,
            Some(("test-server".to_string(), "test_tool".to_string()))
        );
    }

    #[test]
    fn test_parse_call_args_no_tool() {
        let args = vec!["call".to_string(), "test-server".to_string()];
        let result = parse_call_args(&args);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_call_args_empty() {
        let args = vec!["call".to_string()];
        let result = parse_call_args(&args);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_call_args_with_slash_in_tool() {
        // server/tool/extra should parse as server, tool/extra
        let args = vec!["call".to_string(), "server/tool/extra".to_string()];
        let result = parse_call_args(&args);
        assert_eq!(
            result,
            Some(("server".to_string(), "tool/extra".to_string()))
        );
    }
}
