//! Bash Gates - Intelligent bash command permission gate for Claude Code.
//!
//! Usage:
//!   `echo '{"tool_name": "Bash", "tool_input": {"command": "gh pr list"}}' | bash-gates`
//!
//! Or in Claude Code settings.json:
//!   {
//!     "hooks": {
//!       "PreToolUse": [{
//!         "matcher": "Bash",
//!         "hooks": [{
//!           "type": "command",
//!           "command": "/path/to/bash-gates",
//!           "timeout": 10
//!         }]
//!       }]
//!     }
//!   }

use bash_gates::models::{HookInput, HookOutput};
use bash_gates::router::check_command;
use std::io::{self, Read};

fn main() {
    // Read input from stdin
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        eprintln!("Error reading stdin: {e}");
        print_approve();
        return;
    }

    if input.trim().is_empty() {
        print_approve();
        return;
    }

    // Parse JSON input
    let hook_input: HookInput = match serde_json::from_str(&input) {
        Ok(hi) => hi,
        Err(e) => {
            eprintln!("Error: Invalid JSON input: {e}");
            print_approve();
            return;
        }
    };

    // Only process Bash tools
    if hook_input.tool_name != "Bash" {
        print_approve();
        return;
    }

    // Get command string
    let command = hook_input.get_command();
    if command.is_empty() {
        print_approve();
        return;
    }

    // Check command and output result
    let output = check_command(&command);
    match serde_json::to_string(&output) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("Error serializing output: {e}");
            print_approve();
        }
    }
}

fn print_approve() {
    let output = HookOutput::approve();
    if let Ok(json) = serde_json::to_string(&output) {
        println!("{json}");
    } else {
        println!(r#"{{"decision":"approve"}}"#);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_input_parsing() {
        let json = r#"{"tool_name": "Bash", "tool_input": {"command": "git status"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.get_command(), "git status");
    }

    #[test]
    fn test_hook_input_with_map() {
        let json =
            r#"{"tool_name": "Bash", "tool_input": {"command": "npm install", "timeout": 120}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.get_command(), "npm install");
    }

    #[test]
    fn test_check_command_git_status() {
        let output = check_command("git status");
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("allow"));
    }

    #[test]
    fn test_check_command_npm_install() {
        let output = check_command("npm install");
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("ask"));
    }

    #[test]
    fn test_check_command_rm_rf_root() {
        let output = check_command("rm -rf /");
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("deny"));
    }
}
