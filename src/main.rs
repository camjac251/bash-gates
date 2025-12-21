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
use bash_gates::router::check_command_with_settings;
use bash_gates::toml_export;
use std::env;
use std::io::{self, Read};

fn main() {
    // Check for CLI flags
    let args: Vec<String> = env::args().collect();

    if args
        .iter()
        .any(|a| a == "--export-toml" || a == "--gemini-policy")
    {
        // Export Gemini CLI policy rules
        print!("{}", toml_export::generate_toml());
        return;
    }

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("bash-gates {}", env!("GIT_VERSION"));
        return;
    }

    if args.iter().any(|a| a == "--help" || a == "-h") {
        eprintln!("bash-gates - Intelligent bash command permission gate");
        eprintln!();
        eprintln!("USAGE:");
        eprintln!("  bash-gates                   Read hook input from stdin (default)");
        eprintln!("  bash-gates --export-toml     Export Gemini CLI policy rules");
        eprintln!("  bash-gates --help            Show this help");
        eprintln!("  bash-gates --version         Show version");
        eprintln!();
        eprintln!("GEMINI CLI SETUP:");
        eprintln!("  bash-gates --export-toml > ~/.gemini/policies/bash-gates.toml");
        return;
    }

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

    // Only process Bash tools (Claude Code)
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

    // Check command with settings.json awareness
    let output = check_command_with_settings(&command, &hook_input.cwd);
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
    use bash_gates::check_command;

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

    #[test]
    fn test_output_uses_pre_tool_use() {
        let output = check_command("git status");
        let json = serde_json::to_string(&output).unwrap();
        assert!(
            json.contains("PreToolUse"),
            "Expected PreToolUse in: {json}"
        );
    }
}
