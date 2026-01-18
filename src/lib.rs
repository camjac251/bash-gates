//! Bash Gates - Intelligent bash command permission gate.
//!
//! This library provides command parsing and permission checking for bash commands,
//! designed for use as a Claude Code PreToolUse hook.
//!
//! # Example
//!
//! ```
//! use bash_gates::check_command;
//!
//! // Safe command - allowed
//! let output = check_command("git status");
//! let decision = &output.hook_specific_output.as_ref().unwrap().permission_decision;
//! assert_eq!(decision, "allow");
//!
//! // Dangerous command - blocked
//! let output = check_command("rm -rf /");
//! let decision = &output.hook_specific_output.as_ref().unwrap().permission_decision;
//! assert_eq!(decision, "deny");
//! ```

pub mod gates;
pub mod generated;
pub mod hints;
pub mod mise;
pub mod models;
pub mod package_json;
pub mod parser;
pub mod router;
pub mod settings;
pub mod toml_export;
pub mod tool_cache;

pub use models::{CommandInfo, Decision, GateResult};
pub use router::{check_command, check_command_with_settings};
