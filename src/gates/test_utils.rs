//! Test utilities for gate tests.

use crate::models::CommandInfo;

/// Create a CommandInfo for testing.
///
/// # Example
/// ```ignore
/// use crate::gates::test_utils::cmd;
///
/// let info = cmd("git", &["status"]);
/// assert_eq!(info.program, "git");
/// assert_eq!(info.args, vec!["status"]);
/// ```
pub fn cmd(program: &str, args: &[&str]) -> CommandInfo {
    CommandInfo {
        raw: format!("{} {}", program, args.join(" ")),
        program: program.to_string(),
        args: args.iter().map(|s| s.to_string()).collect(),
        is_subshell: false,
        is_pipeline: false,
        pipeline_position: 0,
    }
}
