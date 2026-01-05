//! Permission gates for different command categories.
//!
//! Gates use a hybrid approach:
//! 1. Try declarative rules first (from generated code)
//! 2. Fall back to custom handlers for complex logic

pub mod basics;
pub mod beads;
pub mod cloud;
pub mod devtools;
pub mod filesystem;
pub mod gh;
pub mod git;
pub mod helpers;
pub mod mcp;
pub mod network;
pub mod package_managers;
pub mod shortcut;
pub mod system;

#[cfg(test)]
pub mod test_utils;

pub use basics::check_basics;
pub use beads::check_beads;
pub use cloud::check_cloud;
pub use devtools::check_devtools;
pub use filesystem::check_filesystem;
pub use gh::check_gh;
pub use git::check_git;
pub use mcp::{check_mcp, check_mcp_call};
pub use network::check_network;
pub use package_managers::check_package_managers;
pub use shortcut::check_shortcut;
pub use system::check_system;

use crate::models::{CommandInfo, GateResult};

/// Type alias for gate check functions
pub type GateCheckFn = fn(&CommandInfo) -> GateResult;

/// All gates to run (in order)
/// mcp runs first (priority 5), basics runs last as a catch-all for safe commands
pub static GATES: &[(&str, GateCheckFn)] = &[
    ("mcp", check_mcp),
    ("gh", check_gh),
    ("beads", check_beads),
    ("shortcut", check_shortcut),
    ("cloud", check_cloud),
    ("network", check_network),
    ("git", check_git),
    ("filesystem", check_filesystem),
    ("devtools", check_devtools),
    ("package_managers", check_package_managers),
    ("system", check_system),
    ("basics", check_basics),
];
