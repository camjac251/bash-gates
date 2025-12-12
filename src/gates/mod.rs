//! Permission gates for different command categories.

mod basics;
mod cloud;
mod devtools;
mod filesystem;
mod gh;
mod git;
mod network;
mod package_managers;
mod system;

pub use basics::check_basics;
pub use cloud::check_cloud;
pub use devtools::check_devtools;
pub use filesystem::check_filesystem;
pub use gh::check_gh;
pub use git::check_git;
pub use network::check_network;
pub use package_managers::check_package_managers;
pub use system::check_system;

use crate::models::{CommandInfo, GateResult};

/// Type alias for gate check functions
pub type GateCheckFn = fn(&CommandInfo) -> GateResult;

/// All gates to run (in order)
/// basics runs last as a catch-all for safe commands
pub static GATES: &[(&str, GateCheckFn)] = &[
    ("gh", check_gh),
    ("cloud", check_cloud),
    ("network", check_network),
    ("git", check_git),
    ("filesystem", check_filesystem),
    ("devtools", check_devtools),
    ("package_managers", check_package_managers),
    ("system", check_system),
    ("basics", check_basics),
];
