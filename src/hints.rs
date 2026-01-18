//! Modern CLI hints for legacy commands.
//!
//! Detects when legacy commands are used and suggests modern alternatives.
//! These hints are added to `additionalContext` so Claude can learn better patterns.
//!
//! Hints are only shown if the modern tool is actually installed (checked via cache).

use crate::models::CommandInfo;
use crate::tool_cache::{ToolCache, get_cache};
use std::sync::OnceLock;

/// Global tool cache - loaded once per process
static TOOL_CACHE: OnceLock<ToolCache> = OnceLock::new();

/// Get the tool cache (loads from disk on first call)
fn cache() -> &'static ToolCache {
    TOOL_CACHE.get_or_init(get_cache)
}

/// A hint suggesting a modern alternative to a legacy command.
#[derive(Debug, Clone)]
pub struct ModernHint {
    pub legacy_command: &'static str,
    pub modern_command: &'static str,
    pub hint: String,
}

/// Check if a command could benefit from a modern alternative and return a hint.
/// Only returns hints for tools that are actually installed.
pub fn get_modern_hint(cmd: &CommandInfo) -> Option<ModernHint> {
    let hint = match cmd.program.as_str() {
        // File viewing
        "cat" => Some(hint_cat(cmd)),
        "head" => Some(hint_head(cmd)),
        "tail" => hint_tail(cmd),
        "less" | "more" => Some(hint_less(cmd)),
        // Search & find
        "grep" => hint_grep(cmd),
        "ag" | "ack" => Some(hint_ag_ack(cmd)),
        "find" => Some(hint_find(cmd)),
        // Text processing
        "sed" => hint_sed(cmd),
        "awk" => hint_awk(cmd),
        "wc" => hint_wc(cmd),
        // File listing & disk
        "ls" => hint_ls(cmd),
        "du" => Some(hint_du(cmd)),
        "tree" => hint_tree(cmd),
        // Process (for debugging)
        "ps" => hint_ps(cmd),
        // Network (for API exploration)
        "curl" => hint_curl(cmd),
        "wget" => hint_wget(cmd),
        // Diff & hex (code understanding)
        "diff" => hint_diff(cmd),
        "xxd" | "hexdump" => Some(hint_hex(cmd)),
        // Code stats
        "cloc" => Some(hint_cloc(cmd)),
        // Documentation (understanding APIs/libraries)
        "man" => hint_man(cmd),
        _ => None,
    }?;

    // Only return hint if the modern tool is installed
    if cache().is_available(hint.modern_command) {
        Some(hint)
    } else {
        None
    }
}

fn hint_cat(cmd: &CommandInfo) -> ModernHint {
    // Check if it's viewing a file (not piping)
    let files: Vec<_> = cmd.args.iter().filter(|a| !a.starts_with('-')).collect();
    if files.is_empty() {
        return ModernHint {
            legacy_command: "cat",
            modern_command: "bat",
            hint: "Tip: Use 'bat' for syntax-highlighted output with line numbers".to_string(),
        };
    }

    // Check file extension for specific hints
    let file = files[0];
    let ext_hint = if file.ends_with(".json") {
        " (JSON syntax highlighting)"
    } else if file.ends_with(".md") {
        " (Markdown rendering)"
    } else if file.ends_with(".rs") || file.ends_with(".py") || file.ends_with(".ts") {
        " (code syntax highlighting)"
    } else {
        ""
    };

    ModernHint {
        legacy_command: "cat",
        modern_command: "bat",
        hint: format!(
            "Tip: Use 'bat {}' for syntax highlighting and line numbers{}",
            file, ext_hint
        ),
    }
}

fn hint_head(cmd: &CommandInfo) -> ModernHint {
    // Parse -n flag to get line count
    let mut lines = "10".to_string();
    let mut file = String::new();

    let mut iter = cmd.args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "-n" {
            if let Some(n) = iter.next() {
                lines = n.clone();
            }
        } else if arg.starts_with("-n") && arg.len() > 2 {
            lines = arg[2..].to_string();
        } else if !arg.starts_with('-') {
            file = arg.clone();
        }
    }

    let bat_range = format!(":{}", lines);
    ModernHint {
        legacy_command: "head",
        modern_command: "bat",
        hint: format!(
            "Tip: Use 'bat -r {} {}' for first {} lines with syntax highlighting",
            bat_range,
            if file.is_empty() { "<file>" } else { &file },
            lines
        ),
    }
}

fn hint_tail(cmd: &CommandInfo) -> Option<ModernHint> {
    // Parse -n flag to get line count
    let mut lines = "10".to_string();
    let mut file = String::new();
    let mut follow = false;

    let mut iter = cmd.args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-n" {
            if let Some(n) = iter.next() {
                lines = n.clone();
            }
        } else if arg.starts_with("-n") && arg.len() > 2 {
            lines = arg[2..].to_string();
        } else if arg == "-f" || arg == "--follow" {
            follow = true;
        } else if !arg.starts_with('-') {
            file = arg.clone();
        }
    }

    // tail -f is fine - no hint needed (bat doesn't support following)
    if follow {
        return None;
    }

    let bat_range = format!("-{}:", lines);
    Some(ModernHint {
        legacy_command: "tail",
        modern_command: "bat",
        hint: format!(
            "Tip: Use 'bat -r {} {}' for last {} lines with syntax highlighting",
            bat_range,
            if file.is_empty() { "<file>" } else { &file },
            lines
        ),
    })
}

fn hint_grep(cmd: &CommandInfo) -> Option<ModernHint> {
    // Don't hint if already using rg or if it's a simple pipe case
    if cmd.args.is_empty() {
        return None;
    }

    // Check for flags that rg handles better
    let has_recursive = cmd
        .args
        .iter()
        .any(|a| a == "-r" || a == "-R" || a == "--recursive");
    let has_context = cmd
        .args
        .iter()
        .any(|a| a.starts_with("-A") || a.starts_with("-B") || a.starts_with("-C"));

    let hint = if has_recursive {
        "Tip: Use 'rg <pattern>' - it's recursive by default, respects .gitignore, and is much faster"
    } else if has_context {
        "Tip: Use 'rg <pattern>' with -A/-B/-C for context - same syntax but faster"
    } else {
        "Tip: Consider 'rg <pattern>' for faster searching with better defaults"
    };

    Some(ModernHint {
        legacy_command: "grep",
        modern_command: "rg",
        hint: hint.to_string(),
    })
}

fn hint_find(cmd: &CommandInfo) -> ModernHint {
    // Check for common patterns
    let has_name = cmd.args.iter().any(|a| a == "-name" || a == "-iname");
    let has_type = cmd.args.iter().any(|a| a == "-type");

    let hint = if has_name {
        "Tip: Use 'fd <pattern>' - simpler syntax, respects .gitignore, much faster. Example: fd '*.rs' instead of find . -name '*.rs'"
    } else if has_type {
        "Tip: Use 'fd -t <type> <pattern>' - e.g., 'fd -t f' for files, 'fd -t d' for directories"
    } else {
        "Tip: Use 'fd <pattern>' for faster, simpler file finding with smart defaults"
    };

    ModernHint {
        legacy_command: "find",
        modern_command: "fd",
        hint: hint.to_string(),
    }
}

fn hint_sed(cmd: &CommandInfo) -> Option<ModernHint> {
    // Only hint for substitution patterns
    let has_subst = cmd
        .args
        .iter()
        .any(|a| a.contains("s/") || a.contains("s#"));
    let has_inplace = cmd.args.iter().any(|a| a == "-i" || a.starts_with("-i"));

    if !has_subst {
        return None;
    }

    let hint = if has_inplace {
        "Tip: Use 'sd <find> <replace> <file>' for simpler in-place substitution. No escaping needed for common patterns."
    } else {
        "Tip: Consider 'sd <find> <replace>' for simpler syntax - no 's/.../.../g' needed"
    };

    Some(ModernHint {
        legacy_command: "sed",
        modern_command: "sd",
        hint: hint.to_string(),
    })
}

fn hint_ls(cmd: &CommandInfo) -> Option<ModernHint> {
    // Only hint for detailed listings
    // Match short flags like -l, -la, -al, but not long flags like --help or --color
    let has_long = cmd
        .args
        .iter()
        .any(|a| (a.starts_with('-') && !a.starts_with("--") && a.contains('l')) || a == "--long");
    let has_all = cmd.args.iter().any(|a| {
        (a.starts_with('-') && !a.starts_with("--") && a.contains('a'))
            || a == "--all"
            || a == "--almost-all"
    });

    if !has_long && !has_all {
        return None; // Simple ls is fine
    }

    Some(ModernHint {
        legacy_command: "ls",
        modern_command: "eza",
        hint: "Tip: Use 'eza -la' for better formatting, git status integration, and icons support"
            .to_string(),
    })
}

fn hint_du(_cmd: &CommandInfo) -> ModernHint {
    ModernHint {
        legacy_command: "du",
        modern_command: "dust",
        hint: "Tip: Use 'dust' for visual disk usage with a tree view and better formatting"
            .to_string(),
    }
}

fn hint_ps(cmd: &CommandInfo) -> Option<ModernHint> {
    // Only hint for detailed process listings
    // BSD style: aux, -aux, axu (any combo of a, u, x)
    // POSIX style: -e, -A, -ef
    let has_all = cmd.args.iter().any(|a| {
        a == "-e"
            || a == "-A"
            || a == "-ef"
            || a == "aux"
            || a == "-aux"
            || a == "axu"
            || a == "-axu"
    });

    if !has_all {
        return None;
    }

    Some(ModernHint {
        legacy_command: "ps",
        modern_command: "procs",
        hint: "Tip: Use 'procs' for better formatted process listing with tree view".to_string(),
    })
}

fn hint_curl(cmd: &CommandInfo) -> Option<ModernHint> {
    // Check for JSON APIs or verbose flags
    let has_json = cmd
        .args
        .iter()
        .any(|a| a.contains("json") || a.contains("application/json"));
    let has_verbose = cmd.args.iter().any(|a| a == "-v" || a == "--verbose");

    if has_json || has_verbose {
        return Some(ModernHint {
            legacy_command: "curl",
            modern_command: "xh",
            hint: "Tip: Use 'xh <url>' for cleaner HTTP output with automatic JSON formatting"
                .to_string(),
        });
    }

    None
}

fn hint_wget(_cmd: &CommandInfo) -> Option<ModernHint> {
    Some(ModernHint {
        legacy_command: "wget",
        modern_command: "xh",
        hint: "Tip: Consider 'xh <url>' for HTTP requests or 'xh -d <url>' for downloads"
            .to_string(),
    })
}

fn hint_awk(cmd: &CommandInfo) -> Option<ModernHint> {
    // Check for simple field extraction patterns
    let has_print = cmd.args.iter().any(|a| a.contains("print $"));

    if has_print {
        return Some(ModernHint {
            legacy_command: "awk",
            modern_command: "choose",
            hint: "Tip: For field extraction, use 'choose <field>' - e.g., 'choose 0 2' instead of awk '{print $1, $3}'".to_string(),
        });
    }

    None
}

fn hint_wc(cmd: &CommandInfo) -> Option<ModernHint> {
    // Only hint for line counting
    let has_lines = cmd.args.iter().any(|a| a == "-l");

    if has_lines {
        return Some(ModernHint {
            legacy_command: "wc -l",
            modern_command: "rg",
            hint: "Tip: If counting matches, use 'rg -c <pattern>' for direct count".to_string(),
        });
    }

    None
}

fn hint_cloc(_cmd: &CommandInfo) -> ModernHint {
    ModernHint {
        legacy_command: "cloc",
        modern_command: "tokei",
        hint: "Tip: Use 'tokei' for faster code statistics with better formatting".to_string(),
    }
}

fn hint_tree(_cmd: &CommandInfo) -> Option<ModernHint> {
    Some(ModernHint {
        legacy_command: "tree",
        modern_command: "eza",
        hint: "Tip: Use 'eza -T' for tree view with git status and better formatting".to_string(),
    })
}

fn hint_hex(cmd: &CommandInfo) -> ModernHint {
    let legacy = if cmd.program == "xxd" {
        "xxd"
    } else {
        "hexdump"
    };
    ModernHint {
        legacy_command: legacy,
        modern_command: "hexyl",
        hint: "Tip: Use 'hexyl <file>' for colored hex dump with better formatting".to_string(),
    }
}

fn hint_diff(cmd: &CommandInfo) -> Option<ModernHint> {
    // Hint for code diffs
    let has_files = cmd.args.iter().filter(|a| !a.starts_with('-')).count() >= 2;

    if has_files {
        return Some(ModernHint {
            legacy_command: "diff",
            modern_command: "delta",
            hint: "Tip: For code diffs, pipe through 'delta' for syntax highlighting: diff a b | delta".to_string(),
        });
    }

    None
}

// === Additional hints for code reading/understanding ===

fn hint_less(_cmd: &CommandInfo) -> ModernHint {
    ModernHint {
        legacy_command: "less",
        modern_command: "bat",
        hint: "Tip: Use 'bat <file>' for syntax-highlighted viewing with line numbers".to_string(),
    }
}

fn hint_man(cmd: &CommandInfo) -> Option<ModernHint> {
    // Only hint if looking up a command
    if cmd.args.is_empty() {
        return None;
    }

    let command = &cmd.args[0];
    Some(ModernHint {
        legacy_command: "man",
        modern_command: "tldr",
        hint: format!(
            "Tip: Use 'tldr {}' for practical examples instead of full manual",
            command
        ),
    })
}

fn hint_ag_ack(cmd: &CommandInfo) -> ModernHint {
    ModernHint {
        legacy_command: if cmd.program == "ag" { "ag" } else { "ack" },
        modern_command: "rg",
        hint: format!(
            "Tip: Consider 'rg' instead of '{}' - faster with similar interface",
            cmd.program
        ),
    }
}

/// Format hints as a single context string for Claude.
pub fn format_hints(hints: &[ModernHint]) -> String {
    if hints.is_empty() {
        return String::new();
    }

    hints
        .iter()
        .map(|h| h.hint.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(program: &str, args: &[&str]) -> CommandInfo {
        CommandInfo {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            raw: format!("{} {}", program, args.join(" ")),
        }
    }

    #[test]
    fn test_cat_hint() {
        let hint = get_modern_hint(&cmd("cat", &["file.rs"]));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.modern_command, "bat");
        assert!(hint.hint.contains("syntax highlighting"));
    }

    #[test]
    fn test_head_hint() {
        let hint = get_modern_hint(&cmd("head", &["-n", "50", "file.txt"]));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.modern_command, "bat");
        assert!(hint.hint.contains("-r :50"));
    }

    #[test]
    fn test_tail_hint() {
        let hint = get_modern_hint(&cmd("tail", &["-n", "30", "file.txt"]));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert!(hint.hint.contains("-r -30:"));
    }

    #[test]
    fn test_tail_follow_no_hint() {
        // tail -f doesn't get a hint - it's the right tool for the job
        let hint = get_modern_hint(&cmd("tail", &["-f", "file.txt"]));
        assert!(hint.is_none(), "tail -f should not get a hint");
    }

    #[test]
    fn test_grep_hint() {
        let hint = get_modern_hint(&cmd("grep", &["-r", "pattern", "src/"]));
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.modern_command, "rg");
        assert!(hint.hint.contains("recursive by default"));
    }

    #[test]
    fn test_find_hint() {
        let hint = get_modern_hint(&cmd("find", &[".", "-name", "*.rs"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("fd"));
    }

    #[test]
    fn test_sed_subst_hint() {
        let hint = get_modern_hint(&cmd("sed", &["-i", "s/old/new/g", "file.txt"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("sd"));
    }

    #[test]
    fn test_ls_simple_no_hint() {
        let hint = get_modern_hint(&cmd("ls", &[]));
        assert!(hint.is_none()); // Simple ls doesn't need hint
    }

    #[test]
    fn test_ls_detailed_hint() {
        let hint = get_modern_hint(&cmd("ls", &["-la"]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("eza"));
    }

    #[test]
    fn test_du_hint() {
        let hint = get_modern_hint(&cmd("du", &["-sh", "."]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("dust"));
    }

    #[test]
    fn test_tokei_hint() {
        let hint = get_modern_hint(&cmd("cloc", &["."]));
        assert!(hint.is_some());
        assert!(hint.unwrap().hint.contains("tokei"));
    }

    #[test]
    fn test_unknown_command_no_hint() {
        let hint = get_modern_hint(&cmd("rustfmt", &["file.rs"]));
        assert!(hint.is_none());
    }
}
