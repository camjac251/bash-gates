//! Common helper functions for gate implementations.
//!
//! These helpers extract common patterns that can't be expressed declaratively.

/// Extract the value of a flag from command arguments.
///
/// Handles multiple formats:
/// - `-X value` (short flag with space)
/// - `-Xvalue` (short flag combined)
/// - `--flag value` (long flag with space)
/// - `--flag=value` (long flag with equals)
///
/// # Example
/// ```ignore
/// let args = vec!["-X".to_string(), "POST".to_string()];
/// assert_eq!(get_flag_value(&args, &["-X", "--request"]), Some("POST"));
/// ```
pub fn get_flag_value<'a>(args: &'a [String], flags: &[&str]) -> Option<&'a str> {
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];

        for flag in flags {
            // Long flag with equals: --request=POST
            if let Some(value) = arg.strip_prefix(&format!("{}=", flag)) {
                return Some(value);
            }

            // Exact match with next arg: -X POST or --request POST
            if arg == *flag && i + 1 < args.len() {
                return Some(&args[i + 1]);
            }

            // Short flag combined: -XPOST (only for single-char flags)
            if flag.len() == 2 && flag.starts_with('-') && !flag.starts_with("--") {
                if let Some(value) = arg.strip_prefix(flag) {
                    if !value.is_empty() {
                        return Some(value);
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// Normalize a path for security checking.
///
/// Collapses multiple slashes, removes trailing slashes and dots.
/// Used to detect path traversal attempts like `//`, `/./`, etc.
///
/// # Example
/// ```ignore
/// assert_eq!(normalize_path("//"), "/");
/// assert_eq!(normalize_path("/./"), "/");
/// assert_eq!(normalize_path("/tmp/../"), "/tmp/..");
/// ```
pub fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }

    // Collapse multiple slashes
    let mut result: String = path.chars().fold(String::new(), |mut acc, c| {
        if c == '/' && acc.ends_with('/') {
            // Skip duplicate slash
        } else {
            acc.push(c);
        }
        acc
    });

    // Remove trailing /. sequences and trailing slashes
    loop {
        if result.ends_with("/.") {
            result.truncate(result.len() - 2);
        } else if result.len() > 1 && result.ends_with('/') {
            result.pop();
        } else {
            break;
        }
    }

    // Empty result from root path normalization should become /
    if result.is_empty() {
        return "/".to_string();
    }

    result
}

/// Check if a path contains suspicious traversal patterns.
///
/// Returns true if the path could potentially traverse to sensitive locations.
pub fn is_suspicious_path(path: &str) -> bool {
    // Absolute path with .. could reach root
    if path.starts_with('/') && path.contains("..") {
        return true;
    }
    false
}

/// Check if command has any of the specified flags.
pub fn has_any_flag(args: &[String], flags: &[&str]) -> bool {
    args.iter().any(|a| flags.contains(&a.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // === get_flag_value ===

    #[test]
    fn test_get_flag_value_short_space() {
        let args: Vec<String> = vec!["-X", "POST", "http://example.com"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(get_flag_value(&args, &["-X", "--request"]), Some("POST"));
    }

    #[test]
    fn test_get_flag_value_short_combined() {
        let args: Vec<String> = vec!["-XPOST", "http://example.com"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(get_flag_value(&args, &["-X", "--request"]), Some("POST"));
    }

    #[test]
    fn test_get_flag_value_long_space() {
        let args: Vec<String> = vec!["--request", "PUT", "http://example.com"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(get_flag_value(&args, &["-X", "--request"]), Some("PUT"));
    }

    #[test]
    fn test_get_flag_value_long_equals() {
        let args: Vec<String> = vec!["--request=DELETE", "http://example.com"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(get_flag_value(&args, &["-X", "--request"]), Some("DELETE"));
    }

    #[test]
    fn test_get_flag_value_not_found() {
        let args: Vec<String> = vec!["http://example.com"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(get_flag_value(&args, &["-X", "--request"]), None);
    }

    // === normalize_path ===

    #[test]
    fn test_normalize_path_double_slash() {
        assert_eq!(normalize_path("//"), "/");
        assert_eq!(normalize_path("///"), "/");
    }

    #[test]
    fn test_normalize_path_trailing_dot() {
        assert_eq!(normalize_path("/./"), "/");
        assert_eq!(normalize_path("/tmp/."), "/tmp");
    }

    #[test]
    fn test_normalize_path_trailing_slash() {
        assert_eq!(normalize_path("/tmp/"), "/tmp");
    }

    #[test]
    fn test_normalize_path_normal() {
        assert_eq!(normalize_path("/tmp/foo"), "/tmp/foo");
    }

    // === is_suspicious_path ===

    #[test]
    fn test_suspicious_path_traversal() {
        assert!(is_suspicious_path("/tmp/../etc/passwd"));
        assert!(is_suspicious_path("/.."));
    }

    #[test]
    fn test_suspicious_path_safe() {
        assert!(!is_suspicious_path("/tmp/foo"));
        assert!(!is_suspicious_path("../relative")); // Not absolute, not suspicious
    }

    // === has_any_flag ===

    #[test]
    fn test_has_any_flag() {
        let args: Vec<String> = vec!["--dry-run", "deploy"]
            .into_iter()
            .map(String::from)
            .collect();
        assert!(has_any_flag(&args, &["--dry-run", "-n"]));
        assert!(!has_any_flag(&args, &["--force", "-f"]));
    }
}
