//! Tool availability cache for modern CLI hints.
//!
//! Detects which modern CLI tools are installed and caches the results
//! to avoid repeated `which` calls on every command.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::SystemTime;

/// Cache TTL - refresh after 7 days
const CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// All modern tools we might hint about (focused on code reading/understanding)
const MODERN_TOOLS: &[&str] = &[
    // File viewing
    "bat", "batcat", // bat is sometimes installed as batcat on Debian/Ubuntu
    // Code search
    "rg", "ripgrep", // ripgrep - faster grep (may be installed as either)
    // File finding
    "fd", "fdfind", // fd is sometimes fdfind on Debian/Ubuntu
    // File listing
    "eza", // modern ls with git integration
    "lsd", // another modern ls alternative
    // Text processing
    "sd",     // modern sed - simpler syntax
    "choose", // modern awk field selection
    "jq",     // JSON processor
    "gron",   // JSON flattening for grep
    // Disk usage
    "dust", // modern du - visual tree
    // Process viewing
    "procs", // modern ps - better formatting
    // HTTP (API exploration)
    "xh", // modern curl/wget - cleaner output
    // Code stats
    "tokei", // modern cloc - faster
    "scc",   // another fast code stats tool
    // Hex viewing
    "hexyl", // modern xxd/hexdump - colored
    // Diff viewing
    "delta", // syntax-highlighted diffs
    "difft", // difftastic - structural diff
    // Documentation
    "tldr", "tealdeer", // simplified man pages with examples
    // Fuzzy finding
    "fzf", // fuzzy finder for code exploration
    // Markdown
    "glow", // markdown rendering in terminal
];

/// Cached tool availability data
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ToolCache {
    /// Map of tool name -> is_available
    pub tools: HashMap<String, bool>,
    /// When the cache was last updated (Unix timestamp)
    pub checked_at: u64,
}

impl ToolCache {
    /// Check if a specific tool is available
    pub fn is_available(&self, tool: &str) -> bool {
        // Handle aliases (some tools have different names on different distros)
        match tool {
            "bat" => {
                self.tools.get("bat").copied().unwrap_or(false)
                    || self.tools.get("batcat").copied().unwrap_or(false)
            }
            "fd" => {
                self.tools.get("fd").copied().unwrap_or(false)
                    || self.tools.get("fdfind").copied().unwrap_or(false)
            }
            "rg" => {
                self.tools.get("rg").copied().unwrap_or(false)
                    || self.tools.get("ripgrep").copied().unwrap_or(false)
            }
            "tldr" => {
                self.tools.get("tldr").copied().unwrap_or(false)
                    || self.tools.get("tealdeer").copied().unwrap_or(false)
            }
            _ => self.tools.get(tool).copied().unwrap_or(false),
        }
    }

    /// Check if cache is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        if self.checked_at == 0 {
            return false;
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now.saturating_sub(self.checked_at) < CACHE_TTL_SECS
    }
}

/// Get the cache file path
fn cache_path() -> Option<PathBuf> {
    // Try XDG cache dir first, fall back to ~/.cache
    let cache_dir = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .ok()
        .or_else(|| dirs::home_dir().map(|h| h.join(".cache")))?;

    Some(cache_dir.join("bash-gates").join("available-tools.json"))
}

/// Load cache from disk
fn load_cache() -> Option<ToolCache> {
    let path = cache_path()?;
    let content = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Save cache to disk
fn save_cache(cache: &ToolCache) -> Result<(), std::io::Error> {
    let path = cache_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not determine cache path",
        )
    })?;

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let content = serde_json::to_string_pretty(cache)?;
    fs::write(&path, content)?;
    Ok(())
}

/// Check if a tool is available using `which`
fn check_tool_available(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Detect all modern tools and create a new cache
pub fn detect_tools() -> ToolCache {
    let mut tools = HashMap::new();

    for tool in MODERN_TOOLS {
        tools.insert(tool.to_string(), check_tool_available(tool));
    }

    let checked_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    ToolCache { tools, checked_at }
}

/// Get the tool cache, loading from disk or detecting if needed
pub fn get_cache() -> ToolCache {
    // Try to load existing cache
    if let Some(cache) = load_cache() {
        if cache.is_valid() {
            return cache;
        }
    }

    // Cache missing or expired - detect tools and save
    let cache = detect_tools();
    let _ = save_cache(&cache); // Ignore save errors
    cache
}

/// Force refresh the cache
pub fn refresh_cache() -> ToolCache {
    let cache = detect_tools();
    let _ = save_cache(&cache);
    cache
}

/// Get cache status for display
pub fn cache_status() -> String {
    let path = cache_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    if let Some(cache) = load_cache() {
        let age = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .saturating_sub(cache.checked_at);

        let age_str = if age < 60 {
            format!("{}s ago", age)
        } else if age < 3600 {
            format!("{}m ago", age / 60)
        } else if age < 86400 {
            format!("{}h ago", age / 3600)
        } else {
            format!("{}d ago", age / 86400)
        };

        let mut available: Vec<_> = cache
            .tools
            .iter()
            .filter(|(_, v)| **v)
            .map(|(k, _)| k.as_str())
            .collect();
        available.sort();

        format!(
            "Cache: {}\nLast checked: {}\nAvailable tools: {}",
            path,
            age_str,
            if available.is_empty() {
                "none".to_string()
            } else {
                available.join(", ")
            }
        )
    } else {
        format!("Cache: {} (not found)", path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_validity() {
        let mut cache = ToolCache::default();
        assert!(!cache.is_valid(), "Empty cache should be invalid");

        cache.checked_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(cache.is_valid(), "Fresh cache should be valid");
    }

    #[test]
    fn test_tool_aliases() {
        let mut cache = ToolCache::default();
        cache.tools.insert("batcat".to_string(), true);
        cache.tools.insert("fdfind".to_string(), true);

        assert!(cache.is_available("bat"), "bat alias should work");
        assert!(cache.is_available("fd"), "fd alias should work");
        assert!(
            !cache.is_available("rg"),
            "missing tool should return false"
        );
    }

    #[test]
    fn test_detect_tools() {
        // This actually runs `which` - just verify it doesn't panic
        let cache = detect_tools();
        assert!(cache.checked_at > 0);
        assert!(!cache.tools.is_empty());
    }
}
