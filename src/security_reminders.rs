//! Security anti-pattern scanning for Write/Edit/MultiEdit content.
//!
//! Scans file edit content for common vulnerability patterns (command injection,
//! XSS, hardcoded secrets, unsafe deserialization, etc.) and returns deny/warn
//! decisions. Warnings are deduped per (file, rule) per session.
//!
//! Patterns are organized into tiers:
//! - **Tier 1 (deny):** High confidence, near-zero false positives (secrets, keys)
//! - **Tier 2 (ask-once):** User prompted first time per session, then silent (eval, exec, XSS)
//! - **Tier 3 (warn):** Informational context injected, no block (weak crypto, chmod 777)

use crate::config::SecurityRemindersConfig;
use crate::models::{HookOutput, PostToolUseOutput};
use regex::Regex;
use std::sync::OnceLock;

/// Extract all writable content strings from a tool_input map.
///
/// Handles all tool types:
/// - Write: `map["content"]`
/// - Edit (classic): `map["new_string"]`
/// - Edit (batch): `map["edits"][*]["new_string"]`
/// - MultiEdit: `map["files"][*]["edits"][*]["new_string"]`
///
/// Returns a vec of (file_path, content) pairs. For Write/Edit the file_path
/// comes from the top-level `file_path` field. For MultiEdit each file has its own.
fn extract_content(
    tool_name: &str,
    map: &serde_json::Map<String, serde_json::Value>,
) -> Vec<(String, String)> {
    let mut results = Vec::new();

    let top_file_path = map
        .get("file_path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    match tool_name {
        "Write" => {
            if let Some(content) = map.get("content").and_then(|v| v.as_str()) {
                if !content.is_empty() {
                    results.push((top_file_path, content.to_string()));
                }
            }
        }
        "Edit" => {
            // Classic: single new_string
            if let Some(new_string) = map.get("new_string").and_then(|v| v.as_str()) {
                if !new_string.is_empty() {
                    results.push((top_file_path.clone(), new_string.to_string()));
                }
            }
            // Batch: edits[].new_string
            if let Some(edits) = map.get("edits").and_then(|v| v.as_array()) {
                for edit in edits {
                    if let Some(ns) = edit.get("new_string").and_then(|v| v.as_str()) {
                        if !ns.is_empty() {
                            results.push((top_file_path.clone(), ns.to_string()));
                        }
                    }
                }
            }
        }
        "MultiEdit" => {
            if let Some(files) = map.get("files").and_then(|v| v.as_array()) {
                for file in files {
                    let fp = file
                        .get("file_path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if let Some(edits) = file.get("edits").and_then(|v| v.as_array()) {
                        for edit in edits {
                            if let Some(ns) = edit.get("new_string").and_then(|v| v.as_str()) {
                                if !ns.is_empty() {
                                    results.push((fp.clone(), ns.to_string()));
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    results
}

/// Pattern severity tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Hard deny -- always blocked (secrets, keys).
    Deny,
    /// Ask once per (file, rule) per session, then silent.
    AskOnce,
    /// Allow but inject warning into additionalContext.
    Warn,
}

/// A matched security pattern.
#[derive(Debug)]
pub struct PatternMatch {
    pub rule_name: &'static str,
    pub tier: Tier,
    pub message: &'static str,
}

/// Whether a rule checks path, content, or both.
enum CheckType {
    /// Only fires if file path matches (e.g., GHA workflows).
    PathBased { path_fn: fn(&str) -> bool },
    /// Fires on content substrings (skips doc files).
    Substring { patterns: &'static [&'static str] },
    /// Fires on content substrings unless exclusion also matches (skips doc files).
    SubstringUnless {
        patterns: &'static [&'static str],
        unless: &'static [&'static str],
    },
    /// Fires on content regex (skips doc files).
    ContentRegex { pattern: &'static str },
}

struct SecurityRule {
    name: &'static str,
    tier: Tier,
    message: &'static str,
    check: CheckType,
    /// If true, Tier 1 secret check that fires even on doc files.
    always_check: bool,
}

/// Doc file extensions -- content-based checks are skipped for these.
const DOC_EXTENSIONS: &[&str] = &[".md", ".txt", ".rst", ".adoc", ".asciidoc", ".html", ".htm"];

fn is_doc_file(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    DOC_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

fn is_gha_workflow(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    normalized.contains(".github/workflows/")
        && (normalized.ends_with(".yml") || normalized.ends_with(".yaml"))
}

/// Compiled regex cache (compiled once, reused).
static REGEX_CACHE: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();

fn get_compiled_regexes(rules: &[SecurityRule]) -> &'static Vec<(&'static str, Regex)> {
    REGEX_CACHE.get_or_init(|| {
        rules
            .iter()
            .filter_map(|rule| {
                if let CheckType::ContentRegex { pattern } = &rule.check {
                    Some((
                        rule.name,
                        Regex::new(pattern).expect("invalid security regex"),
                    ))
                } else {
                    None
                }
            })
            .collect()
    })
}

/// All security rules (static definition).
fn rules() -> &'static [SecurityRule] {
    static RULES: OnceLock<Vec<SecurityRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            // === Tier 1: Hard deny ===
            SecurityRule {
                name: "hardcoded_aws_key",
                tier: Tier::Deny,
                message: "Hardcoded AWS access key detected. Use environment variables or a secrets manager instead. Never commit AWS keys to source code.",
                check: CheckType::ContentRegex { pattern: r"AKIA[0-9A-Z]{16}" },
                always_check: true,
            },
            SecurityRule {
                name: "hardcoded_private_key",
                tier: Tier::Deny,
                message: "Private key detected in file content. Private keys must never be committed to source code. Use environment variables, a secrets manager, or file references outside the repo.",
                check: CheckType::Substring {
                    patterns: &[
                        "-----BEGIN RSA PRIVATE KEY",
                        "-----BEGIN EC PRIVATE KEY",
                        "-----BEGIN DSA PRIVATE KEY",
                        "-----BEGIN PRIVATE KEY",
                        "-----BEGIN OPENSSH PRIVATE KEY",
                    ],
                },
                always_check: true,
            },
            SecurityRule {
                name: "hardcoded_github_token",
                tier: Tier::Deny,
                message: "GitHub token detected in file content. Use GITHUB_TOKEN environment variable or gh auth instead. Revoke this token if it was ever committed.",
                check: CheckType::ContentRegex { pattern: r"(ghp|ghs|ghu|gho|ghr)_[A-Za-z0-9_]{36,}" },
                always_check: true,
            },
            SecurityRule {
                name: "hardcoded_generic_secret",
                tier: Tier::Deny,
                message: "API key or token detected in file content. Use environment variables or a secrets manager. Never hardcode secrets in source code.",
                check: CheckType::ContentRegex {
                    pattern: r"(sk-[A-Za-z0-9]{20,}|xox[bporas]-[A-Za-z0-9\-]{10,}|AIza[A-Za-z0-9_\-]{35})",
                },
                always_check: true,
            },
            SecurityRule {
                name: "github_actions_injection",
                tier: Tier::Deny,
                message: "GitHub Actions workflow injection risk. Untrusted input (issue title, PR body, commit message, head_ref) used directly in a run: block can lead to command injection.\n\nUNSAFE:\n  run: echo \"${{ github.event.issue.title }}\"\n\nSAFE:\n  env:\n    TITLE: ${{ github.event.issue.title }}\n  run: echo \"$TITLE\"\n\nSee: https://github.blog/security/vulnerability-research/how-to-catch-github-actions-workflow-injections-before-attackers-do/",
                check: CheckType::PathBased { path_fn: is_gha_workflow },
                always_check: false, // Content check happens separately via GHA-specific regex
            },

            // === Tier 2: Ask once per session ===
            SecurityRule {
                name: "child_process_exec",
                tier: Tier::AskOnce,
                message: "child_process.exec() can lead to command injection. Use child_process.execFile() or child_process.spawn() instead -- they don't invoke a shell and prevent argument injection.",
                check: CheckType::Substring { patterns: &["child_process.exec", "execSync("] },
                always_check: false,
            },
            SecurityRule {
                name: "new_function_injection",
                tier: Tier::AskOnce,
                message: "new Function() with dynamic strings can lead to code injection. Consider alternative approaches that don't evaluate arbitrary code.",
                check: CheckType::Substring { patterns: &["new Function("] },
                always_check: false,
            },
            SecurityRule {
                name: "eval_injection",
                tier: Tier::AskOnce,
                message: "eval() executes arbitrary code and is a major security risk. Use JSON.parse() for data parsing, or alternative design patterns that don't require code evaluation.",
                check: CheckType::Substring { patterns: &["eval("] },
                always_check: false,
            },
            SecurityRule {
                name: "os_system_injection",
                tier: Tier::AskOnce,
                message: "os.system() passes commands through the shell and is vulnerable to injection. Use subprocess.run() with a list of arguments (no shell=True) instead.",
                check: CheckType::Substring { patterns: &["os.system(", "from os import system"] },
                always_check: false,
            },
            SecurityRule {
                name: "pickle_deserialization",
                tier: Tier::AskOnce,
                message: "pickle can execute arbitrary code during deserialization. Use JSON, msgpack, or other safe serialization formats for untrusted data. Only use pickle with data you fully trust.",
                check: CheckType::Substring { patterns: &["pickle.load", "pickle.loads"] },
                always_check: false,
            },
            SecurityRule {
                name: "dangerous_inner_html",
                tier: Tier::AskOnce,
                message: "dangerouslySetInnerHTML can lead to XSS if used with untrusted content. Sanitize all content with DOMPurify or use safe alternatives like textContent.",
                check: CheckType::Substring { patterns: &["dangerouslySetInnerHTML"] },
                always_check: false,
            },
            SecurityRule {
                name: "document_write_xss",
                tier: Tier::AskOnce,
                message: "document.write() can be exploited for XSS attacks. Use DOM manipulation methods like createElement() and appendChild() instead.",
                check: CheckType::Substring { patterns: &["document.write("] },
                always_check: false,
            },
            SecurityRule {
                name: "inner_html_assignment",
                tier: Tier::AskOnce,
                message: "Setting innerHTML with untrusted content can lead to XSS. Use textContent for plain text, or sanitize HTML content with DOMPurify.",
                check: CheckType::Substring { patterns: &[".innerHTML =", ".innerHTML="] },
                always_check: false,
            },
            SecurityRule {
                name: "unsafe_yaml_load",
                tier: Tier::AskOnce,
                message: "yaml.load() without SafeLoader can execute arbitrary Python code. Use yaml.safe_load() or yaml.load(f, Loader=yaml.SafeLoader) instead.",
                check: CheckType::SubstringUnless {
                    patterns: &["yaml.load("],
                    unless: &["SafeLoader", "safe_load"],
                },
                always_check: false,
            },
            SecurityRule {
                name: "sql_string_interpolation",
                tier: Tier::AskOnce,
                message: "SQL query built with string interpolation is vulnerable to SQL injection. Use parameterized queries (?, %s, :param) instead of f-strings or .format().",
                check: CheckType::ContentRegex {
                    pattern: r#"(?i)f["'](?:SELECT|INSERT|UPDATE|DELETE)|\.execute\(f["']"#,
                },
                always_check: false,
            },
            SecurityRule {
                name: "subprocess_shell_true",
                tier: Tier::AskOnce,
                message: "subprocess with shell=True is vulnerable to command injection. Pass a list of arguments instead: subprocess.run([\"cmd\", \"arg1\", \"arg2\"]).",
                check: CheckType::ContentRegex {
                    pattern: r"subprocess\.(call|run|Popen)\(.*shell\s*=\s*True",
                },
                always_check: false,
            },
            SecurityRule {
                name: "flask_ssti",
                tier: Tier::AskOnce,
                message: "render_template_string() with user input can lead to server-side template injection (SSTI). Use render_template() with a file instead, or sanitize all dynamic content.",
                check: CheckType::Substring { patterns: &["render_template_string("] },
                always_check: false,
            },
            SecurityRule {
                name: "marshal_deserialization",
                tier: Tier::AskOnce,
                message: "marshal can execute arbitrary code during deserialization. Use JSON or other safe serialization formats for untrusted data.",
                check: CheckType::Substring { patterns: &["marshal.load(", "marshal.loads(", "shelve.open("] },
                always_check: false,
            },
            SecurityRule {
                name: "python_dynamic_import",
                tier: Tier::AskOnce,
                message: "__import__() with dynamic strings can load arbitrary modules. Use static imports or importlib with validated module names.",
                check: CheckType::Substring { patterns: &["__import__("] },
                always_check: false,
            },
            SecurityRule {
                name: "php_unserialize",
                tier: Tier::AskOnce,
                message: "unserialize() with untrusted data can lead to arbitrary code execution via PHP object injection. Use json_decode() instead.",
                check: CheckType::Substring { patterns: &["unserialize("] },
                always_check: false,
            },

            // === Tier 3: Warn (allow with context) ===
            SecurityRule {
                name: "ssl_verification_disabled",
                tier: Tier::Warn,
                message: "SSL/TLS verification is disabled. This makes the connection vulnerable to man-in-the-middle attacks. Only disable for local development with self-signed certs.",
                check: CheckType::Substring {
                    patterns: &["verify=False", "verify = False", "rejectUnauthorized: false", "NODE_TLS_REJECT_UNAUTHORIZED"],
                },
                always_check: false,
            },
            SecurityRule {
                name: "chmod_777",
                tier: Tier::Warn,
                message: "chmod 777 / 0o777 grants read+write+execute to all users. Use more restrictive permissions (e.g., 0o755 for dirs, 0o644 for files).",
                check: CheckType::Substring { patterns: &["chmod 777", "0o777", "0777"] },
                always_check: false,
            },
            SecurityRule {
                name: "weak_crypto_hash",
                tier: Tier::Warn,
                message: "MD5/SHA1 are cryptographically broken for security purposes. Use SHA-256+ for integrity checks, bcrypt/argon2 for passwords.",
                check: CheckType::Substring {
                    patterns: &["hashlib.md5(", "hashlib.sha1(", "MD5.new(", "SHA1.new("],
                },
                always_check: false,
            },
            SecurityRule {
                name: "vue_v_html",
                tier: Tier::Warn,
                message: "v-html renders raw HTML and is vulnerable to XSS with untrusted content. Sanitize content with DOMPurify or use text interpolation {{ }} instead.",
                check: CheckType::Substring { patterns: &["v-html="] },
                always_check: false,
            },
            SecurityRule {
                name: "template_autoescape_disabled",
                tier: Tier::Warn,
                message: "Disabling autoescape removes XSS protection from template output. Only disable for content you have already sanitized.",
                check: CheckType::Substring { patterns: &["autoescape=False", "autoescape: false", "autoescape=false"] },
                always_check: false,
            },
            SecurityRule {
                name: "cors_wildcard",
                tier: Tier::Warn,
                message: "CORS wildcard origin (*) allows any website to make requests. Restrict to specific trusted origins in production.",
                check: CheckType::Substring {
                    patterns: &[
                        "Access-Control-Allow-Origin: *",
                        r#"origins=["*"]"#,
                        r#"origin: "*""#,
                        r#"origin: '*'"#,
                    ],
                },
                always_check: false,
            },
        ]
    })
}

/// GHA-specific content check: does the workflow content reference dangerous inputs in run: blocks?
fn has_gha_injection(content: &str) -> bool {
    static GHA_REGEX: OnceLock<Regex> = OnceLock::new();
    let re = GHA_REGEX.get_or_init(|| {
        Regex::new(r"\$\{\{\s*github\.(event\.(pull_request|issue|comment|discussion|review|review_comment|pages)\.(title|body|head\.ref|label)|head_ref|event\.head_commit\.(message|author\.(email|name)))").unwrap()
    });
    re.is_match(content)
}

/// Scan content against all rules, returning all matches.
pub fn scan_content(file_path: &str, content: &str) -> Vec<PatternMatch> {
    let all_rules = rules();
    let compiled = get_compiled_regexes(all_rules);
    let is_doc = is_doc_file(file_path);
    let mut matches = Vec::new();

    for rule in all_rules {
        // Skip content-based checks on doc files (unless always_check for secrets)
        let skip_content = is_doc && !rule.always_check;

        match &rule.check {
            CheckType::PathBased { path_fn } => {
                if path_fn(file_path) && has_gha_injection(content) {
                    matches.push(PatternMatch {
                        rule_name: rule.name,
                        tier: rule.tier,
                        message: rule.message,
                    });
                }
            }
            CheckType::Substring { patterns } if !skip_content => {
                if patterns.iter().any(|p| content.contains(p)) {
                    matches.push(PatternMatch {
                        rule_name: rule.name,
                        tier: rule.tier,
                        message: rule.message,
                    });
                }
            }
            CheckType::SubstringUnless { patterns, unless } if !skip_content => {
                if patterns.iter().any(|p| content.contains(p))
                    && !unless.iter().any(|u| content.contains(u))
                {
                    matches.push(PatternMatch {
                        rule_name: rule.name,
                        tier: rule.tier,
                        message: rule.message,
                    });
                }
            }
            CheckType::ContentRegex { pattern: _ } if !skip_content => {
                if let Some((_, re)) = compiled.iter().find(|(name, _)| *name == rule.name) {
                    if re.is_match(content) {
                        matches.push(PatternMatch {
                            rule_name: rule.name,
                            tier: rule.tier,
                            message: rule.message,
                        });
                    }
                }
            }
            _ => {} // skip_content was true
        }
    }

    matches
}

/// PreToolUse: Check content for Tier 1 (deny) and Tier 3 (warn) patterns.
///
/// Tier 2 (anti-patterns) is handled by PostToolUse instead, so the write lands
/// and Claude gets a nudge to fix it -- no wasted edits from re-prompting.
///
/// - Tier 1 (secrets): Always deny, never deduped
/// - Tier 3 (informational): Allow with additionalContext, deduped per session
pub fn check_security_reminders(
    tool_name: &str,
    tool_input_map: &serde_json::Map<String, serde_json::Value>,
    config: &SecurityRemindersConfig,
    session_id: &str,
) -> Option<HookOutput> {
    if tool_name == "Read" {
        return None;
    }

    let content_pairs = extract_content(tool_name, tool_input_map);
    if content_pairs.is_empty() {
        return None;
    }

    for (file_path, content) in &content_pairs {
        let matches = scan_content(file_path, content);

        for m in &matches {
            if config.disable_rules.iter().any(|r| r == m.rule_name) {
                continue;
            }

            match m.tier {
                Tier::Deny => {
                    return Some(HookOutput::deny_with_context(
                        &format!("Security: {}", m.rule_name),
                        m.message,
                    ));
                }
                Tier::AskOnce => {
                    // Handled by PostToolUse -- skip in PreToolUse
                    continue;
                }
                Tier::Warn => {
                    let dedup_key = format!("warn-{}", m.rule_name);
                    if !crate::hint_tracker::is_security_warning_new(session_id, &dedup_key) {
                        continue;
                    }
                    return Some(HookOutput::allow_with_context(
                        None,
                        &format!("Security reminder: {}", m.message),
                    ));
                }
            }
        }
    }

    None
}

/// PostToolUse: Check content for Tier 2 (anti-pattern) matches after the write succeeds.
///
/// Returns `Some(PostToolUseOutput)` with additionalContext containing the security
/// warning. Claude sees this as a `<system-reminder>` and can self-correct.
/// Deduped per (file, rule) per session via hint_tracker.
pub fn check_security_reminders_post(
    tool_name: &str,
    tool_input_map: &serde_json::Map<String, serde_json::Value>,
    config: &SecurityRemindersConfig,
    session_id: &str,
) -> Option<PostToolUseOutput> {
    if tool_name == "Read" {
        return None;
    }

    let content_pairs = extract_content(tool_name, tool_input_map);
    if content_pairs.is_empty() {
        return None;
    }

    // Collect all Tier 2 warnings (multiple patterns can match)
    let mut warnings = Vec::new();

    for (file_path, content) in &content_pairs {
        let matches = scan_content(file_path, content);

        for m in &matches {
            if m.tier != Tier::AskOnce {
                continue; // PostToolUse only handles Tier 2
            }
            if config.disable_rules.iter().any(|r| r == m.rule_name) {
                continue;
            }

            let dedup_key = format!("{}-{}", file_path, m.rule_name);
            if !crate::hint_tracker::is_security_warning_new(session_id, &dedup_key) {
                continue;
            }

            warnings.push(format!("**{}**: {}", m.rule_name, m.message));
        }
    }

    if warnings.is_empty() {
        return None;
    }

    let context = format!(
        "Security review of written content:\n\n{}",
        warnings.join("\n\n")
    );
    Some(PostToolUseOutput::with_context(&context))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map(json: &str) -> serde_json::Map<String, serde_json::Value> {
        match serde_json::from_str::<serde_json::Value>(json).unwrap() {
            serde_json::Value::Object(m) => m,
            _ => panic!("expected object"),
        }
    }

    // --- Content extraction tests ---

    #[test]
    fn test_extract_write_content() {
        let map = make_map(r#"{"file_path": "/tmp/f.ts", "content": "eval(input)"}"#);
        let results = extract_content("Write", &map);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "/tmp/f.ts");
        assert_eq!(results[0].1, "eval(input)");
    }

    #[test]
    fn test_extract_edit_classic() {
        let map = make_map(
            r#"{"file_path": "/tmp/f.ts", "old_string": "foo", "new_string": "eval(bar)"}"#,
        );
        let results = extract_content("Edit", &map);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, "eval(bar)");
    }

    #[test]
    fn test_extract_edit_batch() {
        let map = make_map(
            r#"{"file_path": "/tmp/f.ts", "edits": [
            {"old_string": "a", "new_string": "eval(x)"},
            {"old_string": "b", "new_string": "safe()"}
        ]}"#,
        );
        let results = extract_content("Edit", &map);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1, "eval(x)");
        assert_eq!(results[1].1, "safe()");
    }

    #[test]
    fn test_extract_multiedit() {
        let map = make_map(
            r#"{"files": [
            {"file_path": "/tmp/a.ts", "edits": [{"old_string": "x", "new_string": "eval(y)"}]},
            {"file_path": "/tmp/b.py", "edits": [{"old_string": "z", "new_string": "pickle.load(f)"}]}
        ]}"#,
        );
        let results = extract_content("MultiEdit", &map);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "/tmp/a.ts");
        assert_eq!(results[1].0, "/tmp/b.py");
    }

    #[test]
    fn test_extract_empty_content_skipped() {
        let map = make_map(r#"{"file_path": "/tmp/f.ts", "content": ""}"#);
        let results = extract_content("Write", &map);
        assert!(results.is_empty());
    }

    #[test]
    fn test_extract_read_returns_nothing() {
        let map = make_map(r#"{"file_path": "/tmp/f.ts"}"#);
        let results = extract_content("Read", &map);
        assert!(results.is_empty());
    }

    // --- Pattern matching tests ---

    #[test]
    fn test_tier1_aws_key_detected() {
        let content = r#"aws_key = "AKIAIOSFODNN7EXAMPLE""#;
        let matches = scan_content("/tmp/config.py", content);
        assert!(matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"));
        assert!(matches.iter().any(|m| m.tier == Tier::Deny));
    }

    #[test]
    fn test_tier1_private_key_detected() {
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let matches = scan_content("/tmp/deploy.sh", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "hardcoded_private_key")
        );
    }

    #[test]
    fn test_tier1_github_token_detected() {
        let content = r#"token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij""#;
        let matches = scan_content("/tmp/config.ts", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "hardcoded_github_token")
        );
    }

    #[test]
    fn test_tier1_gha_injection_detected() {
        let content = r#"
name: CI
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
"#;
        let matches = scan_content("/project/.github/workflows/ci.yml", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "github_actions_injection")
        );
    }

    #[test]
    fn test_tier1_gha_only_in_workflow_path() {
        // Same content but NOT in .github/workflows/ -- should not match
        let content = r#"run: echo "${{ github.event.pull_request.title }}""#;
        let matches = scan_content("/tmp/notes.txt", content);
        assert!(
            !matches
                .iter()
                .any(|m| m.rule_name == "github_actions_injection")
        );
    }

    #[test]
    fn test_tier2_eval_detected() {
        let content = "const result = eval(userInput);";
        let matches = scan_content("/tmp/app.js", content);
        assert!(matches.iter().any(|m| m.rule_name == "eval_injection"));
        assert!(matches.iter().any(|m| m.tier == Tier::AskOnce));
    }

    #[test]
    fn test_tier2_pickle_detected() {
        let content = "data = pickle.load(open('model.pkl', 'rb'))";
        let matches = scan_content("/tmp/ml.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "pickle_deserialization")
        );
    }

    #[test]
    fn test_tier2_sql_injection_detected() {
        let content = r#"cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")"#;
        let matches = scan_content("/tmp/db.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "sql_string_interpolation")
        );
    }

    #[test]
    fn test_tier2_subprocess_shell_true() {
        let content = "subprocess.run(cmd, shell=True)";
        let matches = scan_content("/tmp/deploy.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "subprocess_shell_true")
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_tier2_innerHTML_detected() {
        let content = "element.innerHTML = userContent;";
        let matches = scan_content("/tmp/app.js", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "inner_html_assignment")
        );
    }

    #[test]
    fn test_tier2_dangerously_set_detected() {
        let content = r#"<div dangerouslySetInnerHTML={{__html: data}} />"#;
        let matches = scan_content("/tmp/App.tsx", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "dangerous_inner_html")
        );
    }

    #[test]
    fn test_tier2_yaml_load_unsafe() {
        let content = "data = yaml.load(f)";
        let matches = scan_content("/tmp/parser.py", content);
        assert!(matches.iter().any(|m| m.rule_name == "unsafe_yaml_load"));
    }

    #[test]
    fn test_tier2_yaml_load_safe_loader_ok() {
        let content = "data = yaml.load(f, Loader=yaml.SafeLoader)";
        let matches = scan_content("/tmp/parser.py", content);
        assert!(!matches.iter().any(|m| m.rule_name == "unsafe_yaml_load"));
    }

    #[test]
    fn test_tier3_ssl_verify_false() {
        let content = "requests.get(url, verify=False)";
        let matches = scan_content("/tmp/api.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "ssl_verification_disabled")
        );
        assert!(matches.iter().any(|m| m.tier == Tier::Warn));
    }

    #[test]
    fn test_tier3_chmod_777() {
        let content = "os.chmod(path, 0o777)";
        let matches = scan_content("/tmp/setup.py", content);
        assert!(matches.iter().any(|m| m.rule_name == "chmod_777"));
    }

    #[test]
    fn test_doc_files_skip_content_checks() {
        let content = "eval(dangerous_stuff); pickle.load(f); .innerHTML = x;";
        let matches = scan_content("/tmp/README.md", content);
        // Content-based rules should NOT fire on .md files
        assert!(matches.is_empty());
    }

    #[test]
    fn test_doc_files_still_get_secret_checks() {
        // Tier 1 secrets should fire even in doc files (they should never appear anywhere)
        let content = r#"Use this key: AKIAIOSFODNN7EXAMPLE"#;
        let matches = scan_content("/tmp/README.md", content);
        assert!(matches.iter().any(|m| m.rule_name == "hardcoded_aws_key"));
    }

    #[test]
    fn test_no_false_positive_on_safe_code() {
        let content = r#"
import subprocess
result = subprocess.run(["git", "status"], capture_output=True)
print(result.stdout)
"#;
        let matches = scan_content("/tmp/safe.py", content);
        assert!(
            matches.is_empty(),
            "Safe subprocess usage should not trigger: {:?}",
            matches
        );
    }

    #[test]
    fn test_generic_secret_patterns() {
        // Stripe key
        let content = r#"stripe_key = "sk-1234567890abcdefghijklmnop""#;
        let matches = scan_content("/tmp/config.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "hardcoded_generic_secret")
        );

        // Slack token
        let content2 = r#"slack_token = "xoxb-1234567890-abcdefgh""#;
        let matches2 = scan_content("/tmp/config.py", content2);
        assert!(
            matches2
                .iter()
                .any(|m| m.rule_name == "hardcoded_generic_secret")
        );
    }

    #[test]
    fn test_tier2_flask_ssti() {
        let content = "return render_template_string(user_input)";
        let matches = scan_content("/tmp/app.py", content);
        assert!(matches.iter().any(|m| m.rule_name == "flask_ssti"));
    }

    #[test]
    fn test_tier2_marshal_deserialization() {
        let content = "data = marshal.load(f)";
        let matches = scan_content("/tmp/loader.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "marshal_deserialization")
        );
    }

    #[test]
    fn test_tier2_shelve_deserialization() {
        let content = "db = shelve.open('data.db')";
        let matches = scan_content("/tmp/store.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "marshal_deserialization")
        );
    }

    #[test]
    fn test_tier2_dynamic_import() {
        let content = "mod = __import__(user_module)";
        let matches = scan_content("/tmp/plugin.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "python_dynamic_import")
        );
    }

    #[test]
    fn test_tier2_php_unserialize() {
        let content = "$obj = unserialize($data);";
        let matches = scan_content("/tmp/handler.php", content);
        assert!(matches.iter().any(|m| m.rule_name == "php_unserialize"));
    }

    #[test]
    fn test_tier3_vue_v_html() {
        let content = r#"<div v-html="userContent"></div>"#;
        let matches = scan_content("/tmp/Component.vue", content);
        assert!(matches.iter().any(|m| m.rule_name == "vue_v_html"));
    }

    #[test]
    fn test_tier3_autoescape_disabled_python() {
        let content = "env = Environment(autoescape=False)";
        let matches = scan_content("/tmp/app.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "template_autoescape_disabled")
        );
    }

    #[test]
    fn test_tier3_autoescape_disabled_yaml() {
        let content = "autoescape: false";
        let matches = scan_content("/tmp/config.yml", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "template_autoescape_disabled")
        );
    }

    // --- Public API tests ---
    //
    // NOTE: Tests that exercise dedup via check_security_reminders use unique
    // session IDs per run. The hint_tracker persists dedup state to disk
    // (~/.cache/tool-gates/hint-tracker.json), so reusing fixed session IDs
    // across cargo test invocations causes state leakage between runs.

    /// Generate a unique session ID for test isolation across runs.
    fn unique_session(base: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{base}-{nanos}")
    }

    #[test]
    fn test_check_security_reminders_deny_on_secret() {
        let map = make_map(
            r#"{"file_path": "/tmp/config.py", "content": "key = \"AKIAIOSFODNN7EXAMPLE\""}"#,
        );
        let config = SecurityRemindersConfig::default();
        let session = unique_session("deny-secret");
        let result = check_security_reminders("Write", &map, &config, &session);
        assert!(result.is_some());
        let json = serde_json::to_string(&result.unwrap()).unwrap();
        assert!(json.contains("deny"), "Secrets should deny: {json}");
    }

    #[test]
    fn test_tier2_skipped_in_pre_tool_use() {
        // Tier 2 patterns should NOT trigger in PreToolUse (handled by PostToolUse)
        let map = make_map(r#"{"file_path": "/tmp/app.js", "content": "eval(input)"}"#);
        let config = SecurityRemindersConfig::default();
        let session = unique_session("pre-skip");
        let result = check_security_reminders("Write", &map, &config, &session);
        assert!(result.is_none(), "Tier 2 should be skipped in PreToolUse");
    }

    #[test]
    fn test_post_tool_use_catches_tier2() {
        let session = unique_session("post-eval");
        let path = format!("/tmp/post-eval-{}.js", session);
        let json_str = format!(r#"{{"file_path": "{path}", "content": "eval(input)"}}"#);
        let map = make_map(&json_str);
        let config = SecurityRemindersConfig::default();
        let result = check_security_reminders_post("Write", &map, &config, &session);
        assert!(result.is_some(), "PostToolUse should catch eval");
        let json = serde_json::to_string(&result.unwrap()).unwrap();
        assert!(
            json.contains("additionalContext"),
            "Should have context: {json}"
        );
        assert!(
            json.contains("eval_injection"),
            "Should mention eval: {json}"
        );
    }

    #[test]
    fn test_post_tool_use_dedup() {
        let session = unique_session("post-dedup");
        let path = format!("/tmp/post-dedup-{}.js", session);
        let json_str = format!(r#"{{"file_path": "{path}", "content": "eval(input)"}}"#);
        let map = make_map(&json_str);
        let config = SecurityRemindersConfig::default();

        let r1 = check_security_reminders_post("Write", &map, &config, &session);
        assert!(r1.is_some(), "First PostToolUse call should warn");

        let r2 = check_security_reminders_post("Write", &map, &config, &session);
        assert!(r2.is_none(), "Second call should be deduped");
    }

    #[test]
    fn test_post_tool_use_collects_multiple_warnings() {
        let session = unique_session("post-multi");
        let path = format!("/tmp/post-multi-{}.js", session);
        let json_str = format!(
            r#"{{"file_path": "{path}", "content": "eval(input); document.write(html);"}}"#
        );
        let map = make_map(&json_str);
        let config = SecurityRemindersConfig::default();
        let result = check_security_reminders_post("Write", &map, &config, &session);
        assert!(result.is_some());
        let json = serde_json::to_string(&result.unwrap()).unwrap();
        assert!(json.contains("eval_injection"), "Should have eval: {json}");
        assert!(
            json.contains("document_write_xss"),
            "Should have document.write: {json}"
        );
    }

    #[test]
    fn test_post_tool_use_ignores_tier1_and_tier3() {
        // Tier 1 secrets and Tier 3 warns should NOT appear in PostToolUse
        let map = make_map(
            r#"{"file_path": "/tmp/api.py", "content": "requests.get(url, verify=False)"}"#,
        );
        let config = SecurityRemindersConfig::default();
        let session = unique_session("post-tier3");
        let result = check_security_reminders_post("Write", &map, &config, &session);
        assert!(result.is_none(), "Tier 3 should not fire in PostToolUse");
    }

    #[test]
    fn test_post_tool_use_disabled_rule() {
        let map = make_map(r#"{"file_path": "/tmp/app.js", "content": "eval(input)"}"#);
        let config = SecurityRemindersConfig {
            disable_rules: vec!["eval_injection".to_string()],
        };
        let session = unique_session("post-disabled");
        let result = check_security_reminders_post("Write", &map, &config, &session);
        assert!(
            result.is_none(),
            "Disabled rule should not fire in PostToolUse"
        );
    }

    #[test]
    fn test_tier3_produces_allow_with_context() {
        // Test the scan_content output directly (no global tracker involvement)
        let content = "requests.get(url, verify=False)";
        let matches = scan_content("/tmp/api.py", content);
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "ssl_verification_disabled" && m.tier == Tier::Warn),
            "Should detect SSL verification disabled as Warn tier"
        );
    }

    #[test]
    fn test_check_security_reminders_disabled_tier1_skipped() {
        let map = make_map(
            r#"{"file_path": "/tmp/config.py", "content": "key = \"AKIAIOSFODNN7EXAMPLE\""}"#,
        );
        let config = SecurityRemindersConfig {
            disable_rules: vec!["hardcoded_aws_key".to_string()],
        };
        let session = unique_session("disabled");
        let result = check_security_reminders("Write", &map, &config, &session);
        assert!(result.is_none(), "Disabled Tier 1 rule should not fire");
    }

    #[test]
    fn test_check_security_reminders_safe_content_passes() {
        let map = make_map(r#"{"file_path": "/tmp/app.ts", "content": "const x = 1 + 2;"}"#);
        let config = SecurityRemindersConfig::default();
        let session = unique_session("safe");
        let result = check_security_reminders("Write", &map, &config, &session);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_security_reminders_read_skipped() {
        let map = make_map(r#"{"file_path": "/tmp/config.py", "content": "AKIAIOSFODNN7EXAMPLE"}"#);
        let config = SecurityRemindersConfig::default();
        let session = unique_session("read");
        let result = check_security_reminders("Read", &map, &config, &session);
        assert!(result.is_none(), "Read tool should be skipped entirely");
    }

    #[test]
    fn test_tier1_secrets_never_deduped() {
        let map = make_map(r#"{"file_path": "/tmp/config.py", "content": "AKIAIOSFODNN7EXAMPLE"}"#);
        let config = SecurityRemindersConfig::default();
        let session = unique_session("secret-dedup");

        let r1 = check_security_reminders("Write", &map, &config, &session);
        assert!(r1.is_some(), "First secret call should deny");

        let r2 = check_security_reminders("Write", &map, &config, &session);
        assert!(
            r2.is_some(),
            "Second secret call should ALSO deny (never deduped)"
        );
    }
}
