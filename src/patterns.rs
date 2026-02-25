//! Pattern suggestion for commands that return "ask".
//!
//! Generates appropriate patterns for settings.json based on command structure.

use crate::models::CommandInfo;

/// Generate suggested approval patterns for a command.
///
/// Returns patterns from most specific to most broad.
pub fn suggest_patterns(cmd: &CommandInfo) -> Vec<String> {
    let mut patterns = Vec::new();

    // Package managers - suggest subcommand-specific first
    match cmd.program.as_str() {
        "npm" | "pnpm" | "yarn" | "bun" => {
            // npm run <script> → "npm run script", "npm run:*", "npm:*"
            if let Some(subcmd) = cmd.args.first() {
                if subcmd == "run" || subcmd == "exec" {
                    if let Some(script) = cmd.args.get(1) {
                        patterns.push(format!("{} {} {}", cmd.program, subcmd, script));
                        // For nested scripts like "test:unit", also suggest "test*" prefix
                        if let Some(prefix) = script.split(':').next() {
                            if prefix != script {
                                patterns.push(format!("{} {} {}*", cmd.program, subcmd, prefix)); // glob: match test:unit, test:e2e etc.
                            }
                        }
                    }
                    patterns.push(format!("{} {}:*", cmd.program, subcmd));
                } else if subcmd == "install" || subcmd == "add" || subcmd == "remove" {
                    // npm install <pkg> → "npm install pkg", "npm install:*"
                    if let Some(pkg) = cmd.args.get(1) {
                        if !pkg.starts_with('-') {
                            patterns.push(format!("{} {} {}", cmd.program, subcmd, pkg));
                        }
                    }
                    patterns.push(format!("{} {}:*", cmd.program, subcmd));
                } else {
                    patterns.push(format!("{} {}:*", cmd.program, subcmd));
                }
            }
            patterns.push(format!("{}:*", cmd.program));
        }

        // Cargo - similar to package managers
        "cargo" => {
            if let Some(subcmd) = cmd.args.first() {
                patterns.push(format!("cargo {}:*", subcmd));
            }
            patterns.push("cargo:*".to_string());
        }

        // pip/uv/poetry
        "pip" | "pip3" | "uv" | "poetry" => {
            if let Some(subcmd) = cmd.args.first() {
                patterns.push(format!("{} {}:*", cmd.program, subcmd));
            }
            patterns.push(format!("{}:*", cmd.program));
        }

        // mise tasks
        "mise" => {
            if cmd.args.first() == Some(&"run".to_string()) {
                if let Some(task) = cmd.args.get(1) {
                    patterns.push(format!("mise run {}", task));
                }
                patterns.push("mise run:*".to_string());
            } else if let Some(task) = cmd.args.first() {
                // mise <task> shorthand
                patterns.push(format!("mise {}", task));
            }
            patterns.push("mise:*".to_string());
        }

        // Git - subcommand patterns
        "git" => {
            if let Some(subcmd) = cmd.args.first() {
                // git commit with message patterns
                if subcmd == "commit" || subcmd == "push" || subcmd == "pull" {
                    patterns.push(format!("git {}:*", subcmd));
                }
                // git checkout/switch with branch
                else if subcmd == "checkout" || subcmd == "switch" {
                    if let Some(branch) = cmd.args.get(1) {
                        if !branch.starts_with('-') {
                            patterns.push(format!("git {} {}", subcmd, branch));
                        }
                    }
                    patterns.push(format!("git {}:*", subcmd));
                } else {
                    patterns.push(format!("git {}:*", subcmd));
                }
            }
            // Don't suggest "git*" - too broad for a version control system
        }

        // Cloud CLIs - be specific
        "aws" | "gcloud" | "az" | "kubectl" | "docker" | "terraform" | "pulumi" => {
            // aws ec2 describe-instances → "aws ec2 describe:*", "aws ec2:*"
            if cmd.args.len() >= 2 {
                let service = &cmd.args[0];
                let action = &cmd.args[1];
                if action.contains('-') {
                    let prefix = action.split('-').next().unwrap_or(action);
                    patterns.push(format!("{} {} {}:*", cmd.program, service, prefix));
                }
                patterns.push(format!("{} {}:*", cmd.program, service));
            } else if let Some(subcmd) = cmd.args.first() {
                patterns.push(format!("{} {}:*", cmd.program, subcmd));
            }
        }

        // GitHub CLI
        "gh" => {
            if let Some(subcmd) = cmd.args.first() {
                if let Some(action) = cmd.args.get(1) {
                    patterns.push(format!("gh {} {}", subcmd, action));
                }
                patterns.push(format!("gh {}:*", subcmd));
            }
            patterns.push("gh:*".to_string());
        }

        // Formatters/linters - suggest the tool name
        "prettier" | "eslint" | "biome" | "ruff" | "black" | "rustfmt" | "gofmt" | "shfmt" => {
            patterns.push(format!("{}:*", cmd.program));
        }

        // sd (text replacement) - be careful, suggest exact or with args
        "sd" => {
            // sd with file args is a write operation, suggest program-level
            patterns.push("sd:*".to_string());
        }

        // curl/wget with specific patterns
        "curl" | "wget" | "xh" | "http" => {
            // For API calls, might want to approve specific URLs
            if let Some(url_arg) = cmd.args.iter().find(|a| a.starts_with("http")) {
                // Extract domain
                if let Some(domain) = extract_domain(url_arg) {
                    patterns.push(format!("{} *{}*", cmd.program, domain));
                }
            }
            patterns.push(format!("{}:*", cmd.program));
        }

        // Default case - program + first subcommand if exists
        _ => {
            if let Some(first_arg) = cmd.args.first() {
                if !first_arg.starts_with('-') {
                    patterns.push(format!("{} {}:*", cmd.program, first_arg));
                }
            }
            patterns.push(format!("{}:*", cmd.program));
        }
    }

    // Deduplicate while preserving order
    let mut seen = std::collections::HashSet::new();
    patterns.retain(|p| seen.insert(p.clone()));

    patterns
}

/// Extract domain from a URL
fn extract_domain(url: &str) -> Option<String> {
    // Simple extraction - strip protocol and path
    let without_proto = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    // Strip any userinfo (credentials) for security
    let without_userinfo = if let Some(at_pos) = without_proto.find('@') {
        &without_proto[at_pos + 1..]
    } else {
        without_proto
    };

    without_userinfo.split('/').next().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(program: &str, args: &[&str]) -> CommandInfo {
        CommandInfo {
            raw: format!("{} {}", program, args.join(" ")),
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_npm_install_patterns() {
        let patterns = suggest_patterns(&cmd("npm", &["install", "lodash"]));
        assert!(patterns.contains(&"npm install lodash".to_string()));
        assert!(patterns.contains(&"npm install:*".to_string()));
        assert!(patterns.contains(&"npm:*".to_string()));
    }

    #[test]
    fn test_npm_run_patterns() {
        let patterns = suggest_patterns(&cmd("npm", &["run", "test"]));
        assert!(patterns.contains(&"npm run test".to_string()));
        assert!(patterns.contains(&"npm run:*".to_string()));
    }

    #[test]
    fn test_npm_run_nested_script_patterns() {
        // Nested scripts like "test:unit" should suggest "test*" prefix pattern
        let patterns = suggest_patterns(&cmd("npm", &["run", "test:unit"]));
        assert!(patterns.contains(&"npm run test:unit".to_string()));
        assert!(patterns.contains(&"npm run test*".to_string())); // glob: match test:unit etc.
        assert!(patterns.contains(&"npm run:*".to_string()));
    }

    #[test]
    fn test_mise_task_patterns() {
        let patterns = suggest_patterns(&cmd("mise", &["run", "lint"]));
        assert!(patterns.contains(&"mise run lint".to_string()));
        assert!(patterns.contains(&"mise run:*".to_string()));
    }

    #[test]
    fn test_gh_patterns() {
        let patterns = suggest_patterns(&cmd("gh", &["pr", "create"]));
        assert!(patterns.contains(&"gh pr create".to_string()));
        assert!(patterns.contains(&"gh pr:*".to_string()));
    }

    #[test]
    fn test_aws_patterns() {
        let patterns = suggest_patterns(&cmd("aws", &["ec2", "describe-instances"]));
        assert!(patterns.contains(&"aws ec2 describe:*".to_string()));
        assert!(patterns.contains(&"aws ec2:*".to_string()));
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain("https://api.github.com/repos"),
            Some("api.github.com".to_string())
        );
        assert_eq!(
            extract_domain("http://localhost:3000/api"),
            Some("localhost:3000".to_string())
        );
    }

    #[test]
    fn test_extract_domain_strips_credentials() {
        // URL with userinfo should strip credentials
        assert_eq!(
            extract_domain("https://user:password@api.github.com/repos"),
            Some("api.github.com".to_string())
        );
        assert_eq!(
            extract_domain("http://secret@localhost:3000/api"),
            Some("localhost:3000".to_string())
        );
    }
}
