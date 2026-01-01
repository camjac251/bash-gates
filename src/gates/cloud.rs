//! Cloud CLI permission gates (AWS, gcloud, az, terraform, kubectl, docker, podman).
//!
//! Mostly declarative via rules/cloud.toml, with custom handlers for:
//!
//! 1. `check_gcloud` - gcloud uses 3-word patterns: `gcloud <service> <resource> <action>`
//!    The action (3rd word) determines read vs write. TOML only handles 2-word subcommands.
//!
//! 2. `check_docker` - docker compose accepts flags between "compose" and the actual
//!    subcommand (e.g., `docker compose -f x.yml config`). Custom logic skips flags
//!    to find the real subcommand.
//!
//! 3. `check_kubectl` - 3-word block patterns like `delete namespace kube-system`.
//!    The generated declarative code handles 2-word blocks, but 3-word blocks
//!    require explicit checking.
//!
//! Everything else (AWS, Azure, Terraform, Helm, Pulumi, Podman) is fully declarative.

use crate::generated::rules::{
    check_aws_declarative, check_az_declarative, check_docker_compose_declarative,
    check_docker_declarative, check_gcloud_declarative, check_helm_declarative,
    check_kubectl_declarative, check_podman_declarative, check_pulumi_declarative,
    check_terraform_declarative,
};
use crate::models::{CommandInfo, GateResult};

/// Route to appropriate cloud provider gate.
pub fn check_cloud(cmd: &CommandInfo) -> GateResult {
    // Strip path prefix to handle /usr/bin/aws etc.
    let program = cmd.program.rsplit('/').next().unwrap_or(&cmd.program);
    match program {
        "aws" => check_aws(cmd),
        "gcloud" => check_gcloud(cmd),
        "az" => check_az_declarative(cmd).unwrap_or_else(|| {
            GateResult::ask(format!(
                "az: {}",
                cmd.args.first().unwrap_or(&"unknown".to_string())
            ))
        }),
        "terraform" | "tofu" => check_terraform_declarative(cmd).unwrap_or_else(|| {
            GateResult::ask(format!(
                "terraform: {}",
                cmd.args.first().unwrap_or(&"unknown".to_string())
            ))
        }),
        "kubectl" | "k" => check_kubectl(cmd),
        "docker" => check_docker(cmd),
        "podman" => check_podman_declarative(cmd).unwrap_or_else(|| {
            GateResult::ask(format!(
                "podman: {}",
                cmd.args.first().unwrap_or(&"unknown".to_string())
            ))
        }),
        "docker-compose" | "podman-compose" => check_docker_compose_declarative(cmd)
            .unwrap_or_else(|| {
                GateResult::ask(format!(
                    "docker-compose: {}",
                    cmd.args.first().unwrap_or(&"unknown".to_string())
                ))
            }),
        "pulumi" => check_pulumi_declarative(cmd).unwrap_or_else(|| {
            GateResult::ask(format!(
                "pulumi: {}",
                cmd.args.first().unwrap_or(&"unknown".to_string())
            ))
        }),
        "helm" => check_helm_declarative(cmd).unwrap_or_else(|| {
            GateResult::ask(format!(
                "helm: {}",
                cmd.args.first().unwrap_or(&"unknown".to_string())
            ))
        }),
        _ => GateResult::skip(),
    }
}

/// AWS uses declarative rules with action_prefix for prefix matching.
/// The action_prefix field matches args[1] (the action in `aws <service> <action>`).
fn check_aws(cmd: &CommandInfo) -> GateResult {
    check_aws_declarative(cmd).unwrap_or_else(|| {
        GateResult::ask(format!(
            "aws: {}",
            cmd.args.first().unwrap_or(&"unknown".to_string())
        ))
    })
}

/// gcloud needs custom handling for 3-word patterns.
fn check_gcloud(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Less than 3 args - try declarative (handles config list, auth list, etc.)
    if args.len() < 3 {
        return check_gcloud_declarative(cmd).unwrap_or_else(|| {
            GateResult::ask(format!(
                "gcloud: {}",
                args.first().unwrap_or(&"unknown".to_string())
            ))
        });
    }

    // 3+ args - check the action (3rd word)
    let action = args[2].as_str();

    // Read actions
    let read_actions = ["list", "describe", "get"];
    if read_actions.contains(&action) {
        return GateResult::allow();
    }

    // Write actions
    let write_actions = ["create", "delete", "update", "deploy", "start", "stop"];
    if write_actions.contains(&action) {
        return GateResult::ask(format!("gcloud: {} {} {}", args[0], args[1], action));
    }

    GateResult::ask(format!("gcloud: {} {} {}", args[0], args[1], action))
}

/// docker compose needs custom handling because flags can appear between
/// "compose" and the actual subcommand (e.g., docker compose -f x.yml config).
fn check_docker(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;

    // Handle docker compose subcommand
    if args.first().map(String::as_str) == Some("compose") {
        // Find the actual compose subcommand (skip flags)
        let mut subcommand: Option<&str> = None;
        let mut i = 1;
        while i < args.len() {
            let arg = args[i].as_str();
            // Skip flags
            if arg.starts_with('-') {
                i += 1;
                // Skip flag values for known flags that take values
                if i < args.len()
                    && matches!(
                        arg,
                        "-f" | "--file"
                            | "-p"
                            | "--project-name"
                            | "--project-directory"
                            | "--profile"
                            | "--env-file"
                    )
                {
                    i += 1;
                }
                continue;
            }
            subcommand = Some(arg);
            break;
        }

        if let Some(subcmd) = subcommand {
            // Check compose subcommand permissions
            return match subcmd {
                // Read-only
                "ps" | "logs" | "config" | "images" | "ls" | "version" | "top" | "events" => {
                    GateResult::allow()
                }
                // Write commands
                "up" | "down" | "start" | "stop" | "restart" | "build" | "pull" | "push"
                | "exec" | "run" | "rm" | "create" | "kill" | "pause" | "unpause" | "scale"
                | "attach" | "cp" => GateResult::ask(format!("docker compose: {}", subcmd)),
                _ => GateResult::ask(format!("docker compose: {}", subcmd)),
            };
        }
        return GateResult::ask("docker: compose");
    }

    // Use declarative rules for other docker commands
    check_docker_declarative(cmd).unwrap_or_else(|| {
        GateResult::ask(format!(
            "docker: {}",
            args.first().unwrap_or(&"unknown".to_string())
        ))
    })
}

/// kubectl needs custom handling for 3-word block patterns.
/// Generated declarative rules only handle 2-word subcommands.
fn check_kubectl(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    // Check 3-word block patterns (delete namespace kube-system, delete ns kube-system)
    if args.len() >= 3 {
        let three_word = format!("{} {} {}", args[0], args[1], args[2]);
        if three_word == "delete namespace kube-system" || three_word == "delete ns kube-system" {
            return GateResult::block("kubectl: Cannot delete kube-system");
        }
    }

    // Use declarative rules for everything else
    check_kubectl_declarative(cmd).unwrap_or_else(|| {
        GateResult::ask(format!(
            "kubectl: {}",
            args.first().unwrap_or(&"unknown".to_string())
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd as make_cmd;
    use crate::models::Decision;

    fn aws(args: &[&str]) -> CommandInfo {
        make_cmd("aws", args)
    }

    fn kubectl(args: &[&str]) -> CommandInfo {
        make_cmd("kubectl", args)
    }

    fn docker(args: &[&str]) -> CommandInfo {
        make_cmd("docker", args)
    }

    fn terraform(args: &[&str]) -> CommandInfo {
        make_cmd("terraform", args)
    }

    fn gcloud(args: &[&str]) -> CommandInfo {
        make_cmd("gcloud", args)
    }

    // === AWS ===

    #[test]
    fn test_aws_read_allows() {
        let read_cmds = [
            &["--version"][..],
            &["s3", "ls"],
            &["sts", "get-caller-identity"],
            &["ec2", "describe-instances"],
            &["iam", "list-users"],
        ];

        for args in read_cmds {
            let result = check_cloud(&aws(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_aws_write_asks() {
        let write_cmds = [
            &["s3", "cp", "file", "s3://bucket/"][..],
            &["ec2", "run-instances"],
            &["iam", "create-user"],
        ];

        for args in write_cmds {
            let result = check_cloud(&aws(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_aws_blocked() {
        let result = check_cloud(&aws(&["iam", "delete-user", "someone"]));
        assert_eq!(result.decision, Decision::Block);
    }

    // === Terraform ===

    #[test]
    fn test_terraform_read_allows() {
        let read_cmds = [
            &["plan"][..],
            &["show"],
            &["state", "list"],
            &["validate"],
            &["fmt", "-check"],
        ];

        for args in read_cmds {
            let result = check_cloud(&terraform(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_terraform_write_asks() {
        let write_cmds = [&["apply"][..], &["destroy"], &["init"], &["fmt"]];

        for args in write_cmds {
            let result = check_cloud(&terraform(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
        }
    }

    // === kubectl ===

    #[test]
    fn test_kubectl_read_allows() {
        let read_cmds = [
            &["get", "pods"][..],
            &["describe", "pod", "foo"],
            &["logs", "pod-name"],
            &["config", "view"],
        ];

        for args in read_cmds {
            let result = check_cloud(&kubectl(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_kubectl_write_asks() {
        let write_cmds = [
            &["apply", "-f", "file.yaml"][..],
            &["delete", "pod", "foo"],
            &["exec", "-it", "pod", "--", "bash"],
        ];

        for args in write_cmds {
            let result = check_cloud(&kubectl(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_kubectl_kube_system_blocked() {
        let blocked_cmds = [
            &["delete", "namespace", "kube-system"][..],
            &["delete", "ns", "kube-system"],
        ];

        for args in blocked_cmds {
            let result = check_cloud(&kubectl(args));
            assert_eq!(result.decision, Decision::Block, "Failed for: {args:?}");
        }
    }

    // === Docker ===

    #[test]
    fn test_docker_read_allows() {
        let read_cmds = [
            &["ps"][..],
            &["images"],
            &["logs", "container"],
            &["inspect", "container"],
        ];

        for args in read_cmds {
            let result = check_cloud(&docker(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_docker_write_asks() {
        let write_cmds = [
            &["run", "image"][..],
            &["build", "."],
            &["push", "image"],
            &["rm", "container"],
        ];

        for args in write_cmds {
            let result = check_cloud(&docker(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
        }
    }

    // === gcloud ===

    #[test]
    fn test_gcloud_read_allows() {
        let read_cmds = [
            &["--version"][..],
            &["config", "list"],
            &["compute", "instances", "list"],
        ];

        for args in read_cmds {
            let result = check_cloud(&gcloud(args));
            assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
        }
    }

    #[test]
    fn test_gcloud_write_asks() {
        let write_cmds = [
            &["compute", "instances", "create", "vm"][..],
            &["compute", "instances", "delete", "vm"],
        ];

        for args in write_cmds {
            let result = check_cloud(&gcloud(args));
            assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
        }
    }

    // === Non-cloud ===

    #[test]
    fn test_non_cloud_skips() {
        let result = check_cloud(&make_cmd("git", &["status"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}
