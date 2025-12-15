//! Cloud CLI permission gates (AWS, gcloud, az, terraform, kubectl, docker, podman).

use crate::models::{CommandInfo, GateResult};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// Route to appropriate cloud provider gate.
pub fn check_cloud(cmd: &CommandInfo) -> GateResult {
    match cmd.program.as_str() {
        "aws" => check_aws(cmd),
        "gcloud" => check_gcloud(cmd),
        "az" => check_az(cmd),
        "terraform" | "tofu" => check_terraform(cmd),
        "kubectl" | "k" => check_kubectl(cmd),
        "docker" => check_docker(cmd),
        "podman" => check_podman(cmd),
        "docker-compose" | "podman-compose" => check_docker_compose(cmd),
        "pulumi" => check_pulumi(cmd),
        "helm" => check_helm(cmd),
        _ => GateResult::skip(),
    }
}

// === AWS ===

static AWS_READ_COMMANDS: LazyLock<HashSet<(&str, &str)>> = LazyLock::new(|| {
    [
        ("s3", "ls"),
        ("sts", "get-caller-identity"),
        ("sts", "get-session-token"),
        ("configure", "list"),
    ]
    .into_iter()
    .collect()
});

static AWS_READ_SINGLE: LazyLock<HashSet<&str>> =
    LazyLock::new(|| ["--version", "help"].into_iter().collect());

static AWS_READ_PREFIXES: LazyLock<HashSet<(&str, &str)>> = LazyLock::new(|| {
    [
        ("ec2", "describe"),
        ("iam", "get"),
        ("iam", "list"),
        ("s3api", "get"),
        ("s3api", "head"),
        ("s3api", "list"),
        ("lambda", "get"),
        ("lambda", "list"),
        ("logs", "describe"),
        ("logs", "filter"),
        ("logs", "get"),
        ("cloudformation", "describe"),
        ("cloudformation", "list"),
        ("cloudformation", "get"),
        ("cloudwatch", "describe"),
        ("cloudwatch", "get"),
        ("cloudwatch", "list"),
        ("rds", "describe"),
        ("dynamodb", "describe"),
        ("dynamodb", "list"),
        ("dynamodb", "get"),
        ("dynamodb", "query"),
        ("dynamodb", "scan"),
        ("sqs", "get"),
        ("sqs", "list"),
        ("sns", "get"),
        ("sns", "list"),
        ("route53", "get"),
        ("route53", "list"),
        ("elb", "describe"),
        ("elbv2", "describe"),
        ("autoscaling", "describe"),
        ("eks", "describe"),
        ("eks", "list"),
        ("ecr", "describe"),
        ("ecr", "get"),
        ("ecr", "list"),
        ("ecr", "batch-get"),
        ("secretsmanager", "describe"),
        ("secretsmanager", "list"),
        ("secretsmanager", "get-secret"),
        ("ssm", "describe"),
        ("ssm", "get"),
        ("ssm", "list"),
        ("kms", "describe"),
        ("kms", "list"),
        ("kms", "get"),
    ]
    .into_iter()
    .collect()
});

static AWS_BLOCKED: &[(&str, &str, &str)] = &[
    ("iam", "delete-user", "Deleting IAM users is blocked"),
    ("organizations", "delete", "Organization deletion blocked"),
];

static AWS_WRITE_PREFIXES: LazyLock<HashMap<(&str, &str), &str>> = LazyLock::new(|| {
    [
        (("s3", "cp"), "S3 copy"),
        (("s3", "mv"), "S3 move"),
        (("s3", "rm"), "S3 delete"),
        (("s3", "sync"), "S3 sync"),
        (("s3", "mb"), "S3 create bucket"),
        (("s3", "rb"), "S3 delete bucket"),
        (("s3api", "put"), "S3 API put"),
        (("s3api", "delete"), "S3 API delete"),
        (("s3api", "create"), "S3 API create"),
        (("ec2", "run"), "EC2 run"),
        (("ec2", "start"), "EC2 start"),
        (("ec2", "stop"), "EC2 stop"),
        (("ec2", "terminate"), "EC2 terminate"),
        (("ec2", "create"), "EC2 create"),
        (("ec2", "delete"), "EC2 delete"),
        (("ec2", "modify"), "EC2 modify"),
        (("iam", "create"), "IAM create"),
        (("iam", "delete"), "IAM delete"),
        (("iam", "update"), "IAM update"),
        (("iam", "put"), "IAM put"),
        (("iam", "attach"), "IAM attach"),
        (("iam", "detach"), "IAM detach"),
        (("lambda", "create"), "Lambda create"),
        (("lambda", "delete"), "Lambda delete"),
        (("lambda", "update"), "Lambda update"),
        (("lambda", "publish"), "Lambda publish"),
        (("lambda", "invoke"), "Lambda invoke"),
        (("cloudformation", "create"), "CloudFormation create"),
        (("cloudformation", "update"), "CloudFormation update"),
        (("cloudformation", "delete"), "CloudFormation delete"),
        (("rds", "create"), "RDS create"),
        (("rds", "delete"), "RDS delete"),
        (("rds", "modify"), "RDS modify"),
        (("rds", "start"), "RDS start"),
        (("rds", "stop"), "RDS stop"),
        (("rds", "reboot"), "RDS reboot"),
        (("dynamodb", "create"), "DynamoDB create"),
        (("dynamodb", "delete"), "DynamoDB delete"),
        (("dynamodb", "update"), "DynamoDB update"),
        (("dynamodb", "put"), "DynamoDB put"),
        (("dynamodb", "batch-write"), "DynamoDB batch write"),
        (("sqs", "create"), "SQS create"),
        (("sqs", "delete"), "SQS delete"),
        (("sqs", "send"), "SQS send"),
        (("sqs", "purge"), "SQS purge"),
        (("sns", "create"), "SNS create"),
        (("sns", "delete"), "SNS delete"),
        (("sns", "publish"), "SNS publish"),
        (("sns", "subscribe"), "SNS subscribe"),
        (("eks", "create"), "EKS create"),
        (("eks", "delete"), "EKS delete"),
        (("eks", "update"), "EKS update"),
        (("ecr", "create"), "ECR create"),
        (("ecr", "delete"), "ECR delete"),
        (("ecr", "put"), "ECR put"),
        (("ecr", "batch-delete"), "ECR batch delete"),
        (("secretsmanager", "create"), "Secrets create"),
        (("secretsmanager", "delete"), "Secrets delete"),
        (("secretsmanager", "put"), "Secrets put"),
        (("secretsmanager", "update"), "Secrets update"),
        (("secretsmanager", "rotate"), "Secrets rotate"),
    ]
    .into_iter()
    .collect()
});

fn check_aws(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    // Check single-arg read commands
    if args.len() == 1 && AWS_READ_SINGLE.contains(args[0].as_str()) {
        return GateResult::allow();
    }

    // Check blocked
    if args.len() >= 2 {
        for (svc, action, reason) in AWS_BLOCKED {
            if args[0] == *svc && args[1].starts_with(action) {
                return GateResult::block(*reason);
            }
        }
    }

    // Check exact read commands
    if args.len() >= 2 && AWS_READ_COMMANDS.contains(&(args[0].as_str(), args[1].as_str())) {
        return GateResult::allow();
    }

    // Check read prefixes
    if args.len() >= 2 {
        for (svc, prefix) in AWS_READ_PREFIXES.iter() {
            if args[0] == *svc && args[1].starts_with(prefix) {
                return GateResult::allow();
            }
        }
    }

    // Check write patterns
    if args.len() >= 2 {
        for ((svc, prefix), action) in AWS_WRITE_PREFIXES.iter() {
            if args[0] == *svc && args[1].starts_with(prefix) {
                return GateResult::ask(format!("AWS: {action}"));
            }
        }
    }

    GateResult::ask("AWS: Unknown command")
}

// === GCLOUD ===

static GCLOUD_READ: LazyLock<HashSet<Vec<&str>>> = LazyLock::new(|| {
    [
        vec!["config", "list"],
        vec!["config", "get-value"],
        vec!["auth", "list"],
        vec!["auth", "describe"],
        vec!["projects", "list"],
        vec!["projects", "describe"],
        vec!["compute", "instances", "list"],
        vec!["compute", "instances", "describe"],
        vec!["compute", "zones", "list"],
        vec!["compute", "regions", "list"],
        vec!["compute", "machine-types", "list"],
        vec!["container", "clusters", "list"],
        vec!["container", "clusters", "describe"],
        vec!["container", "clusters", "get-credentials"],
        vec!["storage", "ls"],
        vec!["storage", "cat"],
        vec!["functions", "list"],
        vec!["functions", "describe"],
        vec!["functions", "logs"],
        vec!["run", "services", "list"],
        vec!["run", "services", "describe"],
        vec!["sql", "instances", "list"],
        vec!["sql", "instances", "describe"],
        vec!["logging", "read"],
        vec!["iam", "list"],
        vec!["iam", "describe"],
        vec!["secrets", "list"],
        vec!["secrets", "describe"],
        vec!["secrets", "versions"],
        vec!["--version"],
        vec!["help"],
        vec!["info"],
    ]
    .into_iter()
    .collect()
});

static GCLOUD_WRITE: LazyLock<HashMap<Vec<&str>, &str>> = LazyLock::new(|| {
    [
        (vec!["compute", "instances", "create"], "Compute create"),
        (vec!["compute", "instances", "delete"], "Compute delete"),
        (vec!["compute", "instances", "start"], "Compute start"),
        (vec!["compute", "instances", "stop"], "Compute stop"),
        (vec!["compute", "instances", "reset"], "Compute reset"),
        (vec!["container", "clusters", "create"], "GKE create"),
        (vec!["container", "clusters", "delete"], "GKE delete"),
        (vec!["container", "clusters", "resize"], "GKE resize"),
        (vec!["container", "clusters", "upgrade"], "GKE upgrade"),
        (vec!["storage", "cp"], "Storage copy"),
        (vec!["storage", "mv"], "Storage move"),
        (vec!["storage", "rm"], "Storage delete"),
        (vec!["functions", "deploy"], "Functions deploy"),
        (vec!["functions", "delete"], "Functions delete"),
        (vec!["run", "deploy"], "Cloud Run deploy"),
        (vec!["run", "services", "delete"], "Cloud Run delete"),
        (vec!["sql", "instances", "create"], "Cloud SQL create"),
        (vec!["sql", "instances", "delete"], "Cloud SQL delete"),
        (vec!["sql", "instances", "patch"], "Cloud SQL patch"),
        (vec!["secrets", "create"], "Secrets create"),
        (vec!["secrets", "delete"], "Secrets delete"),
        (vec!["projects", "create"], "Project create"),
        (vec!["projects", "delete"], "Project delete"),
    ]
    .into_iter()
    .collect()
});

fn check_gcloud(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let args_str: Vec<&str> = args.iter().map(std::string::String::as_str).collect();

    // Check read commands
    for read_cmd in GCLOUD_READ.iter() {
        if args_str.len() >= read_cmd.len() && args_str[..read_cmd.len()] == read_cmd[..] {
            return GateResult::allow();
        }
    }

    // Check write commands
    for (write_cmd, action) in GCLOUD_WRITE.iter() {
        if args_str.len() >= write_cmd.len() && args_str[..write_cmd.len()] == write_cmd[..] {
            return GateResult::ask(format!("gcloud: {action}"));
        }
    }

    GateResult::ask("gcloud: Unknown command")
}

// === AZ (Azure) ===

fn check_az(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let first = args[0].as_str();
    let second = args.get(1).map(std::string::String::as_str);

    // Help/version
    if matches!(first, "--version" | "--help" | "-h") {
        return GateResult::allow();
    }

    // Read operations
    if matches!(second, Some("list" | "show")) {
        return GateResult::allow();
    }

    // Write operations
    if matches!(
        second,
        Some("create" | "delete" | "update" | "start" | "stop" | "restart")
    ) {
        return GateResult::ask(format!("az: {} {}", first, second.unwrap_or("")));
    }

    GateResult::ask("az: Unknown command")
}

// === TERRAFORM ===

static TERRAFORM_READ: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "plan",
        "show",
        "output",
        "validate",
        "version",
        "providers",
        "graph",
        "-version",
        "--version",
        "-help",
        "--help",
    ]
    .into_iter()
    .collect()
});

static TERRAFORM_WRITE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("apply", "Applying changes"),
        ("destroy", "Destroying infrastructure"),
        ("import", "Importing resource"),
        ("taint", "Tainting resource"),
        ("untaint", "Untainting resource"),
        ("init", "Initializing"),
        ("fmt", "Formatting files"),
    ]
    .into_iter()
    .collect()
});

fn check_terraform(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let subcommand = args[0].as_str();

    // state commands
    if subcommand == "state" && args.len() >= 2 {
        match args[1].as_str() {
            "list" | "show" => return GateResult::allow(),
            sub => return GateResult::ask(format!("Terraform: state {sub}")),
        }
    }

    // workspace commands
    if subcommand == "workspace" && args.len() >= 2 {
        if args[1] == "list" {
            return GateResult::allow();
        }
        return GateResult::ask(format!("Terraform: workspace {}", args[1]));
    }

    // fmt -check is read-only
    if subcommand == "fmt" && args.iter().any(|a| a == "-check") {
        return GateResult::allow();
    }

    if TERRAFORM_READ.contains(subcommand) {
        return GateResult::allow();
    }

    if let Some(reason) = TERRAFORM_WRITE.get(subcommand) {
        return GateResult::ask(format!("Terraform: {reason}"));
    }

    GateResult::ask("Terraform: Unknown command")
}

// === KUBECTL ===

static KUBECTL_READ: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "get",
        "describe",
        "logs",
        "top",
        "explain",
        "api-resources",
        "api-versions",
        "cluster-info",
        "version",
        "-h",
        "--help",
    ]
    .into_iter()
    .collect()
});

static KUBECTL_BLOCKED: &[(&[&str], &str)] = &[
    (
        &["delete", "namespace", "kube-system"],
        "Cannot delete kube-system",
    ),
    (
        &["delete", "ns", "kube-system"],
        "Cannot delete kube-system",
    ),
];

static KUBECTL_WRITE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("apply", "Applying resources"),
        ("create", "Creating resources"),
        ("delete", "Deleting resources"),
        ("edit", "Editing resources"),
        ("patch", "Patching resources"),
        ("replace", "Replacing resources"),
        ("scale", "Scaling resources"),
        ("rollout", "Rollout operation"),
        ("expose", "Exposing service"),
        ("run", "Running pod"),
        ("exec", "Executing in pod"),
        ("cp", "Copying files"),
        ("port-forward", "Port forwarding"),
        ("label", "Labeling resources"),
        ("annotate", "Annotating resources"),
        ("taint", "Tainting nodes"),
        ("drain", "Draining nodes"),
        ("cordon", "Cordoning nodes"),
        ("uncordon", "Uncordoning nodes"),
    ]
    .into_iter()
    .collect()
});

fn check_kubectl(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let args_str: Vec<&str> = args.iter().map(std::string::String::as_str).collect();

    // Check blocked patterns
    for (blocked, reason) in KUBECTL_BLOCKED {
        if args_str.len() >= blocked.len() && args_str[..blocked.len()] == **blocked {
            return GateResult::block(*reason);
        }
    }

    let subcommand = args[0].as_str();

    // config commands
    if subcommand == "config" && args.len() >= 2 {
        match args[1].as_str() {
            "view" | "get-contexts" | "current-context" | "get-clusters" => {
                return GateResult::allow();
            }
            sub => return GateResult::ask(format!("kubectl: config {sub}")),
        }
    }

    // auth commands
    if subcommand == "auth" && args.len() >= 2 && (args[1] == "can-i" || args[1] == "whoami") {
        return GateResult::allow();
    }

    if KUBECTL_READ.contains(subcommand) {
        return GateResult::allow();
    }

    if let Some(reason) = KUBECTL_WRITE.get(subcommand) {
        return GateResult::ask(format!("kubectl: {reason}"));
    }

    GateResult::ask("kubectl: Unknown command")
}

// === DOCKER ===

static DOCKER_READ: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "ps",
        "images",
        "inspect",
        "logs",
        "stats",
        "top",
        "port",
        "version",
        "info",
        "history",
        "-v",
        "--version",
        "-h",
        "--help",
    ]
    .into_iter()
    .collect()
});

static DOCKER_WRITE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("run", "Running container"),
        ("exec", "Executing in container"),
        ("build", "Building image"),
        ("push", "Pushing image"),
        ("pull", "Pulling image"),
        ("rm", "Removing container"),
        ("rmi", "Removing image"),
        ("kill", "Killing container"),
        ("stop", "Stopping container"),
        ("start", "Starting container"),
        ("restart", "Restarting container"),
        ("pause", "Pausing container"),
        ("unpause", "Unpausing container"),
        ("tag", "Tagging image"),
        ("commit", "Committing container"),
        ("cp", "Copying files"),
        ("login", "Logging in"),
        ("logout", "Logging out"),
    ]
    .into_iter()
    .collect()
});

fn check_docker(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let subcommand = args[0].as_str();

    // network/volume/system commands
    if matches!(subcommand, "network" | "volume" | "system") && args.len() >= 2 {
        match args[1].as_str() {
            "ls" | "list" | "inspect" | "df" => return GateResult::allow(),
            sub => return GateResult::ask(format!("Docker: {subcommand} {sub}")),
        }
    }

    if DOCKER_READ.contains(subcommand) {
        return GateResult::allow();
    }

    if let Some(reason) = DOCKER_WRITE.get(subcommand) {
        return GateResult::ask(format!("Docker: {reason}"));
    }

    GateResult::ask("Docker: Unknown command")
}

// === PODMAN ===

/// Podman read-only commands (similar to docker)
static PODMAN_READ: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "ps",
        "images",
        "inspect",
        "logs",
        "stats",
        "top",
        "port",
        "version",
        "info",
        "history",
        "search",
        "healthcheck",
        "-v",
        "--version",
        "-h",
        "--help",
    ]
    .into_iter()
    .collect()
});

/// Podman write commands
static PODMAN_WRITE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("run", "Running container"),
        ("exec", "Executing in container"),
        ("build", "Building image"),
        ("push", "Pushing image"),
        ("pull", "Pulling image"),
        ("rm", "Removing container"),
        ("rmi", "Removing image"),
        ("kill", "Killing container"),
        ("stop", "Stopping container"),
        ("start", "Starting container"),
        ("restart", "Restarting container"),
        ("pause", "Pausing container"),
        ("unpause", "Unpausing container"),
        ("tag", "Tagging image"),
        ("commit", "Committing container"),
        ("cp", "Copying files"),
        ("login", "Logging in"),
        ("logout", "Logging out"),
        ("create", "Creating container"),
        ("pod", "Pod operation"),
        ("generate", "Generating config"),
        ("play", "Playing kube YAML"),
    ]
    .into_iter()
    .collect()
});

fn check_podman(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let subcommand = args[0].as_str();

    // network/volume/system/machine commands
    if matches!(subcommand, "network" | "volume" | "system" | "machine") && args.len() >= 2 {
        match args[1].as_str() {
            "ls" | "list" | "inspect" | "df" | "info" => return GateResult::allow(),
            sub => return GateResult::ask(format!("Podman: {subcommand} {sub}")),
        }
    }

    // pod subcommands
    if subcommand == "pod" && args.len() >= 2 {
        match args[1].as_str() {
            "ps" | "list" | "inspect" | "logs" | "top" | "stats" => return GateResult::allow(),
            sub => return GateResult::ask(format!("Podman: pod {sub}")),
        }
    }

    // secret subcommands
    if subcommand == "secret" && args.len() >= 2 {
        match args[1].as_str() {
            "ls" | "list" | "inspect" => return GateResult::allow(),
            sub => return GateResult::ask(format!("Podman: secret {sub}")),
        }
    }

    if PODMAN_READ.contains(subcommand) {
        return GateResult::allow();
    }

    if let Some(reason) = PODMAN_WRITE.get(subcommand) {
        return GateResult::ask(format!("Podman: {reason}"));
    }

    GateResult::ask("Podman: Unknown command")
}

// === DOCKER COMPOSE ===

static COMPOSE_READ: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "ps", "logs", "config", "images", "ls", "version", "-h", "--help",
    ]
    .into_iter()
    .collect()
});

static COMPOSE_WRITE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("up", "Starting services"),
        ("down", "Stopping services"),
        ("start", "Starting services"),
        ("stop", "Stopping services"),
        ("restart", "Restarting services"),
        ("pause", "Pausing services"),
        ("unpause", "Unpausing services"),
        ("build", "Building services"),
        ("push", "Pushing images"),
        ("pull", "Pulling images"),
        ("rm", "Removing services"),
        ("kill", "Killing services"),
        ("exec", "Executing in service"),
        ("run", "Running one-off"),
        ("create", "Creating services"),
    ]
    .into_iter()
    .collect()
});

fn check_docker_compose(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let subcommand = args[0].as_str();

    if COMPOSE_READ.contains(subcommand) {
        return GateResult::allow();
    }

    if let Some(reason) = COMPOSE_WRITE.get(subcommand) {
        return GateResult::ask(format!("Compose: {reason}"));
    }

    GateResult::ask("Compose: Unknown command")
}

// === PULUMI ===

static PULUMI_READ: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    ["preview", "whoami", "version", "-h", "--help"]
        .into_iter()
        .collect()
});

static PULUMI_WRITE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("up", "Deploying stack"),
        ("destroy", "Destroying stack"),
        ("refresh", "Refreshing state"),
        ("import", "Importing resource"),
        ("cancel", "Canceling update"),
        ("new", "Creating project"),
    ]
    .into_iter()
    .collect()
});

fn check_pulumi(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let subcommand = args[0].as_str();

    if subcommand == "stack" && args.len() >= 2 {
        match args[1].as_str() {
            "ls" | "list" | "output" | "history" | "export" => return GateResult::allow(),
            sub => return GateResult::ask(format!("Pulumi: stack {sub}")),
        }
    }

    if subcommand == "config" && args.len() >= 2 {
        if args[1] == "get" {
            return GateResult::allow();
        }
        return GateResult::ask(format!("Pulumi: config {}", args[1]));
    }

    if PULUMI_READ.contains(subcommand) {
        return GateResult::allow();
    }

    if let Some(reason) = PULUMI_WRITE.get(subcommand) {
        return GateResult::ask(format!("Pulumi: {reason}"));
    }

    GateResult::ask("Pulumi: Unknown command")
}

// === HELM ===

static HELM_READ: LazyLock<HashSet<&str>> = LazyLock::new(|| {
    [
        "list", "ls", "get", "show", "search", "repo", "status", "history", "version", "-h",
        "--help", "template", "lint", "verify",
    ]
    .into_iter()
    .collect()
});

static HELM_WRITE: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    [
        ("install", "Installing release"),
        ("upgrade", "Upgrading release"),
        ("uninstall", "Uninstalling release"),
        ("rollback", "Rolling back"),
        ("delete", "Deleting release"),
        ("push", "Pushing chart"),
        ("package", "Packaging chart"),
    ]
    .into_iter()
    .collect()
});

fn check_helm(cmd: &CommandInfo) -> GateResult {
    let args = &cmd.args;
    if args.is_empty() {
        return GateResult::allow();
    }

    let subcommand = args[0].as_str();

    if HELM_READ.contains(subcommand) {
        return GateResult::allow();
    }

    if let Some(reason) = HELM_WRITE.get(subcommand) {
        return GateResult::ask(format!("Helm: {reason}"));
    }

    GateResult::ask("Helm: Unknown command")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;

    // === AWS ===

    mod aws {
        use super::*;

        #[test]
        fn test_read_commands_allow() {
            let read_cmds = [
                &["s3", "ls"][..],
                &["s3", "ls", "s3://bucket"],
                &["sts", "get-caller-identity"],
                &["ec2", "describe-instances"],
                &["ec2", "describe-security-groups"],
                &["iam", "get-user"],
                &["iam", "list-users"],
                &["lambda", "get-function", "--function-name", "test"],
                &["lambda", "list-functions"],
                &["logs", "describe-log-groups"],
                &["cloudformation", "describe-stacks"],
                &["--version"],
                &["help"],
            ];

            for args in read_cmds {
                let result = check_cloud(&cmd("aws", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_write_commands_ask() {
            let write_cmds = [
                (&["s3", "cp", "file", "s3://bucket/"][..], "S3 copy"),
                (&["s3", "mv", "s3://bucket/a", "s3://bucket/b"], "S3 move"),
                (&["s3", "rm", "s3://bucket/file"], "S3 delete"),
                (&["s3", "sync", ".", "s3://bucket/"], "S3 sync"),
                (
                    &["ec2", "run-instances", "--image-id", "ami-123"],
                    "EC2 run",
                ),
                (
                    &["ec2", "terminate-instances", "--instance-ids", "i-123"],
                    "EC2 terminate",
                ),
                (
                    &["lambda", "invoke", "--function-name", "test", "out.json"],
                    "Lambda invoke",
                ),
                (&["iam", "create-user", "--user-name", "test"], "IAM create"),
            ];

            for (args, expected) in write_cmds {
                let result = check_cloud(&cmd("aws", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(
                    result.reason.as_ref().unwrap().contains(expected),
                    "Failed for: {args:?}"
                );
            }
        }

        #[test]
        fn test_blocked_commands() {
            let blocked = [
                (
                    &["iam", "delete-user", "--user-name", "admin"][..],
                    "IAM users",
                ),
                (&["organizations", "delete-organization"], "Organization"),
            ];

            for (args, expected) in blocked {
                let result = check_cloud(&cmd("aws", args));
                assert_eq!(result.decision, Decision::Block, "Failed for: {args:?}");
                assert!(
                    result.reason.as_ref().unwrap().contains(expected),
                    "Failed for: {args:?}"
                );
            }
        }
    }

    // === Terraform ===

    mod terraform {
        use super::*;

        #[test]
        fn test_read_commands_allow() {
            let read_cmds = [
                &["plan"][..],
                &["show"],
                &["output"],
                &["validate"],
                &["version"],
                &["providers"],
                &["state", "list"],
                &["state", "show", "resource"],
                &["workspace", "list"],
                &["fmt", "-check"],
            ];

            for args in read_cmds {
                let result = check_cloud(&cmd("terraform", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_write_commands_ask() {
            let write_cmds = [
                (&["apply"][..], "Applying"),
                (&["destroy"], "Destroying"),
                (&["import", "resource", "id"], "Importing"),
                (&["init"], "Initializing"),
                (&["fmt"], "Formatting"),
                (&["state", "mv", "a", "b"], "state mv"),
                (&["workspace", "new", "dev"], "workspace new"),
            ];

            for (args, expected) in write_cmds {
                let result = check_cloud(&cmd("terraform", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(
                    result.reason.as_ref().unwrap().contains(expected),
                    "Failed for: {args:?}"
                );
            }
        }
    }

    // === Kubectl ===

    mod kubectl {
        use super::*;

        #[test]
        fn test_read_commands_allow() {
            let read_cmds = [
                &["get", "pods"][..],
                &["get", "deployments", "-n", "default"],
                &["describe", "pod", "web-123"],
                &["logs", "web-123"],
                &["top", "pods"],
                &["explain", "pod"],
                &["cluster-info"],
                &["version"],
                &["config", "view"],
                &["config", "get-contexts"],
                &["auth", "can-i", "get", "pods"],
            ];

            for args in read_cmds {
                let result = check_cloud(&cmd("kubectl", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_write_commands_ask() {
            let write_cmds = [
                (&["apply", "-f", "deployment.yaml"][..], "Applying"),
                (&["create", "deployment", "web"], "Creating"),
                (&["delete", "pod", "web-123"], "Deleting"),
                (&["scale", "deployment", "web", "--replicas=3"], "Scaling"),
                (&["exec", "-it", "web-123", "--", "bash"], "Executing"),
                (&["rollout", "restart", "deployment/web"], "Rollout"),
            ];

            for (args, expected) in write_cmds {
                let result = check_cloud(&cmd("kubectl", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(
                    result.reason.as_ref().unwrap().contains(expected),
                    "Failed for: {args:?}"
                );
            }
        }

        #[test]
        fn test_kube_system_delete_blocks() {
            for args in [
                &["delete", "namespace", "kube-system"][..],
                &["delete", "ns", "kube-system"],
            ] {
                let result = check_cloud(&cmd("kubectl", args));
                assert_eq!(result.decision, Decision::Block, "Failed for: {args:?}");
                assert!(result.reason.as_ref().unwrap().contains("kube-system"));
            }
        }
    }

    // === Docker ===

    mod docker {
        use super::*;

        #[test]
        fn test_read_commands_allow() {
            let read_cmds = [
                &["ps"][..],
                &["ps", "-a"],
                &["images"],
                &["inspect", "container"],
                &["logs", "container"],
                &["stats"],
                &["version"],
                &["info"],
                &["network", "ls"],
                &["volume", "ls"],
            ];

            for args in read_cmds {
                let result = check_cloud(&cmd("docker", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_write_commands_ask() {
            let write_cmds = [
                (&["run", "-d", "nginx"][..], "Running"),
                (&["build", "-t", "myapp", "."], "Building"),
                (&["push", "myapp:latest"], "Pushing"),
                (&["pull", "nginx:latest"], "Pulling"),
                (&["rm", "container"], "Removing"),
                (&["rmi", "image"], "Removing"),
                (&["stop", "container"], "Stopping"),
                (&["exec", "-it", "container", "bash"], "Executing"),
            ];

            for (args, expected) in write_cmds {
                let result = check_cloud(&cmd("docker", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(
                    result.reason.as_ref().unwrap().contains(expected),
                    "Failed for: {args:?}"
                );
            }
        }
    }

    // === Gcloud ===

    mod gcloud {
        use super::*;

        #[test]
        fn test_read_commands_allow() {
            let read_cmds = [
                &["config", "list"][..],
                &["auth", "list"],
                &["projects", "list"],
                &["compute", "instances", "list"],
                &["container", "clusters", "list"],
                &["--version"],
                &["info"],
            ];

            for args in read_cmds {
                let result = check_cloud(&cmd("gcloud", args));
                assert_eq!(result.decision, Decision::Allow, "Failed for: {args:?}");
            }
        }

        #[test]
        fn test_write_commands_ask() {
            let write_cmds = [
                (
                    &["compute", "instances", "create", "vm1"][..],
                    "Compute create",
                ),
                (&["compute", "instances", "delete", "vm1"], "Compute delete"),
                (
                    &["container", "clusters", "create", "cluster1"],
                    "GKE create",
                ),
                (&["functions", "deploy", "func1"], "Functions deploy"),
            ];

            for (args, expected) in write_cmds {
                let result = check_cloud(&cmd("gcloud", args));
                assert_eq!(result.decision, Decision::Ask, "Failed for: {args:?}");
                assert!(
                    result.reason.as_ref().unwrap().contains(expected),
                    "Failed for: {args:?}"
                );
            }
        }
    }
}
