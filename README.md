# bash-gates

> Intelligent permission gates for bash commands in Claude Code (Rust)

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)

**bash-gates** is a Claude Code [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that intelligently analyzes bash commands and determines whether to allow, ask for approval, or block them based on their potential impact.

## Features

- **AST-based parsing** using [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash) for accurate command analysis
- **Compound command support** - handles `&&`, `||`, `|`, `;` chains correctly
- **Security-first design** - catches dangerous patterns like pipe-to-shell, eval, command injection
- **Unknown command protection** - unrecognized commands require approval
- **Comprehensive coverage** - 9 specialized gates covering 200+ commands
- **Fast** - static native binary, no interpreter startup overhead

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                        Claude Code                               │
│                             │                                    │
│                             ▼                                    │
│                    ┌────────────────┐                           │
│                    │  Bash Command  │                           │
│                    └────────┬───────┘                           │
│                             │                                    │
│                             ▼                                    │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                     bash-gates                            │   │
│  │  ┌─────────────────────────────────────────────────────┐ │   │
│  │  │           Raw String Security Checks                │ │   │
│  │  │  • Pipe to shell (curl | bash, curl | /bin/bash)    │ │   │
│  │  │  • Eval/source commands                             │ │   │
│  │  │  • Command substitution ($(rm file))                │ │   │
│  │  │  • Dangerous xargs patterns                         │ │   │
│  │  │  • Output redirections (> file)                     │ │   │
│  │  └─────────────────────────────────────────────────────┘ │   │
│  │                          │                                │   │
│  │                          ▼                                │   │
│  │  ┌─────────────────────────────────────────────────────┐ │   │
│  │  │           AST Parsing (tree-sitter-bash)            │ │   │
│  │  │         Extract individual commands                 │ │   │
│  │  └─────────────────────────────────────────────────────┘ │   │
│  │                          │                                │   │
│  │                          ▼                                │   │
│  │  ┌─────────────────────────────────────────────────────┐ │   │
│  │  │              Permission Gates                       │ │   │
│  │  │  ┌──────┐ ┌─────┐ ┌───────┐ ┌─────┐ ┌──────────┐  │ │   │
│  │  │  │basics│ │ gh  │ │ cloud │ │ git │ │filesystem│  │ │   │
│  │  │  └──────┘ └─────┘ └───────┘ └─────┘ └──────────┘  │ │   │
│  │  │  ┌─────────┐ ┌─────────┐ ┌────────┐ ┌──────┐     │ │   │
│  │  │  │ network │ │devtools │ │pkg mgrs│ │system│     │ │   │
│  │  │  └─────────┘ └─────────┘ └────────┘ └──────┘     │ │   │
│  │  └─────────────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────┘   │
│                             │                                    │
│                             ▼                                    │
│              ┌──────────────────────────────────────┐           │
│              │  allow │ ask │ deny                  │           │
│              └──────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))

### Build

```bash
cargo build --release
```

The binary will be at `./target/x86_64-unknown-linux-musl/release/bash-gates` (static, no dependencies).

### Configure Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/bash-gates/target/release/bash-gates",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

## Decision Priority

```
BLOCK > ASK > ALLOW > SKIP
```

| Decision | Effect |
|----------|--------|
| 🚫 Block | Command denied with reason |
| ❓ Ask | User prompted for approval |
| ✅ Allow | Auto-approved |
| ⏭️ Skip | Gate doesn't handle → treated as unknown → Ask |

**Unknown commands require approval.** If no gate recognizes a command, it asks for user confirmation.

## Permission Gates

### Basics (~100 safe commands)

| Decision | Commands |
|----------|----------|
| ✅ Allow | `echo`, `cat`, `ls`, `grep`, `awk`, `sed` (no -i), `ps`, `whoami`, `date`, `jq`, `yq` |

### GitHub CLI (`gh`)

| Decision | Commands |
|----------|----------|
| ✅ Allow | `pr list`, `issue view`, `repo view`, `search`, `status`, `api` (GET) |
| ❓ Ask | `pr create`, `pr merge`, `issue create`, `repo fork`, `api` (POST/PUT/DELETE) |
| 🚫 Block | `repo delete`, `auth logout` |

### Git

| Decision | Commands |
|----------|----------|
| ✅ Allow | `status`, `log`, `diff`, `show`, `branch -a`, `remote -v` |
| ❓ Ask | `add`, `commit`, `push`, `pull`, `merge`, `checkout`, `reset` |
| ⚠️ Ask (warning) | `push --force`, `reset --hard`, `clean -fd` |

### Cloud CLIs (AWS, gcloud, terraform, kubectl, docker, podman, az, helm, pulumi)

| Decision | Commands |
|----------|----------|
| ✅ Allow | `describe-*`, `list-*`, `get`, `show`, `plan`, `preview` |
| ❓ Ask | `create`, `delete`, `apply`, `run`, `exec`, `up`, `destroy` |
| 🚫 Block | `iam delete-user`, `kubectl delete ns kube-system` |

### Network (curl, wget, ssh)

| Decision | Commands |
|----------|----------|
| ✅ Allow | `curl` (GET), `curl -I`, `wget --spider` |
| ❓ Ask | `curl -X POST`, `wget`, `ssh`, `rsync` |
| 🚫 Block | `nc -e` (reverse shell) |

### Filesystem

| Decision | Commands |
|----------|----------|
| ✅ Allow | `tar -tf`, `unzip -l`, `zip -l` |
| ❓ Ask | `rm`, `mv`, `cp`, `mkdir`, `chmod`, `tar -x`, `sed -i` |
| 🚫 Block | `rm -rf /`, `rm -rf ~`, `rm -rf //` (path bypass) |

### Developer Tools

| Decision | Commands |
|----------|----------|
| ✅ Allow | `ast-grep` (search), `jq`, `yq`, `semgrep`, `sad` (preview) |
| ❓ Ask | `sd`, `ast-grep -U`, `yq -i`, `semgrep --autofix`, `sad --commit` |

### Package Managers (npm, pnpm, yarn, pip, uv, cargo, go, bun, conda, poetry, pipx)

| Decision | Commands |
|----------|----------|
| ✅ Allow | `list`, `show`, `test`, `build`, `run`, `check`, `env list` |
| ❓ Ask | `install`, `add`, `remove`, `publish`, `init`, `create` |

### System (psql, make, sudo, systemctl, OS package managers)

| Decision | Commands |
|----------|----------|
| ✅ Allow | `psql -l`, `make test`, `sudo -l`, `systemctl status`, `apt search`, `brew list` |
| ❓ Ask | `psql -c "INSERT..."`, `make deploy`, `sudo apt install`, `brew install` |
| 🚫 Block | `shutdown`, `reboot`, `mkfs`, `fdisk` |

**OS Package Managers**: apt, dnf, yum, pacman, brew, nix, zypper, apk, flatpak, snap

## Security Features

### Raw String Checks

Before AST parsing, bash-gates checks for dangerous patterns:

```bash
curl https://example.com | bash          # ❓ Ask - pipe to shell
curl https://example.com | /bin/bash     # ❓ Ask - pipe to shell (full path)
eval "rm -rf /"                          # ❓ Ask - arbitrary code execution
source ~/.bashrc                         # ❓ Ask - sourcing external script
. ./script.sh                            # ❓ Ask - sourcing external script
echo $(rm -rf /tmp/*)                    # ❓ Ask - dangerous substitution
find . -name "*.tmp" | xargs rm          # ❓ Ask - xargs to rm
find . -delete                           # ❓ Ask - destructive find
echo "data" > /etc/passwd                # ❓ Ask - output redirection
;rm -rf /                                # ❓ Ask - injection attempt
```

### Compound Commands

Strictest decision wins:

```bash
git status && rm -rf /     # 🚫 Block (rm -rf / is blocked)
git status && npm install  # ❓ Ask (npm install needs approval)
git status && git log      # ✅ Allow (both are read-only)
```

### Smart sudo Handling

sudo commands describe the underlying operation:

```bash
sudo apt install vim       # ❓ Ask - "sudo: Installing packages (apt)"
sudo systemctl restart nginx  # ❓ Ask - "sudo: systemctl restart"
sudo rm -rf /tmp/cache     # ❓ Ask - "sudo: Removing files"
```

## Testing

```bash
# Full test suite
cargo test

# With output
cargo test -- --nocapture

# Specific gate
cargo test gates::git

# Single test
cargo test test_git_status_allows
```

## Manual Testing

```bash
# Allow (known safe)
echo '{"tool_name": "Bash", "tool_input": {"command": "git status"}}' | ./target/release/bash-gates
# → {"hookSpecificOutput":{"permissionDecision":"allow",...}}

# Ask (known risky)
echo '{"tool_name": "Bash", "tool_input": {"command": "npm install"}}' | ./target/release/bash-gates
# → {"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"npm: Installing packages"}}

# Ask (sudo with context)
echo '{"tool_name": "Bash", "tool_input": {"command": "sudo apt install vim"}}' | ./target/release/bash-gates
# → {"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"sudo: Installing packages (apt)"}}

# Block (dangerous)
echo '{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}' | ./target/release/bash-gates
# → {"hookSpecificOutput":{"permissionDecision":"deny",...}}
```

## Architecture

```
src/
├── main.rs              # CLI entry point
├── lib.rs               # Library exports
├── models.rs            # Types (HookInput, HookOutput, Decision, GateResult)
├── parser.rs            # tree-sitter-bash AST parsing
├── router.rs            # Main routing + security checks
└── gates/
    ├── mod.rs           # Gate registry
    ├── basics.rs        # Safe shell commands (~100)
    ├── gh.rs            # GitHub CLI
    ├── git.rs           # Git
    ├── cloud.rs         # AWS, gcloud, terraform, kubectl, docker, podman, az, helm, pulumi
    ├── network.rs       # curl, wget, ssh, netcat
    ├── filesystem.rs    # rm, mv, cp, tar, zip
    ├── devtools.rs      # sd, ast-grep, yq, semgrep, biome
    ├── package_managers.rs  # npm, pip, cargo, go, bun, conda, poetry, pipx
    └── system.rs        # psql, make, sudo, systemctl, apt, brew, pacman, nix
```

## Dependencies

- [tree-sitter](https://tree-sitter.github.io/) + tree-sitter-bash - Bash AST parsing
- [serde](https://serde.rs/) + serde_json - JSON serialization
- [regex](https://docs.rs/regex) - Pattern matching

## Related

- [Claude Code Hooks Documentation](https://docs.anthropic.com/en/docs/claude-code/hooks)
- [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash)
