# Bash Gates - Claude Code Permission Hook (Rust)

Intelligent bash command permission gate using tree-sitter AST parsing. Auto-allows known safe operations, asks for writes and unknown commands, blocks dangerous patterns.

## Quick Reference

```bash
# Test a command
echo '{"tool_name": "Bash", "tool_input": {"command": "gh pr list"}}' | ./target/x86_64-unknown-linux-musl/release/bash-gates

# Run tests
cargo test

# Run specific gate tests
cargo test gates::git -- --nocapture

# Build release (static musl binary by default)
cargo build --release

# Build for glibc instead
cargo build --release --target x86_64-unknown-linux-gnu

# Run clippy
cargo clippy -- -D warnings
```

## Build Output

Default build produces a **fully static musl binary** with zero runtime dependencies:

```bash
$ file target/x86_64-unknown-linux-musl/release/bash-gates
ELF 64-bit LSB pie executable, x86-64, static-pie linked, stripped

$ ldd target/x86_64-unknown-linux-musl/release/bash-gates
statically linked
```

## Architecture

```
src/
├── main.rs          # Entry point - reads stdin JSON, outputs decision
├── lib.rs           # Library root
├── models.rs        # Serde models (HookInput, HookOutput, Decision)
├── parser.rs        # tree-sitter-bash AST parsing → Vec<CommandInfo>
├── router.rs        # Raw string security checks + gate routing
├── settings.rs      # settings.json parsing and pattern matching
└── gates/           # 9 specialized permission gates
    ├── mod.rs           # Gate registry
    ├── basics.rs        # Safe shell commands (echo, cat, ls, grep, etc.)
    ├── gh.rs            # GitHub CLI
    ├── git.rs           # Git commands
    ├── cloud.rs         # AWS, gcloud, terraform, kubectl, docker, helm, pulumi, az
    ├── network.rs       # curl, wget, ssh, scp, rsync, netcat
    ├── filesystem.rs    # rm, mv, cp, chmod, tar, zip
    ├── devtools.rs      # sd, ast-grep, yq, jq, semgrep, biome, prettier
    ├── package_managers.rs  # npm, pnpm, yarn, pip, uv, cargo, go, bun
    └── system.rs        # psql, mysql, make, sudo, systemctl, kill, crontab
```

## How It Works

1. **Input**: JSON from Claude Code's PreToolUse hook (includes `cwd`)
2. **Settings check**: Load `~/.claude/settings.json` + `.claude/settings.json`, check if command matches deny/ask rules
3. **Security checks**: Raw string patterns (pipe-to-shell, xargs, redirections)
4. **Parse**: tree-sitter-bash extracts individual commands from compound statements
5. **Check**: Each command runs through all gates
6. **Decide**: Strictest decision wins (block > ask > allow > skip)
7. **Output**: JSON with `permissionDecision` (allow/ask/deny)

## Settings.json Integration (settings.rs)

bash-gates respects your Claude Code permission rules by checking `settings.json` **before** running gate analysis:

```
┌─────────────────────────────────────────────────────────────┐
│                    Decision Flow                             │
├─────────────────────────────────────────────────────────────┤
│  1. Load settings.json (user + project)                     │
│  2. Check command against settings.json rules               │
│     ├─ matches deny  → return ask (defer to CC, respects deny) │
│     ├─ matches ask   → return ask (defer to CC, respects ask)  │
│     └─ matches allow / no match → proceed to gate analysis  │
│  3. Run bash-gates analysis                                 │
│     ├─ dangerous    → deny                                  │
│     ├─ safe         → allow                                 │
│     └─ unknown      → ask                                   │
└─────────────────────────────────────────────────────────────┘
```

### Pattern Matching

Settings.json uses these pattern formats:

| Pattern | Type | Example | Matches |
|---------|------|---------|---------|
| `Bash(cmd:*)` | Word-boundary prefix | `Bash(git:*)` | `git`, `git status`, `git push` |
| `Bash(cmd*)` | Glob prefix | `Bash(cat /dev/zero*)` | `cat /dev/zero`, `cat /dev/zero \| head` |
| `Bash(cmd)` | Exact | `Bash(pwd)` | Only `pwd` |

### Why This Matters

PreToolUse hooks have **more power** than settings.json:
- Hook returning `allow` → bypasses settings.json entirely
- Hook returning `deny` → bypasses settings.json entirely
- Hook returning `ask` → defers to settings.json

Without settings.json integration, bash-gates could accidentally bypass your explicit deny rules. For example:
- You have `Bash(cat /dev/zero*)` in deny
- bash-gates thinks `cat` is safe → returns `allow`
- Your deny rule is bypassed!

With settings.json integration:
- bash-gates sees your deny rule first
- Returns `ask` to defer to Claude Code
- Claude Code applies your deny rule → blocked

## Decision Priority

```
BLOCK > ASK > ALLOW > SKIP
```

| Decision | Output | Effect |
|----------|--------|--------|
| `block` | `permissionDecision: "deny"` | Block with reason |
| `ask` | `permissionDecision: "ask"` | Prompt user for approval |
| `allow` | `permissionDecision: "allow"` | Auto-approve |
| `skip` | (triggers ask) | Gate doesn't handle command → unknown |

**Unknown commands require approval.** If no gate explicitly allows a command, it's treated as unknown and requires user approval.

## Security Checks (router.rs)

Before AST parsing, raw string checks catch dangerous patterns:

| Pattern | Decision | Reason |
|---------|----------|--------|
| `\| bash`, `\| /bin/bash`, `\| sh`, `\| zsh` | ask | Pipe to shell |
| `\| python`, `\| perl`, `\| ruby` | ask | Pipe to interpreter |
| `\| sudo`, `\| /usr/bin/sudo` | ask | Pipe to sudo |
| `eval ...` | ask | Arbitrary code execution |
| `source ...`, `. script` | ask | Sourcing external script |
| `xargs rm`, `xargs mv` | ask | xargs to dangerous command |
| `find . -delete`, `find -exec rm` | ask | Destructive find |
| `$(rm ...)`, `` `rm ...` `` | ask | Dangerous command substitution |
| `;rm -rf /` | ask | Leading semicolon (injection) |
| `> file`, `>> file`, `&> file` | ask | Output redirection |

## Gate Coverage

### basics.rs - Safe Shell Commands
~100 known-safe commands that are always allowed:
- **Display**: `echo`, `printf`, `cat`, `head`, `tail`, `less`, `bat`
- **Listing**: `ls`, `eza`, `tree`, `find`, `fd`, `which`
- **Text processing**: `grep`, `rg`, `awk`, `sed` (without -i), `cut`, `sort`, `uniq`, `wc`
- **File info**: `file`, `stat`, `du`, `df`, `realpath`
- **Process/system**: `ps`, `top`, `htop`, `whoami`, `id`, `uname`, `date`, `uptime`
- **Network info**: `ping`, `dig`, `ss`, `netstat`, `ip`
- **Dev tools**: `jq`, `yq`, `tokei`, `hexdump`
- **Help**: `man`, `tldr`, `--help`

### gh.rs - GitHub CLI
- **Allow**: `pr list`, `issue view`, `repo view`, `search`, `api` (GET)
- **Ask**: `pr create`, `pr merge`, `issue create`, `api` (POST/PUT/DELETE)
- **Block**: `repo delete`, `auth logout`

### git.rs - Git
- **Allow**: `status`, `log`, `diff`, `show`, `branch -a`, `--dry-run` commands
- **Ask**: `add`, `commit`, `push`, `pull`, `merge`, `checkout`, `branch -d`
- **Ask (warning)**: `push --force`, `reset --hard`, `clean -fd`

### cloud.rs - Cloud CLIs
- **AWS**: `describe-*`/`list-*`/`get-*` allow, `create`/`delete`/`put` ask, `iam delete-user` block
- **gcloud**: `list`/`describe` allow, `create`/`delete`/`deploy` ask
- **terraform/tofu**: `plan`/`show` allow, `apply`/`destroy` ask
- **kubectl**: `get`/`describe`/`logs` allow, `apply`/`delete`/`exec` ask, `delete ns kube-system` block
- **docker**: `ps`/`images`/`logs` allow, `run`/`build`/`push` ask
- **podman**: `ps`/`images`/`logs`/`pod ps` allow, `run`/`build`/`push`/`play` ask
- **az**: `list`/`show` allow, `create`/`delete`/`start`/`stop`/`restart` ask
- **helm**: `list`/`get`/`show`/`template` allow, `install`/`upgrade`/`uninstall` ask
- **pulumi**: `preview`/`stack ls` allow, `up`/`destroy`/`refresh` ask

### network.rs - Network Tools
- **curl**: GET allow, POST/PUT/DELETE ask, `-o`/`-O` (download) ask
- **wget**: `--spider` allow, download ask, `--mirror` ask
- **ssh/scp/sftp**: always ask
- **rsync**: `--dry-run` allow, otherwise ask
- **netcat**: `-e` block (reverse shell), `-l` ask

### filesystem.rs - Filesystem
- **Allow**: `tar -tf`, `unzip -l` (list contents)
- **Ask**: `rm`, `mv`, `cp`, `mkdir`, `chmod`, `tar -x`, `sed -i`
- **Block**: `rm -rf /`, `rm -rf ~`, path traversal attempts (`//`, `/../`)

### devtools.rs - Developer Tools
- **Allow**: `ast-grep` (search), `jq`, `yq`, `semgrep`, `sad` (preview), `black --check`
- **Ask**: `sd`, `ast-grep -U`, `yq -i`, `semgrep --autofix`, `sad --commit`, `black`

### package_managers.rs - Package Managers
- **Allow**: `list`, `show`, `test`, `build`, `run`, `check`, `lint`, `dev`
- **Ask**: `install`, `add`, `remove`, `publish`, `init`
- Covers: npm, pnpm, yarn, pip, uv, cargo, go, bun, conda, mamba, poetry, pipx

### system.rs - System Commands
- **Database**: `psql -l`/`mysql SHOW` allow, `psql -c INSERT`/`psql -f` ask
- **Build**: `make test`/`make build` allow, `make deploy` ask
- **sudo/doas**: `-l`/`-v`/`-k` allow, describes underlying command (e.g., "sudo: Installing packages (apt)")
- **systemctl**: `status`/`list-units` allow, `start`/`stop`/`restart` ask
- **Process**: `kill -0` allow, `kill`/`pkill` ask
- **Crontab**: `crontab -l` allow, `crontab -e` ask
- **Block**: `shutdown`, `reboot`, `mkfs`, `fdisk`, `parted`

### system.rs - OS Package Managers
- **apt/apt-get**: `list`/`search`/`show` allow, `install`/`remove`/`upgrade` ask
- **dnf/yum**: `list`/`info`/`search` allow, `install`/`remove`/`update` ask
- **pacman/yay/paru**: `-Q` (query) allow, `-S`/`-R` (sync/remove) ask
- **brew**: `list`/`search`/`info` allow, `install`/`uninstall`/`upgrade` ask
- **nix/nix-env**: `-q` (query) allow, `-i`/`-e` (install/uninstall) ask
- **flatpak/snap**: `list`/`info` allow, `install`/`remove` ask
- **zypper/apk**: `search`/`info` allow, `install`/`remove` ask

## Adding a New Gate

1. Create `src/gates/new_gate.rs`:

```rust
use crate::models::{CommandInfo, GateResult};

pub fn check_new(cmd: &CommandInfo) -> GateResult {
    if cmd.program != "newtool" {
        return GateResult::skip(); // Don't handle - let other gates or unknown handling take over
    }

    let args = &cmd.args;

    // Read-only
    if args.first().map(|s| s.as_str()) == Some("list") {
        return GateResult::allow();
    }

    // Write
    if args.first().map(|s| s.as_str()) == Some("create") {
        return GateResult::ask("newtool: create");
    }

    GateResult::ask("newtool: Unknown subcommand")
}
```

2. Register in `gates/mod.rs`:
```rust
mod new_gate;
pub use new_gate::check_new;

pub static GATES: &[(&str, fn(&CommandInfo) -> GateResult)] = &[
    // ... other gates ...
    ("new", check_new),
    ("basics", check_basics), // basics should be last (catch-all for safe commands)
];
```

3. Add tests at bottom of file:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CommandInfo, Decision};

    fn cmd(program: &str, args: &[&str]) -> CommandInfo {
        CommandInfo {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn test_newtool_list_allows() {
        let result = check_new(&cmd("newtool", &["list"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_non_newtool_skips() {
        let result = check_new(&cmd("other", &["list"]));
        assert_eq!(result.decision, Decision::Skip);
    }
}
```

## Key Patterns

### CommandInfo Fields
```rust
cmd.program        // "gh", "aws", "kubectl"
cmd.args           // vec!["pr", "list", "--author", "@me"]
cmd.raw            // Original command string
cmd.is_subshell    // true if inside $() or ``
cmd.is_pipeline    // true if in a pipeline
```

### Gate Return Values
```rust
// Skip (gate doesn't handle this command)
GateResult::skip()

// Allow (read-only, explicitly safe)
GateResult::allow()

// Ask (mutation, needs approval)
GateResult::ask("Description")

// Block (dangerous, never allow)
GateResult::block("Explanation")
```

### Prefix Matching for Subcommands
```rust
// For commands like "aws ec2 describe-instances" matching "describe" prefix
if args.len() >= 2 && args[0] == "ec2" && args[1].starts_with("describe") {
    return GateResult::allow();
}
```

## Testing

```bash
# Full test suite
cargo test

# With output
cargo test -- --nocapture

# Single test file
cargo test gates::git

# Single test
cargo test test_git_status_allows

# Run only ignored (slow) tests
cargo test -- --ignored
```

### Manual Testing
```bash
# Allow (known safe)
echo '{"tool_name": "Bash", "tool_input": {"command": "git status"}}' | ./target/release/bash-gates
# → {"hookSpecificOutput":{"permissionDecision":"allow",...}}

# Ask (known risky)
echo '{"tool_name": "Bash", "tool_input": {"command": "npm install"}}' | ./target/release/bash-gates
# → {"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"npm: Installing packages"}}

# Ask (unknown command)
echo '{"tool_name": "Bash", "tool_input": {"command": "mamba install numpy"}}' | ./target/release/bash-gates
# → {"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"Unknown command: mamba"}}

# Block (dangerous)
echo '{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}' | ./target/release/bash-gates
# → {"hookSpecificOutput":{"permissionDecision":"deny",...}}

# Ask (respects settings.json deny rule) - if you have Bash(cat /dev/zero*) in deny
echo '{"tool_name": "Bash", "tool_input": {"command": "cat /dev/zero"}, "cwd": "/home/user"}' | ./target/release/bash-gates
# → {"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"Matched settings.json deny rule"}}
```

## Compound Commands

For `&&`, `||`, `|`, `;` chains, **strictest decision wins**:

| Command | Result | Why |
|---------|--------|-----|
| `echo hello && cat file` | allow | Both safe |
| `git status && npm install` | ask | npm asks |
| `mamba activate && git status` | ask | mamba unknown |
| `rm -rf / && echo done` | deny | rm blocks |

## Edge Cases Handled

| Input | Result | Why |
|-------|--------|-----|
| `gh pr list && gh pr create` | ask | Mutation in chain |
| `echo "gh pr create"` | allow | String argument, not command |
| `curl ... \| bash` | ask | Raw string check catches pipe |
| `$(gh pr create)` | ask | tree-sitter detects subshell |
| `git clean -fd --dry-run` | allow | Dry-run checked first |
| `find . -name "*.tmp" \| xargs rm` | ask | xargs pattern check |
| `;rm -rf /` | ask | Leading semicolon check |
| `rm -rf //` | block | Path normalization catches bypass |
| `rm -rf /./` | block | Path normalization catches bypass |
| `mamba install` | ask | Unknown command |
| `randomtool --flag` | ask | Unknown command |

## Dependencies

- `tree-sitter` + `tree-sitter-bash` - Bash AST parsing
- `serde` + `serde_json` - JSON serialization
- `regex` - Pattern matching
- `dirs` - Home directory detection for settings.json

## Claude Code Integration

In `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{
          "type": "command",
          "command": "/path/to/bash-gates/target/x86_64-unknown-linux-musl/release/bash-gates",
          "timeout": 10
        }]
      }
    ]
  }
}
```
