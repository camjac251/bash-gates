# Bash Gates - Claude Code Permission Hook (Rust)

Intelligent bash command permission gate using tree-sitter AST parsing. Auto-allows known safe operations, asks for writes and unknown commands, blocks dangerous patterns.

**Claude Code:** Use as a PreToolUse hook (native integration)
**Gemini CLI:** Use `--export-toml` to generate policy rules

## Quick Reference

```bash
# Test a command
echo '{"tool_name": "Bash", "tool_input": {"command": "gh pr list"}}' | ./target/x86_64-unknown-linux-musl/release/bash-gates

# Export Gemini CLI policy rules
./target/x86_64-unknown-linux-musl/release/bash-gates --export-toml > ~/.gemini/policies/bash-gates.toml

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
├── router.rs        # Raw string security checks + gate routing + task expansion
├── settings.rs      # settings.json parsing and pattern matching
├── mise.rs          # Mise task file parsing and command extraction
├── package_json.rs  # package.json script parsing and command extraction
└── gates/           # 12 specialized permission gates
    ├── mod.rs           # Gate registry
    ├── basics.rs        # Safe shell commands (echo, cat, ls, grep, etc.)
    ├── beads.rs         # Beads issue tracker CLI (bd)
    ├── mcp.rs           # MCP CLI (mcp-cli)
    ├── gh.rs            # GitHub CLI
    ├── git.rs           # Git commands
    ├── shortcut.rs      # Shortcut.com CLI (short)
    ├── cloud.rs         # AWS, gcloud, terraform, kubectl, docker, helm, pulumi, az
    ├── network.rs       # curl, wget, ssh, scp, rsync, netcat
    ├── filesystem.rs    # rm, mv, cp, chmod, tar, zip
    ├── devtools.rs      # sd, ast-grep, yq, jq, semgrep, biome, prettier
    ├── package_managers.rs  # npm, pnpm, yarn, pip, uv, cargo, go, bun
    └── system.rs        # psql, mysql, make, sudo, systemctl, kill, crontab
```

## How It Works

1. **Input**: JSON from Claude Code's PreToolUse hook (includes `cwd`, `permission_mode`)
2. **Mise expansion**: If command is `mise run <task>` or `mise <task>`, expand to underlying commands
3. **Package.json expansion**: If command is `npm run <script>`, `pnpm run <script>`, etc., expand to underlying command
4. **Gate analysis**: Security checks (raw string patterns) + tree-sitter parsing + gate checks; strictest decision wins
5. **If blocked**: Deny immediately (dangerous commands always blocked, regardless of settings)
6. **Load settings**: Merge settings.json from all locations
7. **Settings deny**: If command matches deny rules, deny immediately
8. **Accept Edits Mode**: If `permission_mode` is `acceptEdits` and command is file-editing within allowed directories, auto-allow
9. **Settings ask/allow**: Check remaining settings.json rules
10. **Output**: JSON with `permissionDecision` (allow/ask/deny)

## Mise Task Expansion (mise.rs)

When bash-gates sees `mise run <task>` or `mise <task>`, it automatically:

1. Finds the mise config file (`.mise.toml` or `mise.toml`) in cwd or parent directories
2. Parses the TOML and extracts the task's `run` command
3. Recursively includes commands from `depends = [...]` tasks
4. Handles `dir = "..."` by prepending `cd <dir> &&`
5. Passes all extracted commands through the gate engine
6. Returns the strictest decision from all commands

### Examples

```bash
# mise.toml
[tasks.lint]
run = "pnpm lint"

[tasks."lint:fix"]
run = "pnpm lint:fix"
depends = ["lint"]

[tasks."dev:frontend"]
dir = "web"
run = "pnpm dev"
```

| Command | Extracted | Decision |
|---------|-----------|----------|
| `mise run lint` | `pnpm lint` | ask (pnpm) |
| `mise lint:fix` | `pnpm lint`, `pnpm lint:fix` | ask (both pnpm) |
| `mise dev:frontend` | `cd web && pnpm dev` | allow (dev is safe) |

### Edge Cases

| Input | Result | Why |
|-------|--------|-----|
| `mise install` | Not expanded | Built-in mise subcommand |
| `mise nonexistent` | ask | Task not found |
| `mise run danger` (if run = `rm -rf /`) | deny | Blocked command in task |
| Circular dependencies | Handled | Uses visited set |

## Package.json Script Expansion (package_json.rs)

When bash-gates sees `npm run <script>`, `pnpm run <script>`, `yarn <script>`, etc., it:

1. Finds `package.json` in cwd or parent directories
2. Parses JSON and extracts the script's command
3. Passes the underlying command through the gate engine
4. Returns the result with context

### Examples

```json
// package.json
{
  "scripts": {
    "lint": "biome check .",
    "lint:fix": "biome check --write .",
    "dev": "vite",
    "test": "vitest run"
  }
}
```

| Command | Extracted | Decision |
|---------|-----------|----------|
| `pnpm run lint` | `biome check .` | allow |
| `pnpm run lint:fix` | `biome check --write .` | ask (writes files) |
| `pnpm run dev` | `vite` | allow |
| `npm run test` | `vitest run` | allow |
| `yarn lint` | `biome check .` | allow |

### Shorthand Support

- `pnpm lint` → expands to `pnpm run lint`
- `yarn test` → expands to `yarn run test`
- `npm run build` → requires explicit `run`

## Settings.json Integration (settings.rs)

bash-gates combines gate analysis with your Claude Code permission rules. Gate blocks take priority (dangerous commands always denied), then settings.json deny rules, then acceptEdits mode:

```
┌─────────────────────────────────────────────────────────────┐
│                    Decision Flow                             │
├─────────────────────────────────────────────────────────────┤
│  1. Run bash-gates analysis first                           │
│     └─ gate blocks  → deny directly (dangerous always blocked) │
│  2. Load settings.json (all locations, merged)              │
│  3. Check settings.json DENY rules                          │
│     └─ matches deny  → deny directly                        │
│  4. acceptEdits mode + file-editing command                 │
│     └─ auto-allow (if not blocked or denied above)          │
│  5. Check settings.json ask/allow rules                     │
│     ├─ matches ask   → return ask (defer to CC)             │
│     └─ matches allow → return allow                         │
│  6. No settings match → use gate result (allow/ask)         │
└─────────────────────────────────────────────────────────────┘
```

### Settings File Locations

Settings are loaded from all Claude Code settings files (merged, higher priority overrides):

| Priority | Location | Description |
|----------|----------|-------------|
| 1 (highest) | `/etc/claude-code/managed-settings.json` | Enterprise managed (Linux) |
| 2 | `.claude/settings.local.json` | Local project (not committed) |
| 3 | `.claude/settings.json` | Shared project (committed) |
| 4 (lowest) | `~/.claude/settings.json` | User settings |

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

**Gate blocks always win:** Commands like `rm -rf /` are denied directly, regardless of settings.json. This ensures dangerous commands are always blocked.

**Settings.json respected for non-blocked commands:** If you have `Bash(cat /dev/zero*)` in deny and a gate would allow `cat`, bash-gates returns `ask` to defer to Claude Code, which then applies your deny rule.

## Accept Edits Mode (router.rs)

When `permission_mode` is `acceptEdits`, file-editing commands are auto-allowed if:
1. The command is a known file-editing program (formatters, linters, text replacement)
2. The target files are within allowed directories (cwd + `additionalDirectories` from settings.json)
3. The target files are not sensitive system paths or credentials

### Additional Directories

The `additionalDirectories` setting from `~/.claude/settings.json` or `.claude/settings.json` is respected:

```json
{
  "permissions": {
    "additionalDirectories": ["~/other-project", "/tmp/workspace"]
  }
}
```

Files in these directories are treated as "within project" for acceptEdits mode.

```bash
# Auto-allowed in acceptEdits mode
sd 'old' 'new' file.txt           # Text replacement
prettier --write src/             # Code formatting
ast-grep -p 'old' -r 'new' -U .   # Code refactoring
sed -i 's/foo/bar/g' file.txt     # In-place sed
black src/                        # Python formatting
eslint --fix src/                 # Linting with fix
yq -i '.key = "value"' file.yaml  # YAML editing
rustfmt src/main.rs               # Rust formatting
```

### File-Editing Programs

| Category | Programs |
|----------|----------|
| Text replacement | `sd`, `sed -i`, `patch`, `dos2unix` |
| Formatters | `prettier --write`, `black`, `rustfmt`, `go fmt`, `gofmt -w`, `clang-format`, `shfmt`, `stylua` |
| Linters with fix | `eslint --fix`, `biome --fix`, `ruff format`, `rubocop -a`, `golangci-lint --fix` |
| Code refactoring | `ast-grep -U`, `sg -U` |
| Data editing | `yq -i` |

### Still Requires Approval (even in acceptEdits)

- Package managers: `npm install`, `cargo add`
- Git operations: `git push`, `git commit`
- Deletions: `rm file.txt`
- Network: `curl -X POST`, `ssh`
- Paths outside cwd: `sd 'a' 'b' /other/project/file.txt`, `prettier --write ~/file.js`
- Parent directory escapes: `sd 'a' 'b' ../../file.txt`
- Blocked commands: `rm -rf /` still denied

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
| `fd -x rm`, `fd --exec rm` | ask | fd executing dangerous command |
| `$(rm ...)`, `` `rm ...` `` | ask | Dangerous command substitution |
| `;rm -rf /` | ask | Leading semicolon (injection) |
| `> file`, `>> file`, `&> file` | ask | Output redirection |

## Gate Coverage

### basics.rs - Safe Shell Commands
~130+ known-safe commands that are always allowed:
- **Display**: `echo`, `printf`, `cat`, `head`, `tail`, `less`, `more`, `bat`, `batcat`
- **Listing**: `ls`, `eza`, `lsd`, `tree`, `find`, `fd`, `locate`, `which`, `whereis`, `type`
- **Text processing**: `grep`, `rg`, `awk`, `sed` (without -i), `cut`, `sort`, `uniq`, `wc`, `tr`, `diff`, `cmp`
- **File info**: `file`, `stat`, `du`, `df`, `lsof`, `readlink`, `realpath`, `basename`, `dirname`
- **Process/system**: `ps`, `top`, `htop`, `btop`, `procs`, `pgrep`, `uptime`, `whoami`, `id`, `uname`, `hostname`, `date`, `cal`, `free`, `nproc`, `lscpu`
- **Network info**: `ping`, `traceroute`, `mtr`, `dig`, `nslookup`, `host`, `whois`, `ss`, `netstat`, `ip`, `ifconfig`
- **Archive listing**: `zipinfo`, `unrar` (listing only)
- **Dev tools**: `jq`, `yq`, `gron`, `fx`, `tokei`, `cloc`, `scc`, `hexdump`, `xxd`, `hexyl`, `base64`, `delta`, `difft`, `dust`, `fselect`
- **Checksums**: `sha256sum`, `md5sum`, `sha1sum`, `b2sum`, `cksum`
- **Help**: `man`, `info`, `help`, `tldr`, `cheat`
- **Misc**: `true`, `false`, `seq`, `expr`, `bc`, `sleep`, `pwd`, `cd`, `printenv`, `export`, `test`
- **Custom handlers**: `xargs` (safe only with known-safe target), `bash -c`/`sh -c` (parses inner script)

### beads.rs - Beads Issue Tracker CLI
Handles `bd` (beads) issue tracker commands:
- **Allow**: `list`, `show`, `ready`, `blocked`, `search`, `stats`, `doctor`, `dep tree`, `label list`, `prime`
- **Ask**: `create`, `update`, `close`, `delete`, `sync`, `init`, `dep add`, `label add`, `comments add`
- No blocked commands (all recoverable via git)

### mcp.rs - MCP CLI
Handles `mcp-cli` commands for Model Context Protocol servers:
- **Allow**: `servers`, `tools`, `info`, `grep`, `resources`, `read`, `help` (discovery commands)
- **Ask**: `call` (invokes MCP tools - checks settings.json for MCP permissions)

MCP permissions in settings.json use patterns:
- `mcp__<server>` - allow entire server
- `mcp__<server>__<tool>` - allow specific tool
- `mcp__<server>__*` - allow all tools on server (wildcard)

Example settings.json:
```json
{
  "permissions": {
    "allow": ["mcp__docs", "mcp__search__*"],
    "deny": ["mcp__docs__dangerous_tool"]
  }
}
```

### gh.rs - GitHub CLI
- **Allow**: `pr list`, `issue view`, `repo view`, `search`, `api` (GET)
- **Ask**: `pr create`, `pr merge`, `issue create`, `api` (POST/PUT/DELETE)
- **Block**: `repo delete`, `auth logout`

### shortcut.rs - Shortcut.com CLI
Handles `short` CLI for Shortcut.com project management:
- **Allow**: `search`, `find`, `story` (view only), `members`, `epics`, `workflows`, `projects`, `workspace` (list), `help`
- **Ask**: `create`, `install`, `story` (with update flags like `--state`, `--title`, `--comment`), `search --save`, `api` (POST/PUT/DELETE)

### git.rs - Git
- **Allow**: `status`, `log`, `diff`, `show`, `branch -a`, `--dry-run` commands
- **Ask**: `add`, `commit`, `push`, `pull`, `merge`, `checkout`, `branch -d`
- **Ask (warning)**: `push --force`, `reset --hard`, `clean -fd`

### cloud.rs - Cloud CLIs
- **AWS**: `describe-*`/`list-*`/`get-*` allow, `create`/`delete`/`put` ask, `iam delete-user` block
- **gcloud**: `list`/`describe` allow, `create`/`delete`/`deploy` ask
- **terraform/tofu**: `plan`/`show` allow, `apply`/`destroy` ask
- **kubectl**: `get`/`describe`/`logs` allow, `apply`/`delete`/`exec` ask, `delete ns kube-system` block
- **docker**: `ps`/`images`/`logs` allow, `run`/`build`/`push` ask; `compose` subcommands supported (handles flags like `-f`)
- **podman**: `ps`/`images`/`logs`/`pod ps` allow, `run`/`build`/`push`/`play` ask
- **az**: `list`/`show` allow, `create`/`delete`/`start`/`stop`/`restart` ask
- **helm**: `list`/`get`/`show`/`template` allow, `install`/`upgrade`/`uninstall` ask
- **pulumi**: `preview`/`stack ls` allow, `up`/`destroy`/`refresh` ask

### network.rs - Network Tools
- **curl**: HEAD (`-I`) allow, GET allow by default, POST/PUT/DELETE/PATCH ask, `-o`/`-O` (download) ask, `-d`/`--data` implies mutation
- **wget**: `--spider` allow (just checks URLs), `-O`/`-r`/`-m`/`--post-*` ask
- **ssh/scp/sftp**: always ask (remote connections)
- **rsync**: `-n`/`--dry-run` allow (preview), otherwise ask
- **netcat** (`nc`/`ncat`): `-e` block (reverse shell risk), `-l` ask (listen mode), connections ask
- **HTTPie** (`http`/`https`/`xh`): GET allow, POST/PUT/DELETE/PATCH ask

### filesystem.rs - Filesystem
- **Allow**: `tar -t`/`tar --list` (list contents), `unzip -l` (list contents)
- **Ask**: `rm`, `mv`, `cp`, `mkdir`, `touch`, `chmod`, `chown`, `chgrp`, `ln`, `tar -x`/`tar -c`, `sed -i`, `perl` (can execute arbitrary code), `zip`
- **Block**: `rm -rf /`, `rm -rf ~`, `rm -rf /*`, path traversal with normalization (`//`, `/./`, `/../`)

### devtools.rs - Developer Tools
Handles ~50+ developer tools with write-flag detection:
- **Always safe**: `jq`, `shellcheck`, `hadolint`, `actionlint`, `vite`, `vitest`, `jest`, `mocha`, `tsc`, `tsup`, `esbuild`, `turbo`, `nx`, `knip`, `oxlint`
- **Safe by default, ask with write flags**:
  - `ast-grep`/`sg`: search safe, `-U`/`--update-all` asks
  - `yq`: read safe, `-i`/`--inplace` asks
  - `semgrep`: scan safe, `--autofix`/`--fix` asks
  - `sad`: preview safe, `--commit` asks
  - `prettier`: safe, `--write`/`-w` asks
  - `eslint`: safe, `--fix` asks
  - `biome`: `check`/`lint` safe, `--write`/`--fix` asks
  - `ruff`: `check` safe, `check --fix` or `format` asks
  - `black`/`isort`: `--check`/`--diff` safe, otherwise asks
  - `gofmt`/`goimports`/`shfmt`: safe, `-w` asks
  - `rustfmt`/`stylua`: `--check` safe, otherwise asks
  - `golangci-lint`: safe, `--fix` asks
  - `rubocop`/`standardrb`: safe, `-a`/`--auto-correct` asks
  - `patch`: `--dry-run` safe, otherwise asks
  - `clang-format`/`autopep8`: safe, `-i` asks
- **Always ask**: `sd` (always writes), `watchexec` (runs commands), `dos2unix`/`unix2dos`, `dartfmt`, `elm-format`

### package_managers.rs - Package Managers
- **Allow**: `list`, `show`, `test`, `build`, `check`, `lint`, `dev`
- **Ask**: `install`, `add`, `remove`, `publish`, `init`, `run` (executes scripts), `fmt` (modifies files)
- Covers: npm, pnpm, yarn, pip, uv, cargo, go, bun, conda, mamba, poetry, pipx, mise
- **mise**: `ls`/`doctor`/`reshim`/`exec` allow, `install`/`use`/`upgrade` ask (task expansion handled separately)

### system.rs - System Commands
- **Database**: `psql -l` allow, `psql -c SELECT` allow, `psql -c INSERT`/`psql -f` ask; `pg_dump` allow, `pg_restore` ask
- **Database CLIs**: `mysql`, `sqlite3`, `mongosh`, `redis-cli` - query commands parsed
- **Database migrations**: `migrate`, `goose`, `dbmate`, `flyway`, `alembic` - always ask
- **Build tools**:
  - `make`: `-n`/`--dry-run` allow, `test`/`build`/`clean`/`fmt` allow, other targets ask
  - `cmake`: `--view-only` allow, otherwise ask
  - `ninja`, `just`, `task`: list commands allow, others ask
  - `gradle`/`maven`: `tasks`/`help`/`test`/`build` allow, `publish`/`deploy` ask
  - `bazel`: `info`/`query`/`build`/`test` allow, `run`/`clean` ask
  - `meson`, `ansible`, `vagrant`, `hyperfine`: various patterns
- **sudo/doas**: `-l`/`-v`/`-k` allow, describes underlying command (e.g., "sudo: Installing packages (apt)")
- **systemctl**: `status`/`show`/`list-*`/`is-*`/`cat` allow, `start`/`stop`/`restart`/`enable`/`disable` ask
- **Process**: `kill -0`/`kill -l` allow, `kill`/`pkill`/`killall` ask
- **Crontab**: `crontab -l` allow, `crontab -e` ask
- **Block**: `shutdown`, `reboot`, `poweroff`, `halt`, `init`, `mkfs`, `fdisk`, `parted`, `gdisk`, `dd`, `shred`, `wipe`, `useradd`, `userdel`, `passwd`, `iptables`, `ufw`, `mount` (partial), `insmod`, `rmmod`, `modprobe`, `grub-install`

### system.rs - OS Package Managers
- **apt/apt-get**: `list`/`search`/`show` allow, `install`/`remove`/`upgrade` ask
- **dnf/yum**: `list`/`info`/`search` allow, `install`/`remove`/`update` ask
- **pacman/yay/paru**: `-Q` (query) allow, `-S`/`-R` (sync/remove) ask
- **brew**: `list`/`search`/`info` allow, `install`/`uninstall`/`upgrade` ask
- **nix/nix-env**: `-q` (query) allow, `-i`/`-e` (install/uninstall) ask
- **flatpak/snap**: `list`/`info` allow, `install`/`remove` ask
- **zypper/apk**: `search`/`info` allow, `install`/`remove` ask

## Adding a Tool to an Existing Gate

For most tools, just edit the TOML and rebuild - no Rust changes needed.

**Example: Adding shellcheck to devtools**

```toml
# rules/devtools.toml
[[programs]]
name = "shellcheck"
unknown_action = "allow"  # Always safe (read-only)
```

Then `cargo build --release`. Done.

**Example: Tool with flag-conditional behavior**

```toml
# rules/devtools.toml
[[programs]]
name = "prettier"
unknown_action = "allow"

[[programs.ask]]
reason = "Writing formatted files"
if_flags_any = ["--write", "-w"]
```

**Available TOML options:**

| Field | Description |
|-------|-------------|
| `name` | Program name |
| `aliases` | Alternative names (e.g., `["podman"]` for docker) |
| `unknown_action` | What to do for unknown subcommands: `allow`, `ask`, `skip`, `block` |
| `[[programs.allow]]` | Rules that allow (with optional conditions) |
| `[[programs.ask]]` | Rules that ask (requires `reason`) |
| `[[programs.block]]` | Rules that block (requires `reason`) |

**Rule conditions:**

| Field | Description |
|-------|-------------|
| `subcommand` | Match specific subcommand (e.g., `"pr list"`) |
| `subcommand_prefix` | Match subcommand prefix (e.g., `"describe"` matches `describe-instances`) |
| `if_flags_any` | Ask/allow only if any of these flags present |
| `unless_flags` | Allow unless any of these flags present |
| `if_args_contain` | Block if args contain these values |

**Custom handlers:** If a tool needs complex logic beyond TOML, add to `[[custom_handlers]]`:

```toml
[[custom_handlers]]
program = "ruff"
handler = "check_ruff"
description = "ruff format asks unless --check or --diff present"
```

Then implement `check_ruff` in the gate file. The generated gate returns `Skip` for this program, letting the custom handler take over.

## Adding a New Gate

For a new category of tools (not fitting existing gates):

1. Create `rules/newgate.toml`:

```toml
[meta]
name = "newgate"
description = "New category of tools"
priority = 50

[[programs]]
name = "newtool"
unknown_action = "ask"

[[programs.allow]]
subcommand = "list"

[[programs.ask]]
subcommand = "create"
reason = "Creating resource"
```

2. Create `src/gates/newgate.rs` (uses generated gate function):

```rust
use crate::generated::rules::check_newgate_gate;
use crate::models::{CommandInfo, GateResult};

pub fn check_newgate(cmd: &CommandInfo) -> GateResult {
    check_newgate_gate(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::test_utils::cmd;
    use crate::models::Decision;

    #[test]
    fn test_newtool_list_allows() {
        let result = check_newgate(&cmd("newtool", &["list"]));
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_newtool_create_asks() {
        let result = check_newgate(&cmd("newtool", &["create"]));
        assert_eq!(result.decision, Decision::Ask);
    }
}
```

3. Register in `gates/mod.rs`:

```rust
mod newgate;
pub use newgate::check_newgate;

pub static GATES: &[(&str, GateCheckFn)] = &[
    // ... other gates ...
    ("newgate", check_newgate),
    ("basics", check_basics), // basics should be last
];
```

## Key Patterns

### CommandInfo Fields
```rust
cmd.program        // "gh", "aws", "kubectl"
cmd.args           // vec!["pr", "list", "--author", "@me"]
cmd.raw            // Original command string
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
# → {"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"conda: Installing packages"}}

# Block (dangerous)
echo '{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}' | ./target/release/bash-gates
# → {"hookSpecificOutput":{"permissionDecision":"deny",...}}

# Accept Edits Mode - auto-allow file editing
echo '{"tool_name": "Bash", "tool_input": {"command": "sd old new file.txt"}, "permission_mode": "acceptEdits"}' | ./target/release/bash-gates
# → {"hookSpecificOutput":{"permissionDecision":"allow","permissionDecisionReason":"Auto-allowed in acceptEdits mode"}}

# Accept Edits Mode - still asks for non-file-editing
echo '{"tool_name": "Bash", "tool_input": {"command": "npm install"}, "permission_mode": "acceptEdits"}' | ./target/release/bash-gates
# → {"hookSpecificOutput":{"permissionDecision":"ask",...}}

# Accept Edits Mode - asks for paths outside cwd
echo '{"tool_name": "Bash", "tool_input": {"command": "sd old new /other/file.txt"}, "permission_mode": "acceptEdits", "cwd": "/home/user/project"}' | ./target/release/bash-gates
# → {"hookSpecificOutput":{"permissionDecision":"ask",...}}
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
| `fd -t d .venv -x rm -rf {}` | ask | fd exec pattern check |
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

## Gemini CLI Integration

Gemini CLI's hook system cannot prompt users (only allow/block). Use the policy engine instead:

```bash
# Generate and install policy rules
bash-gates --export-toml > ~/.gemini/policies/bash-gates.toml
```

This exports 700+ policy rules (pulled from actual gate definitions) with proper `ask_user` support:
- **deny** (priority 900+): Dangerous commands like `rm -rf /`, `gh repo delete`
- **allow** (priority 100-199): Safe read-only commands like `git status`, `ls`
- **ask_user** (priority 200-299): Risky commands like `npm install`, `git push`
- **ask_user** (priority 1): Default fallback for unknown commands
