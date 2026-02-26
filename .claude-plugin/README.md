# bash-gates Plugin

Companion plugin for [bash-gates](https://github.com/camjac251/bash-gates) -- review manually approved commands and promote them to permanent permission rules.

## Overview

When you use bash-gates, commands that aren't recognized as safe require manual approval. Over time, these approvals accumulate. This plugin provides the `/bash-gates:review` skill to batch-review those pending approvals and save patterns to your `settings.json` so you don't get prompted again.

## Prerequisites

The `bash-gates` binary must be installed and hooks configured before using this plugin:

```bash
# Install binary
cargo install --git https://github.com/camjac251/bash-gates

# Or download from releases
curl -Lo ~/.local/bin/bash-gates \
  https://github.com/camjac251/bash-gates/releases/latest/download/bash-gates-linux-amd64
chmod +x ~/.local/bin/bash-gates

# Configure hooks
bash-gates hooks add -s user
```

## Skills

### `/bash-gates:review`

Review commands you've been manually approving and optionally promote them to permanent rules.

**What it does:**

1. Lists pending approvals with counts and suggested glob patterns
2. Presents a numbered checklist for selection
3. Asks which to approve and at what scope
4. Writes selected patterns to `settings.json`
5. Shows final rules summary

**Usage:**

```bash
/bash-gates:review              # review all pending approvals
/bash-gates:review --project    # show project-scoped pending only
```

**Example output:**

```
1. [ ] cargo build --release (12x) -> cargo build:*
2. [ ] npm install (8x) -> npm install:*
3. [ ] git push origin main (3x) -> git push:*
```

**Scopes:**
| Scope | File | Use case |
|-------|------|----------|
| `local` (default) | `.claude/settings.local.json` | Personal project overrides |
| `project` | `.claude/settings.json` | Share with team via git |
| `user` | `~/.claude/settings.json` | All projects globally |

**Permissions:**

| Command                                     | Permission                |
| ------------------------------------------- | ------------------------- |
| `bash-gates pending list`                   | Auto-approved (read-only) |
| `bash-gates rules list`                     | Auto-approved (read-only) |
| `bash-gates approve '<pattern>' -s <scope>` | Requires confirmation     |

## Installation

**From marketplace:**

```bash
/plugin marketplace add camjac251/bash-gates
/plugin install bash-gates@camjac251-bash-gates
```

**From local clone:**

```bash
claude --plugin-dir /path/to/bash-gates
```

## Note on hooks

This plugin does not ship hooks. The `bash-gates` binary handles hook installation via `bash-gates hooks add`, which registers PreToolUse, PermissionRequest, and PostToolUse hooks in your Claude Code settings. See the [main README](https://github.com/camjac251/bash-gates#configure-claude-code) for details.
