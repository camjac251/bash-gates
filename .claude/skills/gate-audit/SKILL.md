---
name: gate-audit
description: This skill should be used when the user asks to "audit gates", "find missing gates", "analyze sessions for edge cases", "check what commands need gates", "find false ask decisions", "mine sessions for read-only commands", or mentions finding commands that should be allowed but aren't.
argument-hint: "[project-path-or-encoded-name]"
---

# Gate Audit -- Mine Sessions for Edge Cases

Analyze Claude Code session logs to find bash commands that are getting incorrect permission decisions, particularly read-only commands that return "ask" when they should return "allow".

## Session File Locations

Claude Code stores session logs at:
```
~/.claude/projects/<encoded-project-path>/<session-uuid>.jsonl
```

The project path is encoded by replacing `/` with `-`. For example:
- `/home/user/projects/myapp` -> `-home-user-projects-myapp`

Sessions with subagents store child logs at:
```
~/.claude/projects/<encoded-path>/<session-uuid>/subagents/agent-<id>.jsonl
```

## Workflow

### 1. Resolve target project

If `$ARGUMENTS` is provided, use it. Accept either:
- A full path (e.g., `/home/user/projects/myapp`)
- An already-encoded name (e.g., `-home-user-projects-myapp`)

Convert paths to encoded form by replacing `/` with `-`.

If no argument, ask which project to audit.

Verify the session directory exists:
```bash
ls ~/.claude/projects/<encoded-path>/
```

### 2. Extract all unique bash commands

Extract from ALL session files including subagents:
```bash
fd -e jsonl . ~/.claude/projects/<encoded-path>/ -x \
  jq -r 'select(.message.content[]?.name == "Bash") |
    .message.content[] | select(.name == "Bash") |
    .input.command' {} 2>/dev/null | sort -u > /tmp/gate-audit-commands.txt
```

**Warning**: jq extraction sometimes captures non-command text (Rust/Python code fragments, commit messages, partial expressions). These get "ask" as "Unknown command" which is correct behavior -- filter them out before analysis.

Report counts:
```bash
# Total files (sessions + subagents)
fd -e jsonl . ~/.claude/projects/<encoded-path>/ | wc -l

# Subagent sessions
fd -e jsonl . ~/.claude/projects/<encoded-path>/ | rg -c subagents

# Total unique commands
wc -l /tmp/gate-audit-commands.txt
```

### 3. Classify every command through bash-gates

Use the release binary (musl target):
```bash
BIN=$(fd bash-gates target/x86_64-unknown-linux-musl/release/ --type f --max-depth 1 \
  -E '*.d' | head -1)
```

If binary not found, build it:
```bash
cargo build --release
```

Run all commands through the hook interface:
```bash
while IFS= read -r cmd; do
  result=$(printf '{"tool_name":"Bash","tool_input":{"command":%s}}' \
    "$(printf '%s' "$cmd" | jq -Rs .)" | \
    $BIN 2>/dev/null | \
    jq -r '.hookSpecificOutput | "\(.permissionDecision // "allow")\t\(.permissionDecisionReason // "-")"')
  printf "%s\t%s\n" "$result" "$cmd"
done < /tmp/gate-audit-commands.txt > /tmp/gate-audit-decisions.txt
```

**Important**: This can take several minutes for large command sets. Use `run_in_background` for 500+ commands.

### 4. Analyze results

Summarize decision counts:
```bash
cut -f1 /tmp/gate-audit-decisions.txt | sort | uniq -c | sort -rn
```

Extract "ask" commands with reasons, filtering out code fragments (jq extraction sometimes captures non-command text):
```bash
rg '^ask\t' /tmp/gate-audit-decisions.txt | cut -f2-
```

### 5. Identify read-only edge cases

For each "ask" command, evaluate whether it's genuinely read-only:

**Likely should be `allow` (read-only):**
- Version/help flags: `--version`, `-V`, `--help`, `-h`
- List/query subcommands: `list`, `show`, `status`, `info`, `search`, `registry`
- Git read-only plumbing: `check-ignore`, `check-attr`, `grep`, `merge-base`, `show-ref`
- Shell builtins used in pipes: `read` in `while read` loops
- Tool discovery: `which`, `command -v`, `type`

**Should remain `ask` (mutations):**
- File writes: `mkdir`, `mv`, `cp`, `rm`, `rmdir`, `touch`, `cat >`
- Git mutations: `add`, `commit`, `push`, `pull`, `clone`, `stash`
- Package installs: `cargo install`, `npm install`, `pip install`
- In-place edits: `sd`, `sed -i`, `rustfmt` (without `--check`)
- Network mutations: `curl -X POST`, `git push`

**Should be `ask` but with better categorization (not "Unknown command"):**
- Commands handled by no gate -- add to appropriate gate file

### 6. Propose fixes

For each edge case found, identify which file to modify:

| Fix type | Where |
|----------|-------|
| New allow subcommand | `rules/<gate>.toml` -- add `[[programs.allow]]` entry |
| New program to existing gate | `rules/<gate>.toml` -- add `[[programs]]` section + wire in `src/gates/<gate>.rs` match arm |
| New safe command | `rules/basics.toml` -- add to `safe_commands` list |
| Move ask to allow | `rules/<gate>.toml` -- change `[[programs.ask]]` to `[[programs.allow]]` |

**Critical**: When adding programs to TOML, also check the gate's Rust match statement in `src/gates/<gate>.rs`. Generated rules are only effective if the custom handler routes the program to the declarative function. This is the most common gotcha.

### 7. Verify and test

After making changes:
```bash
cargo build --release
cargo test
```

Re-run the full audit to confirm the ask count dropped:
```bash
# Same classification loop from step 3
```

Present before/after comparison.

## Reference: JSONL Extraction Patterns

| Need | jq command |
|------|-----------|
| All Bash commands | `select(.message.content[]?.name == "Bash") \| .message.content[] \| select(.name == "Bash") \| .input.command` |
| Human messages | `select(.type == "user" and (.message.content \| type == "string")) \| .message.content` |
| Tool use counts | Group by `.name` on `tool_use` type blocks |
| Session title | `select(.type == "summary") \| .summary` |

## Reference: bash-gates Hook Input Format

```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "the command to test"
  }
}
```

Pipe to the binary via stdin. Output JSON has `.hookSpecificOutput.permissionDecision` (`allow`/`ask`/`deny`) and `.hookSpecificOutput.permissionDecisionReason`.

Empty output means `allow` (the hook returns nothing for allowed commands in some paths).
