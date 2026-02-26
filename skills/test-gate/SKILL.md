---
name: test-gate
description: Test bash-gates against a command to see the permission decision (allow/ask/deny). Use when debugging gate behavior, verifying a new rule, or checking how a command is handled.
argument-hint: [command] [--mode=acceptEdits]
---

# Test a command against bash-gates

Test how bash-gates handles the given command. Pipe JSON to the binary and show the formatted result.

## Instructions

1. Parse `$ARGUMENTS` for the command and optional flags:
   - `--mode=acceptEdits` or `--accept-edits` -- test in acceptEdits permission mode
   - `--pr` or `--permission-request` -- test as a PermissionRequest hook
   - Everything else is the command to test

2. Build the JSON input and pipe it to `bash-gates`:

**PreToolUse (default):**
```bash
echo '{"tool_name": "Bash", "tool_input": {"command": "<COMMAND>"}}' | bash-gates
```

**With acceptEdits mode:**
```bash
echo '{"tool_name": "Bash", "tool_input": {"command": "<COMMAND>"}, "permission_mode": "acceptEdits", "cwd": "'$(pwd)'"}' | bash-gates
```

**PermissionRequest hook:**
```bash
echo '{"tool_name": "Bash", "tool_input": {"command": "<COMMAND>"}, "hook_event_name": "PermissionRequest"}' | bash-gates
```

3. Format the output. Show:
   - The **decision** (allow/ask/deny)
   - The **reason** if present
   - Any **additionalContext** (hints, approval commands)
   - Any **updatedPermissions** (for PermissionRequest)

4. If the result is unexpected, suggest which gate or TOML rule is responsible by checking `rules/*.toml` for the program name.

## Examples

```
/test-gate git status              -> allow (read-only)
/test-gate npm install             -> ask (installing packages)
/test-gate rm -rf /                -> deny (dangerous)
/test-gate sd old new f.txt --mode=acceptEdits  -> allow (auto-approved)
```
