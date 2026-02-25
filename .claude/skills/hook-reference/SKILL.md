---
name: hook-reference
description: Detailed hook input/output JSON formats for PreToolUse, PermissionRequest, and PostToolUse hooks. Use when working on hook handlers, debugging hook behavior, or modifying models.rs.
user-invocable: false
---

# Hook Input/Output Reference

## PermissionRequest Input Fields

| Field | Type | Description |
|-------|------|-------------|
| `hook_event_name` | `"PermissionRequest"` | Identifies the hook type |
| `tool_name` | `"Bash"` | Always "Bash" for our hooks |
| `tool_input` | `{"command": "..."}` | The command being requested |
| `decision_reason` | `string` (optional) | Why Claude Code is asking (e.g., "Path is outside allowed working directories") |
| `blocked_path` | `string` (optional) | The specific path that triggered the prompt |
| `agent_id` | `string` (optional) | Present for subagents, absent for main session |

### PermissionRequest Output (approve with directory access)

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": {
      "behavior": "allow",
      "updatedPermissions": [{
        "type": "addDirectories",
        "directories": ["/path/to/allow"],
        "destination": "session"
      }]
    }
  }
}
```

### PermissionRequest Output (deny)

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": {
      "behavior": "deny",
      "reason": "Dangerous command blocked"
    }
  }
}
```

### PermissionRequest Output (pass through)

Return empty/no output to let the normal permission prompt show.

## PostToolUse Input Fields

| Field | Type | Description |
|-------|------|-------------|
| `hook_event_name` | `"PostToolUse"` | Identifies the hook type |
| `tool_name` | `"Bash"` | Always "Bash" for our hooks |
| `tool_use_id` | `string` | Unique ID to correlate with PreToolUse tracking |
| `tool_response` | `object` | Command result including `exit_code`, `stdout`, `stderr` |

PostToolUse output is currently empty (silent) to avoid cluttering Claude's context.

## PreToolUse Output Format

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow|ask|deny",
    "permissionDecisionReason": "Human-readable reason",
    "additionalContext": "Optional hints for Claude"
  }
}
```

## Serde Casing

All JSON output uses **camelCase** field names (`hookEventName`, `permissionDecision`, `updatedPermissions`). This is enforced by `#[serde(rename_all = "camelCase")]` on the output structs in `models.rs`. Any new fields must follow this convention and have test coverage asserting the exact casing.
