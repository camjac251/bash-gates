//! Core types for the bash gates permission system.
//!
//! Supports two hook types:
//! - `PreToolUse`: Runs before tool execution, can allow/deny/ask
//! - `PermissionRequest`: Runs when internal checks want to ask, can approve for subagents

use serde::{Deserialize, Serialize};

/// Sanitize a path to match Claude Code's project ID format.
/// Replaces non-alphanumeric characters with `-`.
fn sanitize_path(path: &str) -> String {
    path.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect()
}

/// Permission decision types with priority: Block > Ask > Allow > Skip
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Decision {
    Skip = 0,  // Gate doesn't handle this command
    Allow = 1, // Explicitly allowed
    Ask = 2,   // Requires user approval
    Block = 3, // Blocked
}

impl Decision {
    /// Returns the stricter of two decisions (used in tests)
    #[cfg(test)]
    pub fn stricter(self, other: Decision) -> Decision {
        if self > other { self } else { other }
    }
}

/// Information about a parsed command
#[derive(Debug, Clone, Default)]
pub struct CommandInfo {
    /// Original command string
    pub raw: String,
    /// The executable (gh, aws, kubectl, etc.)
    pub program: String,
    /// Arguments after the program
    pub args: Vec<String>,
}

/// Result from a permission gate check
#[derive(Debug, Clone)]
pub struct GateResult {
    pub decision: Decision,
    pub reason: Option<String>,
}

impl GateResult {
    /// Gate doesn't handle this command - pass through
    pub fn skip() -> Self {
        Self {
            decision: Decision::Skip,
            reason: None,
        }
    }

    pub fn allow() -> Self {
        Self {
            decision: Decision::Allow,
            reason: None,
        }
    }

    pub fn allow_with_reason(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Allow,
            reason: Some(reason.into()),
        }
    }

    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Ask,
            reason: Some(reason.into()),
        }
    }

    pub fn block(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Block,
            reason: Some(reason.into()),
        }
    }
}

// === Hook Input/Output Types ===

/// Tool input from Claude Code
#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
pub struct ToolInput {
    #[serde(default)]
    pub command: String,
    pub description: Option<String>,
    pub timeout: Option<u32>,
}

/// Input received by `PreToolUse` hook
#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
pub struct HookInput {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub transcript_path: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: String,
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: ToolInputVariant,
    #[serde(default)]
    pub tool_use_id: String,
}

/// Tool input can be either structured or a raw map
#[derive(Debug, Deserialize, Default)]
#[serde(untagged)]
pub enum ToolInputVariant {
    Structured(ToolInput),
    Map(serde_json::Map<String, serde_json::Value>),
    #[default]
    Empty,
}

impl HookInput {
    /// Extract command string from `tool_input`
    pub fn get_command(&self) -> String {
        match &self.tool_input {
            ToolInputVariant::Structured(ti) => ti.command.clone(),
            ToolInputVariant::Map(m) => m
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            ToolInputVariant::Empty => String::new(),
        }
    }

    /// Extract stable project identifier from `transcript_path`.
    ///
    /// The transcript_path format is:
    /// `~/.claude/projects/<sanitized-project-path>/<session>.jsonl`
    ///
    /// Returns the sanitized project path (e.g., "-home-user-projects-myapp")
    /// which is stable across the session even if `cwd` changes.
    pub fn project_id(&self) -> String {
        // Parse: ~/.claude/projects/<project-id>/<session>.jsonl
        if let Some(projects_idx) = self.transcript_path.find("/projects/") {
            let after_projects = &self.transcript_path[projects_idx + 10..];
            if let Some(slash_idx) = after_projects.find('/') {
                return after_projects[..slash_idx].to_string();
            }
        }
        // Fallback to sanitized cwd if transcript_path not available
        sanitize_path(&self.cwd)
    }
}

/// Updated tool input for modifying commands before execution
#[derive(Debug, Serialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct UpdatedInput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Hook-specific output for `PreToolUse`
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookSpecificOutput {
    pub hook_event_name: String,
    pub permission_decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_decision_reason: Option<String>,
    /// Modify the tool input before execution (e.g., rewrite command)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_input: Option<UpdatedInput>,
    /// Additional context to inject into Claude's conversation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Output format for hooks
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HookOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<HookSpecificOutput>,
}

impl HookOutput {
    /// Return approval (pass-through to settings.json)
    pub fn approve() -> Self {
        Self {
            decision: Some("approve".to_string()),
            hook_specific_output: None,
        }
    }

    /// Return explicit allow (overrides settings.json)
    pub fn allow(reason: Option<&str>) -> Self {
        Self {
            decision: None,
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "allow".to_string(),
                permission_decision_reason: reason.map(String::from),
                updated_input: None,
                additional_context: None,
            }),
        }
    }

    /// Return explicit allow with additional context for Claude
    pub fn allow_with_context(reason: Option<&str>, context: &str) -> Self {
        Self {
            decision: None,
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "allow".to_string(),
                permission_decision_reason: reason.map(String::from),
                updated_input: None,
                additional_context: Some(context.to_string()),
            }),
        }
    }

    /// Return ask for user permission
    pub fn ask(reason: &str) -> Self {
        Self {
            decision: None,
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "ask".to_string(),
                permission_decision_reason: Some(reason.to_string()),
                updated_input: None,
                additional_context: None,
            }),
        }
    }

    /// Return ask with additional context for Claude
    pub fn ask_with_context(reason: &str, context: &str) -> Self {
        Self {
            decision: None,
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "ask".to_string(),
                permission_decision_reason: Some(reason.to_string()),
                updated_input: None,
                additional_context: Some(context.to_string()),
            }),
        }
    }

    /// Return ask with a modified command (safer alternative)
    pub fn ask_with_updated_command(
        reason: &str,
        new_command: &str,
        context: Option<&str>,
    ) -> Self {
        Self {
            decision: None,
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "ask".to_string(),
                permission_decision_reason: Some(reason.to_string()),
                updated_input: Some(UpdatedInput {
                    command: Some(new_command.to_string()),
                    timeout: None,
                    description: None,
                }),
                additional_context: context.map(String::from),
            }),
        }
    }

    /// Return deny (block the command)
    pub fn deny(reason: &str) -> Self {
        Self {
            decision: None,
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: Some(reason.to_string()),
                updated_input: None,
                additional_context: None,
            }),
        }
    }

    /// Return deny with additional context explaining the danger
    pub fn deny_with_context(reason: &str, context: &str) -> Self {
        Self {
            decision: None,
            hook_specific_output: Some(HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: Some(reason.to_string()),
                updated_input: None,
                additional_context: Some(context.to_string()),
            }),
        }
    }
}

// === PermissionRequest Hook Types ===

/// Permission suggestion from Claude Code (what it wants to add)
#[derive(Debug, Deserialize, Clone)]
pub struct PermissionSuggestion {
    #[serde(rename = "type")]
    pub suggestion_type: String,
    #[serde(default)]
    pub directories: Vec<String>,
    #[serde(default)]
    pub rules: Vec<serde_json::Value>,
    #[serde(default)]
    pub behavior: Option<String>,
    #[serde(default)]
    pub destination: Option<String>,
}

/// Input received by `PermissionRequest` hook
#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
pub struct PermissionRequestInput {
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: ToolInputVariant,
    #[serde(default)]
    pub permission_suggestions: Vec<PermissionSuggestion>,
    #[serde(default)]
    /// Optional path that triggered the permission prompt.
    /// May be absent depending on Claude Code version/runtime path.
    pub blocked_path: Option<String>,
    #[serde(default)]
    /// Optional reason from Claude Code for why it prompted.
    /// May be absent depending on Claude Code version/runtime path.
    pub decision_reason: Option<String>,
    #[serde(default)]
    pub tool_use_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: String,
}

impl PermissionRequestInput {
    /// Extract command string from `tool_input`
    pub fn get_command(&self) -> String {
        match &self.tool_input {
            ToolInputVariant::Structured(ti) => ti.command.clone(),
            ToolInputVariant::Map(m) => m
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            ToolInputVariant::Empty => String::new(),
        }
    }
}

/// Decision for PermissionRequest - allow or deny
#[derive(Debug, Serialize)]
#[serde(tag = "behavior")]
pub enum PermissionRequestDecision {
    #[serde(rename = "allow", rename_all = "camelCase")]
    Allow {
        #[serde(skip_serializing_if = "Option::is_none")]
        updated_input: Option<serde_json::Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        updated_permissions: Option<Vec<UpdatedPermission>>,
    },
    #[serde(rename = "deny")]
    Deny {
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        interrupt: Option<bool>,
    },
}

/// Permission update to add (e.g., addDirectories)
#[derive(Debug, Serialize, Clone)]
pub struct UpdatedPermission {
    #[serde(rename = "type")]
    pub permission_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directories: Option<Vec<String>>,
    pub destination: String,
}

/// Hook-specific output for `PermissionRequest`
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestSpecificOutput {
    pub hook_event_name: String,
    pub decision: PermissionRequestDecision,
}

/// Output format for PermissionRequest hooks
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestOutput {
    pub hook_specific_output: PermissionRequestSpecificOutput,
}

impl PermissionRequestOutput {
    /// Approve the permission request (command will execute)
    pub fn allow() -> Self {
        Self {
            hook_specific_output: PermissionRequestSpecificOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision: PermissionRequestDecision::Allow {
                    updated_input: None,
                    updated_permissions: None,
                },
            },
        }
    }

    /// Approve and also add directories to session permissions
    pub fn allow_with_directories(directories: Vec<String>) -> Self {
        Self {
            hook_specific_output: PermissionRequestSpecificOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision: PermissionRequestDecision::Allow {
                    updated_input: None,
                    updated_permissions: Some(vec![UpdatedPermission {
                        permission_type: "addDirectories".to_string(),
                        directories: Some(directories),
                        destination: "session".to_string(),
                    }]),
                },
            },
        }
    }

    /// Deny the permission request
    pub fn deny(message: &str) -> Self {
        Self {
            hook_specific_output: PermissionRequestSpecificOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision: PermissionRequestDecision::Deny {
                    message: Some(message.to_string()),
                    interrupt: None,
                },
            },
        }
    }

    /// Deny and interrupt the agent
    pub fn deny_and_interrupt(message: &str) -> Self {
        Self {
            hook_specific_output: PermissionRequestSpecificOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision: PermissionRequestDecision::Deny {
                    message: Some(message.to_string()),
                    interrupt: Some(true),
                },
            },
        }
    }
}

// === PostToolUse Hook Types ===

/// Input received by `PostToolUse` hook
#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
pub struct PostToolUseInput {
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: ToolInputVariant,
    #[serde(default)]
    pub tool_use_id: String,
    /// Response from the tool execution
    #[serde(default)]
    pub tool_response: Option<serde_json::Value>,
}

impl PostToolUseInput {
    /// Extract command string from `tool_input`
    pub fn get_command(&self) -> String {
        match &self.tool_input {
            ToolInputVariant::Structured(ti) => ti.command.clone(),
            ToolInputVariant::Map(m) => m
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            ToolInputVariant::Empty => String::new(),
        }
    }

    /// Check if the tool response indicates success.
    ///
    /// PostToolUse only fires for successful tool calls — failures trigger
    /// the separate PostToolUseFailure event. So we default to `true` unless
    /// an explicit non-zero exit code is present.
    pub fn is_success(&self) -> bool {
        self.tool_response
            .as_ref()
            .and_then(|r| {
                r.get("exit_code")
                    .or_else(|| r.get("exitCode"))
                    .and_then(|c| c.as_i64())
                    .map(|c| c == 0)
            })
            .unwrap_or(true)
    }
}

/// Hook-specific output for `PostToolUse`
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostToolUseSpecificOutput {
    pub hook_event_name: String,
    /// Additional context to inject into Claude's conversation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Output format for PostToolUse hooks
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostToolUseOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_specific_output: Option<PostToolUseSpecificOutput>,
}

impl PostToolUseOutput {
    /// Return empty output (no action needed)
    pub fn none() -> Self {
        Self {
            hook_specific_output: None,
        }
    }

    /// Return output with additional context
    pub fn with_context(context: &str) -> Self {
        Self {
            hook_specific_output: Some(PostToolUseSpecificOutput {
                hook_event_name: "PostToolUse".to_string(),
                additional_context: Some(context.to_string()),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_ordering() {
        assert!(Decision::Block > Decision::Ask);
        assert!(Decision::Ask > Decision::Allow);
    }

    #[test]
    fn test_decision_stricter() {
        assert_eq!(Decision::Allow.stricter(Decision::Ask), Decision::Ask);
        assert_eq!(Decision::Ask.stricter(Decision::Allow), Decision::Ask);
        assert_eq!(Decision::Block.stricter(Decision::Ask), Decision::Block);
    }

    #[test]
    fn test_hook_output_serialization() {
        let output = HookOutput::allow(Some("Read-only operation"));
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("allow"));
        assert!(json.contains("Read-only operation"));
    }

    #[test]
    fn test_permission_request_allow_uses_camel_case() {
        let output = PermissionRequestOutput::allow_with_directories(vec!["/tmp".to_string()]);
        let json = serde_json::to_string(&output).unwrap();
        assert!(
            json.contains("updatedPermissions"),
            "expected camelCase 'updatedPermissions', got: {json}"
        );
        assert!(
            !json.contains("updated_permissions"),
            "should not contain snake_case 'updated_permissions', got: {json}"
        );
    }

    #[test]
    fn test_permission_request_deny_uses_camel_case() {
        let output = PermissionRequestOutput::deny_and_interrupt("dangerous");
        let json = serde_json::to_string(&output).unwrap();
        // 'message' and 'interrupt' are single words so casing doesn't matter,
        // but 'hookEventName' from the wrapper must be camelCase
        assert!(
            json.contains("hookEventName"),
            "expected camelCase 'hookEventName', got: {json}"
        );
    }
}
