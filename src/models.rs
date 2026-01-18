//! Core types for the bash gates permission system.

use serde::{Deserialize, Serialize};

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
}
