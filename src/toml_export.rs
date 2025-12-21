//! TOML policy export for Gemini CLI.
//!
//! Uses the pre-generated TOML policy from the build process.
//! Output can be saved to ~/.gemini/policies/bash-gates.toml

/// Generate the complete TOML policy file.
///
/// Returns the pre-generated TOML policy from `src/generated/toml_policy.rs`.
pub fn generate_toml() -> String {
    crate::generated::toml_policy::TOML_POLICY.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_toml_not_empty() {
        let toml = generate_toml();
        assert!(!toml.is_empty());
        assert!(toml.contains("[[rule]]"));
        assert!(toml.contains("toolName = \"run_shell_command\""));
    }

    #[test]
    fn test_rules_have_allow_and_deny() {
        let toml = generate_toml();
        assert!(
            toml.contains("decision = \"allow\""),
            "Should have allow rules"
        );
        assert!(
            toml.contains("decision = \"deny\""),
            "Should have deny rules"
        );
        // No ask_user rules needed - Gemini CLI defaults to ask_user
    }

    #[test]
    fn test_uses_gate_definitions() {
        let toml = generate_toml();

        // Should include commands from basics
        assert!(toml.contains("cat"), "Should have cat from basics");

        // Should include commands from git gate
        assert!(
            toml.contains("git status"),
            "Should have git status from git gate"
        );

        // Should include commands from gh gate
        assert!(
            toml.contains("gh pr list"),
            "Should have gh pr list from gh gate"
        );

        // Should include commands from cloud gate
        assert!(
            toml.contains("kubectl get"),
            "Should have kubectl get from cloud gate"
        );
        assert!(
            toml.contains("docker ps"),
            "Should have docker ps from cloud gate"
        );
    }
}
