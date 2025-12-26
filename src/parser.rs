//! Bash command parser using tree-sitter-bash for AST parsing.

use crate::models::CommandInfo;
use std::sync::{LazyLock, Mutex};
use tree_sitter::{Parser, Tree, TreeCursor};
use tree_sitter_bash::LANGUAGE;

static PARSER: LazyLock<Mutex<Parser>> = LazyLock::new(|| {
    let mut parser = Parser::new();
    parser
        .set_language(&LANGUAGE.into())
        .expect("Failed to set language");
    std::sync::Mutex::new(parser)
});

/// Extract all commands from a bash command string.
///
/// Handles:
/// - Simple commands: `gh pr list`
/// - Chained commands: `gh pr list && gh pr create`
/// - Pipelines: `gh pr list | head`
/// - Subshells: `$(gh pr create)`
/// - Quoted strings: `echo "gh pr create"` (not treated as gh command)
pub fn extract_commands(command_string: &str) -> Vec<CommandInfo> {
    if command_string.trim().is_empty() {
        return Vec::new();
    }

    let tree = {
        let mut parser = PARSER.lock().unwrap();
        match parser.parse(command_string, None) {
            Some(tree) => tree,
            None => return fallback_parse(command_string),
        }
    };

    let mut commands = Vec::new();
    extract_from_tree(&tree, command_string, &mut commands);

    if commands.is_empty() {
        return fallback_parse(command_string);
    }

    commands
}

fn extract_from_tree(tree: &Tree, source: &str, commands: &mut Vec<CommandInfo>) {
    let mut cursor = tree.walk();
    visit_node(&mut cursor, source, commands);
}

fn visit_node(cursor: &mut TreeCursor, source: &str, commands: &mut Vec<CommandInfo>) {
    let node = cursor.node();
    let kind = node.kind();

    match kind {
        "command" => {
            if let Some(cmd) = extract_command(cursor, source) {
                commands.push(cmd);
            }
        }
        "pipeline" => {
            // Visit each command in the pipeline
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if child.kind() == "command" {
                        if let Some(cmd) = extract_command(cursor, source) {
                            commands.push(cmd);
                        }
                    } else if child.kind() != "|" {
                        // Recurse into non-pipe children
                        visit_node(cursor, source, commands);
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
                cursor.goto_parent();
            }
        }
        "list" | "program" | "subshell" | "command_substitution" | "if_statement"
        | "while_statement" | "for_statement" | "case_statement" | "compound_statement" => {
            // Visit all children
            if cursor.goto_first_child() {
                loop {
                    visit_node(cursor, source, commands);
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
                cursor.goto_parent();
            }
        }
        "function_definition" => {
            // Visit function body
            if cursor.goto_first_child() {
                loop {
                    let child = cursor.node();
                    if child.kind() == "compound_statement" {
                        visit_node(cursor, source, commands);
                    }
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
                cursor.goto_parent();
            }
        }
        _ => {
            // For other node types, try to visit children
            if cursor.goto_first_child() {
                loop {
                    visit_node(cursor, source, commands);
                    if !cursor.goto_next_sibling() {
                        break;
                    }
                }
                cursor.goto_parent();
            }
        }
    }
}

fn extract_command(cursor: &mut TreeCursor, source: &str) -> Option<CommandInfo> {
    let node = cursor.node();
    let raw = node.utf8_text(source.as_bytes()).ok()?.to_string();

    let mut parts: Vec<String> = Vec::new();

    // Walk through command children to get words
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            match child.kind() {
                "word" | "simple_expansion" => {
                    if let Ok(text) = child.utf8_text(source.as_bytes()) {
                        parts.push(text.to_string());
                    }
                }
                "string" | "raw_string" => {
                    // Handle quoted strings - extract the content without quotes
                    if let Ok(text) = child.utf8_text(source.as_bytes()) {
                        let unquoted = unquote(text);
                        parts.push(unquoted);
                    }
                }
                "concatenation" => {
                    // Handle concatenated strings (e.g., "foo"bar)
                    if let Some(text) = extract_concatenation(cursor, source) {
                        parts.push(text);
                    }
                }
                "command_name" => {
                    // Command name can contain word or string
                    if cursor.goto_first_child() {
                        let name_node = cursor.node();
                        if let Ok(text) = name_node.utf8_text(source.as_bytes()) {
                            parts.push(unquote(text));
                        }
                        cursor.goto_parent();
                    }
                }
                _ => {}
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }

    if parts.is_empty() {
        return None;
    }

    let program = parts.remove(0);
    let args = parts;

    Some(CommandInfo { raw, program, args })
}

fn extract_concatenation(cursor: &mut TreeCursor, source: &str) -> Option<String> {
    let mut result = String::new();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if let Ok(text) = child.utf8_text(source.as_bytes()) {
                result.push_str(&unquote(text));
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Remove quotes from a string
fn unquote(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Fallback parser using simple tokenization when tree-sitter fails
fn fallback_parse(command_string: &str) -> Vec<CommandInfo> {
    let mut commands = Vec::new();

    // Simple tokenization - split on whitespace while respecting quotes
    let tokens = tokenize(command_string);
    if tokens.is_empty() {
        return commands;
    }

    let program = tokens[0].clone();
    let args = tokens[1..].to_vec();

    commands.push(CommandInfo {
        raw: command_string.to_string(),
        program,
        args,
    });

    commands
}

/// Simple tokenizer that handles quoted strings
fn tokenize(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape_next = false;

    for c in s.chars() {
        if escape_next {
            current.push(c);
            escape_next = false;
            continue;
        }

        match c {
            '\\' if !in_single_quote => {
                escape_next = true;
            }
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
            }
            ' ' | '\t' if !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_command() {
        let cmds = extract_commands("gh pr list");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "gh");
        assert_eq!(cmds[0].args, vec!["pr", "list"]);
    }

    #[test]
    fn test_chained_commands() {
        let cmds = extract_commands("git status && git add .");
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].program, "git");
        assert_eq!(cmds[1].program, "git");
    }

    #[test]
    fn test_pipeline() {
        let cmds = extract_commands("gh pr list | head");
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].program, "gh");
        assert_eq!(cmds[1].program, "head");
    }

    #[test]
    fn test_quoted_string_not_command() {
        let cmds = extract_commands(r#"echo "gh pr create""#);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "echo");
        // The quoted string should be an argument, not parsed as a command
    }

    #[test]
    fn test_subshell() {
        let cmds = extract_commands("echo $(git status)");
        assert!(!cmds.is_empty());
        // Should detect commands in subshell
    }

    #[test]
    fn test_empty_command() {
        let cmds = extract_commands("");
        assert!(cmds.is_empty());
        let cmds = extract_commands("   ");
        assert!(cmds.is_empty());
    }

    #[test]
    fn test_tokenize() {
        let tokens = tokenize("git commit -m 'hello world'");
        assert_eq!(tokens, vec!["git", "commit", "-m", "hello world"]);
    }

    // === Edge Case Tests ===

    #[test]
    fn test_malformed_quotes_no_panic() {
        // Should not panic on unterminated quotes
        let cmds = extract_commands("echo 'unterminated");
        // Parser should either return something or empty, but not panic
        assert!(cmds.len() <= 1);
    }

    #[test]
    fn test_unicode_command() {
        let cmds = extract_commands("echo '测试' && git status");
        assert!(!cmds.is_empty(), "Should handle unicode");
    }

    #[test]
    fn test_very_long_argument() {
        let long_arg = "x".repeat(10000);
        let cmd = format!("echo {long_arg}");
        let cmds = extract_commands(&cmd);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "echo");
    }

    #[test]
    fn test_many_arguments() {
        let args: Vec<String> = (0..100).map(|i| format!("arg{i}")).collect();
        let cmd = format!("echo {}", args.join(" "));
        let cmds = extract_commands(&cmd);
        assert_eq!(cmds.len(), 1);
    }

    #[test]
    fn test_nested_subshell() {
        let cmds = extract_commands("echo $(echo $(git status))");
        assert!(!cmds.is_empty());
    }

    #[test]
    fn test_escaped_quotes() {
        let cmds = extract_commands(r#"echo "hello\"world""#);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "echo");
    }

    #[test]
    fn test_mixed_quotes() {
        let cmds = extract_commands(r#"echo "it's" 'a "test"'"#);
        assert_eq!(cmds.len(), 1);
    }

    #[test]
    fn test_empty_args() {
        let cmds = extract_commands("echo '' \"\"");
        assert_eq!(cmds.len(), 1);
    }

    #[test]
    fn test_just_operators() {
        // Edge case: just operators, no commands
        let cmds = extract_commands("&& || ;");
        // Should handle gracefully, might be empty
        assert!(
            cmds.is_empty()
                || cmds
                    .iter()
                    .all(|c| c.program.is_empty() || c.program == "&&" || c.program == "||")
        );
    }

    #[test]
    fn test_newlines_in_command() {
        let cmds = extract_commands("echo hello\ngit status");
        assert!(!cmds.is_empty(), "Should handle newlines");
    }

    #[test]
    fn test_tabs_in_command() {
        let cmds = extract_commands("echo\thello\tworld");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "echo");
    }

    #[test]
    fn test_comments_ignored() {
        let cmds = extract_commands("echo hello # this is a comment");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "echo");
    }

    #[test]
    fn test_background_operator() {
        let cmds = extract_commands("sleep 10 &");
        assert!(!cmds.is_empty());
    }

    #[test]
    fn test_heredoc() {
        let cmds = extract_commands("cat <<EOF\nhello\nEOF");
        assert!(!cmds.is_empty());
    }

    // === Property-based Fuzz Tests ===
    // These ensure the parser handles various inputs correctly.
    // Note: Some arbitrary inputs can crash tree-sitter-bash (C library),
    // so we focus on shell-realistic inputs.

    mod fuzz {
        use super::*;
        use proptest::prelude::*;

        // Shell keywords that tree-sitter parses as statements, not commands
        const SHELL_KEYWORDS: &[&str] = &[
            "if", "then", "else", "elif", "fi", "case", "esac", "for", "while", "until", "do",
            "done", "in", "function", "select", "time", "coproc",
        ];

        #[allow(clippy::ptr_arg)]
        fn is_not_shell_keyword(s: &String) -> bool {
            !SHELL_KEYWORDS.contains(&s.as_str())
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(500))]

            #[test]
            fn tokenize_never_panics(s in "[[:print:]]{0,200}") {
                // Tokenizer is pure Rust, should never panic
                let _ = tokenize(&s);
            }

            #[test]
            fn valid_commands_parse_correctly(
                program in "[a-z]{1,10}".prop_filter("not a shell keyword", is_not_shell_keyword),
                args in prop::collection::vec("[a-zA-Z0-9_\\-]{1,20}", 0..10)
            ) {
                let cmd = if args.is_empty() {
                    program.clone()
                } else {
                    format!("{} {}", program, args.join(" "))
                };
                let cmds = extract_commands(&cmd);
                prop_assert!(!cmds.is_empty());
                prop_assert_eq!(&cmds[0].program, &program);
            }

            #[test]
            fn handles_repeated_operators(
                op in prop::sample::select(vec!["&&", "||", ";", "|"]),
                count in 1usize..20
            ) {
                let cmd = format!("echo a {} echo b",
                    std::iter::repeat_n(op, count).collect::<Vec<_>>().join(" echo x "));
                let _ = extract_commands(&cmd);
            }

            #[test]
            fn handles_nested_quotes(depth in 1usize..5) {
                let mut cmd = "echo hello".to_string();
                for _ in 0..depth {
                    cmd = format!("echo \"{cmd}\"");
                }
                let _ = extract_commands(&cmd);
            }

            #[test]
            fn handles_nested_subshells(depth in 1usize..5) {
                let mut cmd = "echo x".to_string();
                for _ in 0..depth {
                    cmd = format!("echo $({cmd})");
                }
                let _ = extract_commands(&cmd);
            }

            #[test]
            fn handles_chained_commands(
                count in 1usize..10,
                sep in prop::sample::select(vec![" && ", " || ", " ; ", " | "])
            ) {
                let cmd = (0..count)
                    .map(|i| format!("cmd{i} arg{i}"))
                    .collect::<Vec<_>>()
                    .join(sep);
                let cmds = extract_commands(&cmd);
                // Should parse without crashing
                prop_assert!(!cmds.is_empty());
            }

            #[test]
            fn handles_various_quoting(
                content in "[a-zA-Z0-9 ]{0,20}",
                quote in prop::sample::select(vec!["'", "\""])
            ) {
                let cmd = format!("echo {quote}{content}{quote}");
                let cmds = extract_commands(&cmd);
                prop_assert_eq!(cmds.len(), 1);
                prop_assert_eq!(&cmds[0].program, "echo");
            }
        }
    }
}
