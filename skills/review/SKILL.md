---
name: review
description: Review commands you've been manually approving and optionally make them permanent. Shows counts, suggests patterns, lets you multi-select which to always allow.
argument-hint: "[--project]"
---

# Review Pending Approvals

1. Run `bash-gates pending list $ARGUMENTS` to get pending approvals.

2. If no pending approvals, tell the user and stop.

3. Present as a numbered list using the first suggested pattern for each:
   ```
   1. [ ] cargo build --release (12x) -> cargo build:*
   2. [ ] npm install (8x) -> npm install:*
   3. [ ] git push origin main (3x) -> git push:*
   ```
   If multiple patterns are suggested, show the most specific one. Mention alternatives briefly (e.g., "or broader: cargo:*").

4. Ask the user which to approve (e.g., "1, 3" or "all") and at what scope:
   - **local** (default) -- just you, this project
   - **project** -- shared with team via git
   - **user** -- all projects globally

5. For each selection, run `bash-gates approve '<pattern>' -s <scope>`.

6. Show final rules with `bash-gates rules list`.

Warn about overly broad patterns (e.g., `git:*` allows force-push). Low-count commands (1-2x) may be one-offs worth skipping.
