# Cursor AI Agent Configuration

## Default Agent Setup

This workspace is configured to use **Cursor Agent** as the default agent with **Codex verification** after completion.

## Workflow

1. **Cursor Agent** (Primary)
    - Handles initial task execution
    - Makes code changes automatically
    - Completes the primary task

2. **Codex Verification** (Secondary)
    - Reviews changes made by Cursor Agent
    - Provides verification and feedback
    - Ensures code quality and standards compliance

## Configuration Files

### `.vscode/settings.json`

Contains Cursor-specific agent settings:

- Default agent: Cursor Agent
- Codex verification: Enabled
- Agent workflow: Cursor → Codex verification

### `SecureApp.code-workspace`

Workspace-level settings with the same agent configuration.

### `.cursorrules`

Project-specific rules and guidelines for AI agents.

## Manual Configuration (If Settings Don't Apply)

If the settings don't automatically apply, you can configure manually:

1. Open Cursor Settings (`Cmd/Ctrl + ,`)
2. Search for "Chat" or "Agent"
3. Set "Default Mode" to "Agent"
4. Enable "Verification" or "Codex Review" after agent completion

## Workflow Behavior

When using Cursor Agent:

1. User requests a task
2. Cursor Agent executes the task
3. Upon completion, Codex provides verification/review
4. User reviews and approves changes

This ensures code quality and adherence to project standards.
