# Cursor Custom Instructions Guide

## Are Custom Instructions Automatically Applied?

**Short Answer**: Yes, but with some nuances.

## How Cursor Applies Custom Instructions

### 1. `.cursorrules` File (Project-Specific)

**Location**: Root of your project (`.cursorrules`)

**Status**: ✅ **Automatically applied** to Cursor Agent and Codex when working in this workspace.

**What it contains**:

- Project-specific coding guidelines
- Agent workflow configuration
- Code style rules (PEP 8, black, type hints)
- Security practices
- Testing requirements
- Documentation standards

**When it applies**:

- Cursor automatically reads `.cursorrules` when you open the workspace
- Both Cursor Agent and Codex use these rules during conversations
- The rules are included as context in every AI interaction

### 2. VS Code/Cursor Settings (`.vscode/settings.json`)

**Status**: ✅ **Applied automatically** for agent configuration and editor behavior.

**What it configures**:

- Default agent (Cursor Agent)
- Codex verification workflow
- Editor formatting (black, isort)
- Python interpreter settings

### 3. Workspace Settings (`SecureApp.code-workspace`)

**Status**: ✅ **Applied automatically** when you open the workspace file.

**What it configures**:

- Same agent configuration as `.vscode/settings.json`
- Workspace-level editor settings

### 4. Global Cursor Settings (Windows AppData)

**Location**: `%APPDATA%\Cursor\User\settings.json` or similar

**Status**: ⚠️ **May override project settings** if conflicts exist.

**Note**: Project settings (`.vscode/settings.json`) typically take precedence over global settings.

### 5. Writing Style Instructions (`docs/ai_custom_directions`)

**Status**: ❓ **Not automatically applied** - This file is informational only.

**To use**: You would need to reference it explicitly or include its contents in `.cursorrules`.

---

## How to Verify Your Instructions Are Applied

### Method 1: Check Cursor UI

1. Open Cursor Settings (`Ctrl/Cmd + ,`)
2. Search for "Chat" or "Agent"
3. Verify:
    - Default Mode: "Agent"
    - Codex Verification: Enabled

### Method 2: Test with a Conversation

Ask Cursor Agent a question that should trigger your custom rules:

```
"Add a new function that validates user input.
Make sure it follows PEP 8 and includes type hints."
```

**Expected behavior**:

- Function should use `snake_case`
- Type hints should be present
- Should follow black formatting (88 char line length)

### Method 3: Check Agent Workflow

When you make a request:

1. Cursor Agent should respond first (primary)
2. Codex should verify/review after (verification)
3. Both should follow rules in `.cursorrules`

---

## Current Configuration Status

### ✅ Configured and Working:

1. **`.cursorrules`** - Contains project-specific guidelines
    - Code style (PEP 8, black, type hints)
    - Security practices
    - Testing requirements (80%+ coverage)
    - Documentation standards

2. **`.vscode/settings.json`** - Agent workflow configured
    - Primary: Cursor Agent
    - Verification: Codex (enabled)
    - Workflow: Cursor → Codex verification

3. **`SecureApp.code-workspace`** - Workspace settings
    - Matches `.vscode/settings.json` configuration

### ⚠️ Potential Issues:

1. **Writing Style Instructions** (`docs/ai_custom_directions`)
    - **Not automatically applied**
    - Currently only in `docs/` folder
    - Not referenced in `.cursorrules`

2. **Global Settings Override**
    - If you have conflicting settings in global Cursor config
    - They might override project settings

---

## Recommendations

### Option 1: Merge Writing Style into `.cursorrules`

If you want the writing style instructions from `docs/ai_custom_directions` to be applied:

Add a section to `.cursorrules`:

```markdown
## Communication Style

- Use clear, straightforward language
- Write short, impactful sentences
- Organize ideas with bullet points
- Use active voice
- [Include other instructions from docs/ai_custom_directions]
```

### Option 2: Verify Global Settings

Check your global Cursor settings to ensure they don't conflict:

**Windows**: `%APPDATA%\Cursor\User\settings.json`

Look for:

- `cursor.chat.defaultAgent` - Should match project or be empty
- `cursor.chat.enableCodexVerification` - Should match project or be empty

### Option 3: Test and Confirm

Run a test conversation to verify rules are being followed:

```
"Write a function that processes user data.
Make sure it follows all our project standards."
```

Then check:

- ✅ Uses PEP 8 naming (`snake_case`)
- ✅ Has type hints
- ✅ Includes docstring
- ✅ Follows black formatting (88 chars)
- ✅ Codex verifies after Cursor Agent completes

---

## Summary

| Configuration               | Auto-Applied? | Applies To               |
| --------------------------- | ------------- | ------------------------ |
| `.cursorrules`              | ✅ Yes        | Cursor Agent & Codex     |
| `.vscode/settings.json`     | ✅ Yes        | Agent workflow, editor   |
| `SecureApp.code-workspace`  | ✅ Yes        | Agent workflow, editor   |
| Global Cursor Settings      | ⚠️ Partial    | May override project     |
| `docs/ai_custom_directions` | ❌ No         | Not automatically loaded |

---

## Quick Fix: Ensure Everything Works

1. **Verify `.cursorrules` is in project root** ✅ (Confirmed)
2. **Check `.vscode/settings.json` exists** ✅ (Confirmed)
3. **Test with a simple request** to confirm rules are followed
4. **Optionally merge** `docs/ai_custom_directions` into `.cursorrules` if you want those writing style rules applied

Your configuration looks correct. The custom instructions **should be automatically applied** to both Cursor Agent and Codex.
