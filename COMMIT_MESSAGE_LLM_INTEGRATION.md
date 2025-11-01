# Commit Message LLM Integration Guide

## Overview

The commit message generation system supports multiple methods, from simple heuristics to LLM-powered analysis.

## Methods (in priority order)

### 1. LLM-Enhanced Generation (Best Quality) ⭐

Uses AI to analyze git diffs and generate contextual commit messages.

**Requirements:**

- API key for one of: Cursor, Anthropic Claude, or OpenAI
- Python 3.8+
- Optional: `openai` or `anthropic` packages

**Setup:**

```bash
# Set API key (choose one)
export OPENAI_API_KEY="your-openai-api-key-here"
# OR
export ANTHROPIC_API_KEY="your-anthropic-api-key-here"
# OR
export CURSOR_API_KEY="your-cursor-api-key-here"

# Install dependencies (optional, only if using OpenAI/Anthropic)
pip install openai anthropic
```

**Usage:**
The `git-commit-review` script automatically tries LLM generation first if API keys are available.

### 2. Enhanced Heuristics (Good Quality, Fast) ⭐

Improved pattern matching and file analysis (no API needed).

**Files:**

- `generate_commit_msg_enhanced.sh` - Better heuristics-based generation

**How it works:**

- Analyzes file paths and names
- Categorizes changes (features, fixes, docs, tests)
- Checks git diff for fix patterns
- Generates contextual messages

### 3. Original Heuristics (Basic)

Simple file counting and categorization.

**Files:**

- `generate_commit_msg.sh` - Basic extraction
- `show_changes.sh` - Full summary with message

## Integration Approaches

### Option A: Direct LLM API Call (Recommended)

**Pros:**

- Best quality messages
- Understands code context
- Can summarize complex changes

**Cons:**

- Requires API key
- Costs money (usually minimal per commit)
- Network request (slower)

**Implementation:**
`generate_commit_msg_with_llm.py` handles this automatically when:

- API keys are set
- Dependencies are installed

### Option B: Cursor Agent Integration

Since you're already using Cursor, you could:

1. **Use Cursor's built-in capabilities:**
    - Ask Cursor in chat: "Generate a commit message for my changes"
    - Cursor can see the git diff and generate a message

2. **Create a Cursor command:**
    - Add a custom command that runs git diff and asks Cursor API

3. **Use Cursor's context:**
    - The agent already has project context
    - Can generate better messages than generic LLM

### Option C: Enhanced Heuristics Only (No API)

**Pros:**

- No API keys needed
- Always works
- Fast and free

**Cons:**

- Less intelligent than LLM
- May miss nuanced changes

**Implementation:**
Just use `generate_commit_msg_enhanced.sh` which improves on the basic pattern matching.

## Recommendation

**Best approach: Hybrid with Cursor integration**

1. **Try Cursor Agent first** (if available in context):

    ```bash
    # In Cursor chat:
    "Generate a commit message for my current git changes"
    ```

2. **Fall back to enhanced heuristics:**
    - Works without API
    - Good enough for most commits
    - Fast and reliable

3. **Optional: Add LLM as enhancement:**
    - Set API keys if you want better messages
    - Falls back gracefully if unavailable

## Quick Setup

```bash
# Make enhanced script executable
chmod +x generate_commit_msg_enhanced.sh generate_commit_msg_with_llm.py

# Optionally set API keys
export OPENAI_API_KEY="your-key"  # For OpenAI
# OR
export ANTHROPIC_API_KEY="your-key"  # For Claude

# The git-commit-review script will automatically try:
# 1. LLM (if API keys available)
# 2. Enhanced heuristics
# 3. Original methods
# 4. Simple fallback
```

## Using Cursor Directly

Since you're already in Cursor, the simplest approach:

1. Stage your changes: `git add .`
2. In Cursor chat, ask: "Generate a conventional commit message for my staged changes"
3. Copy the message and use: `git commit -m "..."`

Or create a Cursor command/shortcut for this workflow.
