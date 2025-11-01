# Commit Message LLM Integration Guide

## Overview

The commit message generation system supports multiple methods, from simple heuristics to LLM-powered analysis.

## Methods (in priority order)

### 1. LLM-Enhanced Generation (Best Quality) ⭐

Uses AI to analyze git diffs and generate contextual commit messages.

**Requirements:**

- API key for OpenAI or Anthropic Claude (if using external LLM APIs)
- **Note:** Cursor Agent in the IDE works without an API key - you're already authenticated when logged into Cursor
- Python 3.8+
- Optional: `openai` or `anthropic` packages

**Setup:**

1. **Create `.env` file (recommended - gitignored):**

    ```bash
    # Copy the example template
    cp .env.example .env

    # Edit .env and add your keys
    nano .env
    ```

    Add your keys to `.env`:

    ```bash
    OPENAI_API_KEY=your-openai-api-key-here
    ANTHROPIC_API_KEY=your-anthropic-api-key-here
    # CURSOR_API_KEY is optional - only if using Cursor's API programmatically
    # Not needed for Cursor Agent in IDE (already logged in)
    CURSOR_API_KEY=your-cursor-api-key-here
    ```

    **The `.env` file is automatically loaded by `python-dotenv` (already in requirements.txt).**

2. **Or set environment variables manually:**

    ```bash
    export OPENAI_API_KEY="your-openai-api-key-here"
    # OR
    export ANTHROPIC_API_KEY="your-anthropic-api-key-here"
    # OR
    export CURSOR_API_KEY="your-cursor-api-key-here"
    ```

3. **Install dependencies (optional, only if using OpenAI/Anthropic):**

    ```bash
    pip install openai anthropic
    ```

**Security Note:** Never commit API keys to git. See `SECURE_API_KEYS_GUIDE.md` for detailed instructions.

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

### Option B: Cursor Agent Integration (No API Key Needed) ⭐

Since you're already using Cursor, this is the easiest option:

1. **Use Cursor's built-in chat (recommended):**
    - You're already logged in - no API key needed
    - Ask Cursor in chat: "Generate a commit message for my staged changes"
    - Cursor Agent can see the git diff and generate a message
    - Works immediately, no setup required

2. **Use Cursor's context:**
    - The agent already has full project context
    - Can generate better messages than generic LLM
    - Understands your codebase and conventions

3. **Programmatic API (future - if Cursor exposes one):**
    - Would require `CURSOR_API_KEY` if Cursor adds API access
    - Currently not available - use chat interface instead

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
# 1. Make enhanced script executable
chmod +x generate_commit_msg_enhanced.sh generate_commit_msg_with_llm.py

# 2. Set up API keys (optional, for LLM generation)
# Method A: Use .env file (recommended)
cp .env.example .env
# Edit .env and add your keys

# Method B: Export manually
export OPENAI_API_KEY="your-key"  # For OpenAI
# OR
export ANTHROPIC_API_KEY="your-key"  # For Claude

# The git-commit-review script will automatically try:
# 1. Smart diff analyzer (no API needed)
# 2. LLM (if API keys available)
# 3. Enhanced heuristics
# 4. Original methods
# 5. Simple fallback
```

**For detailed API key setup, see `SECURE_API_KEYS_GUIDE.md`.**

## Using Cursor Agent Directly (Recommended - No API Key Needed)

Since you're already logged into Cursor, this is the simplest approach:

1. **Stage your changes:**

    ```bash
    git add .
    ```

2. **Ask Cursor Agent in chat:**
    - Open Cursor chat (Cmd/Ctrl + L)
    - Ask: "Generate a conventional commit message for my staged git changes"
    - Cursor will analyze your changes and provide a message

3. **Copy and commit:**
    ```bash
    git commit -m "message from cursor"
    ```

**Why this works better:**

- No API key needed (you're already authenticated)
- Cursor Agent has full project context
- Understands your codebase conventions
- Generates contextual, high-quality messages

**Pro tip:** You can also just ask me (Cursor Agent) directly: "Generate a commit message for my changes" and I'll do it right now!
