#!/usr/bin/env python3
"""
Generate commit message using LLM analysis of git changes.
Can use Cursor API, OpenAI, Anthropic, or fall back to heuristics.
"""

import os
import subprocess
import sys

# Try to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    # python-dotenv not installed, skip .env loading
    pass


def get_git_changes():
    """Get git diff and status information."""
    try:
        # Get staged changes
        staged_files = (
            subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                capture_output=True,
                text=True,
                check=True,
            )
            .stdout.strip()
            .split("\n")
        )

        # Get untracked files
        untracked = (
            subprocess.run(
                ["git", "ls-files", "--others", "--exclude-standard"],
                capture_output=True,
                text=True,
                check=True,
            )
            .stdout.strip()
            .split("\n")
        )

        # Get actual diff for analysis
        diff_output = subprocess.run(
            ["git", "diff", "--cached"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout

        # Get shortstat
        diff_summary = subprocess.run(
            ["git", "diff", "--cached", "--shortstat"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        return {
            "staged_files": [f for f in staged_files if f],
            "untracked": [f for f in untracked if f],
            "diff": diff_output,
            "diff_summary": diff_summary,
        }
    except subprocess.CalledProcessError:
        return None


def analyze_with_simple_heuristics(changes):
    """Enhanced heuristics-based analysis (no LLM needed)."""
    if not changes:
        return None

    files = changes["staged_files"] + changes["untracked"]
    if not files:
        return None

    # Import the enhanced bash script logic here
    # For now, return structured analysis
    features = []
    fixes = []
    docs = []
    tests = []
    scripts = []

    for file in files:
        file_lower = file.lower()
        if file.startswith("app/") or file.startswith("src/"):
            features.append(file)
        elif any(x in file_lower for x in ["fix", "bug", "error", "patch"]):
            fixes.append(file)
        elif any(x in file_lower for x in ["readme", "guide", "doc", ".md"]):
            docs.append(file)
        elif "test" in file_lower or file.startswith("tests/"):
            tests.append(file)
        elif file.endswith((".sh", ".ps1")) and "test" not in file_lower:
            scripts.append(file)

    # Build message
    if features:
        return f"feat: add features\n\n- Update: {', '.join(features[:3])}"
    elif fixes:
        return f"fix: resolve issues\n\n- Fix: {', '.join(fixes[:3])}"
    elif tests:
        return f"test: add tests\n\n- Add: {', '.join(tests[:3])}"
    elif docs:
        return f"docs: update documentation\n\n- Update: {', '.join(docs[:3])}"
    elif scripts:
        return f"chore: add scripts\n\n- Add: {', '.join(scripts[:3])}"
    else:
        return f"chore: update files\n\n- Modified: {', '.join(files[:5])}"


def generate_with_cursor_api(changes):
    """Generate using Cursor API if available."""
    # Check for Cursor API key or local Cursor instance
    cursor_api_key = os.getenv("CURSOR_API_KEY")
    if not cursor_api_key:
        return None

    # Try to use Cursor's local API if available
    # Note: This requires Cursor to expose an API endpoint
    # For now, fall back to other methods
    return None


def generate_with_cursor_chat(changes):
    """
    Generate commit message by creating a prompt that could be used
    with Cursor's chat interface. This is a helper for manual use.
    """
    files_str = "\n".join(changes["staged_files"][:10])
    diff_preview = changes["diff"][:3000]  # First 3000 chars

    prompt = f"""Generate a conventional commit message for these git changes:

Files changed:
{files_str}

Git diff:
{diff_preview}

Provide a commit message following Conventional Commits format with:
- Type (feat, fix, docs, test, chore, refactor, etc.)
- Clear, descriptive subject line
- Detailed body explaining what changed and why

Commit message:"""

    # For now, just return the prompt - user can paste into Cursor chat
    # In future, could integrate with Cursor API if available
    return prompt


def generate_with_openai(changes):
    """Generate using OpenAI API if available."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None

    try:
        import openai  # type: ignore

        # Build prompt from changes
        files_str = "\n".join(changes["staged_files"][:20])
        diff_preview = changes["diff"][:2000]  # Limit diff size

        prompt = (
            f"Analyze these git changes and generate a conventional commit message:\n\n"
            f"Files changed:\n{files_str}\n\n"
            f"Diff preview:\n{diff_preview}\n\n"
            f"Generate a commit message following Conventional Commits format:\n"
            f"- Type (feat, fix, docs, test, chore, etc.)\n"
            f"- Clear subject line\n"
            f"- Detailed body with bullet points\n"
            f"- Focus on what changed and why\n\n"
            f"Commit message:"
        )

        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
            temperature=0.3,
        )

        return response.choices[0].message.content.strip()
    except ImportError:
        return None
    except Exception:
        return None


def generate_with_anthropic(changes):
    """Generate using Anthropic Claude API if available."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return None

    try:
        import anthropic  # type: ignore

        files_str = "\n".join(changes["staged_files"][:20])
        diff_preview = changes["diff"][:2000]

        prompt = (
            f"Analyze these git changes and generate a conventional commit message:\n\n"
            f"Files changed:\n{files_str}\n\n"
            f"Diff preview:\n{diff_preview}\n\n"
            f"Generate a commit message following Conventional Commits format."
        )

        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=200,
            temperature=0.3,
            messages=[{"role": "user", "content": prompt}],
        )

        return message.content[0].text.strip()
    except ImportError:
        return None
    except Exception:
        return None


def main():
    """Main function."""
    changes = get_git_changes()
    if not changes:
        print("No changes detected", file=sys.stderr)
        return 1

    message = None

    # Try LLM APIs in order of preference
    # 1. Cursor API (if available)
    message = generate_with_cursor_api(changes)

    # 2. Anthropic Claude (if available)
    if not message:
        message = generate_with_anthropic(changes)

    # 3. OpenAI (if available)
    if not message:
        message = generate_with_openai(changes)

    # 4. Fall back to enhanced heuristics
    if not message:
        message = analyze_with_simple_heuristics(changes)

    if message:
        print(message)
        return 0
    else:
        print("Could not generate commit message", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
