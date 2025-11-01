#!/usr/bin/env python3
"""
Generate commit message prompt optimized for Cursor Agent.
Formats git diff for easy copy-paste into Cursor chat.
"""

import subprocess
import sys
from typing import Optional


def get_git_changes() -> Optional[dict]:
    """Get git diff and status information."""
    try:
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

        diff_output = subprocess.run(
            ["git", "diff", "--cached"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout

        diff_stats = subprocess.run(
            ["git", "diff", "--cached", "--stat"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout

        return {
            "staged_files": [f for f in staged_files if f],
            "untracked": [f for f in untracked if f],
            "diff": diff_output,
            "diff_stats": diff_stats,
        }
    except subprocess.CalledProcessError:
        return None


def format_for_cursor_agent(changes: dict) -> str:
    """Format git changes for Cursor Agent to generate commit message."""
    files = changes["staged_files"] + changes["untracked"]
    files_str = "\n".join(f"  - {f}" for f in files[:20])

    # Limit diff size for readability (keep first 4000 chars, show summary)
    diff_preview = changes["diff"][:4000]
    if len(changes["diff"]) > 4000:
        diff_preview += f"\n\n... (diff truncated, {len(changes['diff'])} total chars)"

    prompt = f"""Generate a conventional commit message for these git changes:

Files changed ({len(files)}):
{files_str}

Git diff:
{diff_preview}

Generate a commit message following Conventional Commits format with:
- Type (feat, fix, docs, test, chore, refactor, etc.)
- Clear, descriptive subject line
- Detailed body explaining what changed and why
- Reference specific files or components if relevant

Commit message:"""

    return prompt


def main():
    """Main function."""
    changes = get_git_changes()
    if not changes or (not changes["staged_files"] and not changes["untracked"]):
        print("No changes detected", file=sys.stderr)
        return 1

    prompt = format_for_cursor_agent(changes)

    # Output the prompt - user can copy-paste into Cursor chat
    print("=" * 70)
    print("Copy the prompt below and paste into Cursor chat (Cmd/Ctrl + L):")
    print("=" * 70)
    print()
    print(prompt)
    print()
    print("=" * 70)
    print('After Cursor generates the message, copy it and use: git commit -m "..."')

    return 0


if __name__ == "__main__":
    sys.exit(main())
