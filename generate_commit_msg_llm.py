#!/usr/bin/env python3
"""
Generate commit message using LLM analysis of git changes.
Uses simple diff analysis and prompts for better commit messages.
"""

import subprocess
import sys
from pathlib import Path


def get_git_changes():
    """Get git diff and status information."""
    try:
        # Get staged changes
        staged = subprocess.run(
            ["git", "diff", "--cached", "--stat"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout

        # Get staged file names
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

        # Get diff summary
        diff_summary = subprocess.run(
            ["git", "diff", "--cached", "--shortstat"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

        return {
            "staged": staged,
            "staged_files": [f for f in staged_files if f],
            "untracked": [f for f in untracked if f],
            "diff_summary": diff_summary,
        }
    except subprocess.CalledProcessError:
        return None


def analyze_changes_simple(changes):
    """Simple analysis without LLM - categorizes changes."""
    if not changes:
        return None

    files = changes["staged_files"] + changes["untracked"]
    if not files:
        return None

    # Categorize files
    features = []
    fixes = []
    docs = []
    tests = []
    config = []

    for file in files:
        file_lower = file.lower()
        if any(x in file_lower for x in ["test", "spec"]):
            tests.append(file)
        elif any(
            x in file_lower
            for x in [
                "readme",
                "guide",
                "doc",
                "changelog",
                "contributing",
                "architecture",
            ]
        ):
            docs.append(file)
        elif any(
            x in file_lower
            for x in [
                ".toml",
                ".yaml",
                ".yml",
                ".ini",
                ".json",
                "config",
                ".git",
                "workflow",
            ]
        ):
            config.append(file)
        elif "fix" in file_lower or "bug" in file_lower or "error" in file_lower:
            fixes.append(file)
        else:
            features.append(file)

    # Determine commit type
    commit_type = "chore"
    subject = "update files"

    if features:
        commit_type = "feat"
        if len(features) == 1:
            subject = f"add {Path(features[0]).name}"
        else:
            subject = f"add {len(features)} new features/files"
    elif fixes:
        commit_type = "fix"
        subject = "fix issues"
    elif tests:
        commit_type = "test"
        subject = f"add {len(tests)} test files"
    elif docs:
        commit_type = "docs"
        subject = f"update documentation ({len(docs)} files)"
    elif config:
        commit_type = "config"
        subject = "update configuration"

    # Build body
    body_parts = []
    if features:
        body_parts.append(f"- Add/modify: {', '.join(features[:5])}")
        if len(features) > 5:
            body_parts.append(f"- And {len(features) - 5} more files")
    if fixes:
        body_parts.append(f"- Fix: {', '.join(fixes[:3])}")
    if docs:
        body_parts.append(f"- Documentation: {', '.join(docs[:3])}")
    if tests:
        body_parts.append(f"- Tests: {', '.join(tests[:3])}")
    if config:
        body_parts.append(f"- Config: {', '.join(config[:3])}")

    message = f"{commit_type}: {subject}\n"
    if body_parts:
        message += "\n" + "\n".join(body_parts)

    if changes["diff_summary"]:
        message += f"\n\n{changes['diff_summary']}"

    return message


def generate_with_llm(changes):
    """Generate commit message using LLM (placeholder for future implementation)."""
    # This would use an LLM API or agent
    # For now, return None to fall back to simple analysis
    return None


def main():
    """Main function."""
    changes = get_git_changes()
    if not changes:
        print("No changes detected", file=sys.stderr)
        return 1

    # Try LLM first (if available)
    message = generate_with_llm(changes)

    # Fall back to simple analysis
    if not message:
        message = analyze_changes_simple(changes)

    if message:
        print(message)
        return 0
    else:
        print("Could not generate commit message", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
