#!/usr/bin/env python3
"""
Smart commit message generator that analyzes git diff content.
Uses git diff to understand actual changes, not just filenames.
"""

import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional


def get_git_changes() -> Optional[Dict]:
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

        # Get actual diff content for analysis
        diff_output = subprocess.run(
            ["git", "diff", "--cached"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout

        # Get diff stats
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


def analyze_diff_content(diff: str, files: List[str]) -> Dict:
    """Analyze git diff to understand what actually changed."""
    diff_lower = diff.lower()

    # Look for meaningful patterns in the diff
    features_added = []
    bugs_fixed = []
    improvements = []

    # Check for new functions/classes
    if "+def " in diff or "+class " in diff:
        features_added.append("new functionality")

    # Check for bug fixes - look in comments, function names, and commit-style messages
    fix_patterns = [
        "+fix",
        "+bug",
        "+error",
        "+issue",
        "+correct",
        "+resolve",
        "-# bug",
        "-# fix",
        "# fix",
        "# bug",
        "bug fix",
        "fix bug",
        "fix issue",
        "correct",
        "resolve",
        "return FileListResult",
        "fix return type",
        "maintain consistency",
    ]
    if any(pattern in diff_lower for pattern in fix_patterns):
        bugs_fixed.append("bug fixes")

    # Look for exception handling improvements
    if "+except" in diff or "Exception" in diff or "finally:" in diff:
        improvements.append("error handling")

    # Look for session cleanup improvements
    if "close_session" in diff_lower and "if session is not None" in diff_lower:
        bugs_fixed.append("session cleanup")

    # Check for test additions
    if any("test" in f.lower() for f in files) or "+def test_" in diff:
        improvements.append("test coverage")

    # Check for documentation
    if (
        any(f.endswith(".md") for f in files)
        or "docstring" in diff_lower
        or "documentation" in diff_lower
    ):
        improvements.append("documentation")

    # Check for refactoring
    if (
        "+refactor" in diff_lower
        or "+improve" in diff_lower
        or "+optimize" in diff_lower
        or "+clean" in diff_lower
    ):
        improvements.append("code improvements")

    # Count significant changes
    lines_added = diff.count("\n+") - diff.count("\n+++")
    lines_removed = diff.count("\n-") - diff.count("\n---")

    return {
        "features": features_added,
        "fixes": bugs_fixed,
        "improvements": improvements,
        "lines_added": lines_added,
        "lines_removed": lines_removed,
        "net_change": lines_added - lines_removed,
    }


def categorize_files(files: List[str]) -> Dict[str, List[str]]:
    """Categorize files by type."""
    categories = {
        "features": [],
        "tests": [],
        "docs": [],
        "scripts": [],
        "config": [],
        "other": [],
    }

    for file in files:
        file_lower = file.lower()
        if file.startswith("app/") or file.startswith("src/"):
            categories["features"].append(file)
        elif "test" in file_lower or file.startswith("tests/"):
            categories["tests"].append(file)
        elif file.endswith(".md") or any(
            x in file_lower for x in ["readme", "guide", "doc"]
        ):
            categories["docs"].append(file)
        elif file.endswith((".sh", ".ps1")) and "test" not in file_lower:
            categories["scripts"].append(file)
        elif any(
            file.endswith(ext) for ext in [".toml", ".yaml", ".yml", ".ini", ".json"]
        ):
            categories["config"].append(file)
        else:
            categories["other"].append(file)

    return categories


def generate_commit_message(changes: Dict, analysis: Dict, categories: Dict) -> str:
    """Generate a meaningful commit message based on analysis."""
    files = changes["staged_files"] + changes["untracked"]
    total_files = len(files)

    # Determine commit type and subject
    commit_type = "chore"
    subject = "update files"
    body_lines = []

    # Prioritize based on what was actually changed
    if analysis["fixes"]:
        commit_type = "fix"
        if total_files == 1:
            file_base = Path(files[0]).stem
            subject = f"fix issue in {file_base}"
        else:
            subject = "fix bugs and issues"
        body_lines.append("- Fix bugs and resolve issues")

    elif analysis["features"]:
        commit_type = "feat"
        if total_files == 1:
            file_base = Path(files[0]).stem
            subject = f"add {file_base} feature"
        elif len(categories["features"]) == 1:
            file_base = Path(categories["features"][0]).stem
            subject = f"add {file_base} functionality"
        else:
            subject = f"add features ({len(categories['features'])} files)"
        body_lines.append("- Add new functionality")

    elif categories["tests"]:
        commit_type = "test"
        subject = f"add tests ({len(categories['tests'])} files)"
        body_lines.append(f"- Add test coverage: {', '.join(categories['tests'][:3])}")

    elif categories["docs"]:
        commit_type = "docs"
        if len(categories["docs"]) == 1:
            doc_name = Path(categories["docs"][0]).stem
            subject = f"add {doc_name} documentation"
        else:
            subject = f"update documentation ({len(categories['docs'])} files)"
        body_lines.append(f"- Documentation: {', '.join(categories['docs'][:3])}")

    elif categories["scripts"]:
        commit_type = "chore"
        if len(categories["scripts"]) == 1:
            script_name = Path(categories["scripts"][0]).stem
            subject = f"add {script_name} script"
        else:
            subject = f"add utility scripts ({len(categories['scripts'])} files)"
        body_lines.append(f"- Scripts: {', '.join(categories['scripts'][:3])}")

    elif analysis["improvements"]:
        commit_type = (
            "refactor" if "code improvements" in analysis["improvements"] else "chore"
        )
        subject = "improve code quality"
        for imp in analysis["improvements"]:
            body_lines.append(f"- {imp.capitalize()}")

    elif categories["config"]:
        commit_type = "config"
        subject = "update configuration"
        body_lines.append(f"- Config: {', '.join(categories['config'][:3])}")

    # Add specific details for small changes
    if total_files <= 5:
        body_lines.append("")
        for file in files[:5]:
            if file in changes["staged_files"]:
                body_lines.append(f"- Modify: {file}")
            else:
                body_lines.append(f"- Add: {file}")

    # Add stats if significant
    if analysis["lines_added"] > 50 or analysis["lines_removed"] > 50:
        body_lines.append("")
        net_change = analysis["net_change"]
        lines_msg = (
            f"Lines: +{analysis['lines_added']}/"
            f"-{analysis['lines_removed']} (net: {net_change:+d})"
        )
        body_lines.append(lines_msg)

    # Build message
    message = f"{commit_type}: {subject}\n"
    if body_lines:
        message += "\n" + "\n".join(body_lines)

    return message


def main():
    """Main function."""
    changes = get_git_changes()
    if not changes or (not changes["staged_files"] and not changes["untracked"]):
        print("No changes detected", file=sys.stderr)
        return 1

    # Analyze the changes
    files = changes["staged_files"] + changes["untracked"]
    analysis = analyze_diff_content(changes["diff"], files)
    categories = categorize_files(files)

    # Generate message
    message = generate_commit_message(changes, analysis, categories)
    print(message)
    return 0


if __name__ == "__main__":
    sys.exit(main())
