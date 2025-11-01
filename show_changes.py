#!/usr/bin/env python3
"""
Show git changes summary for the current project.
Automatically detects which project (SecureApp or QuantFramework) and shows changes.
Works across platforms (Linux, Windows, macOS).
"""

import subprocess
import sys
from pathlib import Path


def run_git_command(cmd: list[str]) -> tuple[str, int]:
    """Run a git command and return output and exit code."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.stdout.strip(), result.returncode
    except FileNotFoundError:
        print("Error: git not found. Please install git.")
        sys.exit(1)


def check_git_repo() -> bool:
    """Check if we're in a git repository."""
    _, exit_code = run_git_command(["git", "rev-parse", "--git-dir"])
    return exit_code == 0


def get_changes_summary() -> dict:
    """Get summary of git changes."""
    summary = {
        "modified": [],
        "untracked": [],
        "modified_count": 0,
        "untracked_count": 0,
    }

    # Get modified files
    modified_output, _ = run_git_command(["git", "diff", "--name-only"])
    if modified_output:
        summary["modified"] = [
            line for line in modified_output.split("\n") if line.strip()
        ]
        summary["modified_count"] = len(summary["modified"])

    # Get untracked files
    untracked_output, _ = run_git_command(
        ["git", "ls-files", "--others", "--exclude-standard"]
    )
    if untracked_output:
        summary["untracked"] = [
            line for line in untracked_output.split("\n") if line.strip()
        ]
        summary["untracked_count"] = len(summary["untracked"])

    return summary


def main():
    """Main function."""
    project_root = Path.cwd()
    project_name = project_root.name

    print("=" * 50)
    print(f"Changes Summary: {project_name}")
    print("=" * 50)
    print()
    print(f"Project Directory: {project_root}")
    print()

    # Check if in git repo
    if not check_git_repo():
        print("Error: Not in a git repository")
        sys.exit(1)

    # Get changes
    summary = get_changes_summary()

    # Check if no changes
    if summary["modified_count"] == 0 and summary["untracked_count"] == 0:
        print("✅ No changes since last commit")
        print()
        return

    # Show modified files
    if summary["modified_count"] > 0:
        print("## Modified Files")
        print()
        stat_output, _ = run_git_command(["git", "diff", "--stat"])
        if stat_output:
            print(stat_output)
        print()

    # Show new files
    if summary["untracked_count"] > 0:
        print("## New Files")
        print()
        for file in summary["untracked"]:
            print(f"  + {file}")
        print()

    # Automatic Summary Analysis
    print("## Automatic Summary")
    print()

    total_count = summary["modified_count"] + summary["untracked_count"]
    print(
        f"**Total Changes:** {total_count} files "
        f"({summary['modified_count']} modified, {summary['untracked_count']} new)"
    )
    print()

    # Categorize files
    all_files = summary["modified"] + summary["untracked"]

    if all_files:
        # Count by file type
        python_files = len([f for f in all_files if f.endswith(".py")])
        config_files = len(
            [
                f
                for f in all_files
                if any(
                    f.endswith(ext)
                    for ext in [".toml", ".yaml", ".yml", ".json", ".ini", ".cfg"]
                )
            ]
        )
        doc_files = len(
            [
                f
                for f in all_files
                if any(f.endswith(ext) for ext in [".md", ".txt", ".rst"])
            ]
        )
        script_files = len(
            [
                f
                for f in all_files
                if any(f.endswith(ext) for ext in [".sh", ".ps1", ".bat"])
            ]
        )
        test_files = len([f for f in all_files if "/test" in f or "test_" in f])
        config_dir_files = len(
            [
                f
                for f in all_files
                if f.startswith(".") or "config/" in f or ".cursor" in f
            ]
        )

        categories = []
        if python_files > 0:
            categories.append(f"  • Python files: {python_files}")
        if test_files > 0:
            categories.append(f"  • Test files: {test_files}")
        if config_files > 0:
            categories.append(f"  • Config files: {config_files}")
        if config_dir_files > 0:
            categories.append(f"  • Configuration/root files: {config_dir_files}")
        if doc_files > 0:
            categories.append(f"  • Documentation: {doc_files}")
        if script_files > 0:
            categories.append(f"  • Scripts: {script_files}")

        if categories:
            print("**By Category:**")
            for cat in categories:
                print(cat)
            print()

        # Analyze change types (lines added/removed) - for commit message
        lines_added = 0
        lines_removed = 0
        net_changes = 0

        if summary["modified_count"] > 0:
            numstat_output, _ = run_git_command(["git", "diff", "--numstat"])

            if numstat_output:
                for line in numstat_output.split("\n"):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                lines_added += int(parts[0])
                                lines_removed += int(parts[1])
                            except ValueError:
                                pass

            net_changes = lines_added - lines_removed

            print("**Code Changes:**")
            print(f"  • Lines added: {lines_added}")
            print(f"  • Lines removed: {lines_removed}")
            if net_changes > 0:
                print(f"  • Net change: +{net_changes} lines")
            elif net_changes < 0:
                print(f"  • Net change: {net_changes} lines")
            else:
                print("  • Net change: 0 lines")
            print()

        # Generate commit message summary
        print("## Suggested Commit Message")
        print()

        # Determine commit type and build message
        change_types = []
        commit_body_parts = []

        if any(".cursorrules" in f for f in all_files):
            change_types.append("config")
            commit_body_parts.append("- Update Cursor AI agent configuration")

        if any("verify_" in f or "guide" in f.lower() for f in all_files):
            change_types.append("docs")
            commit_body_parts.append("- Add verification scripts and documentation")

        if any("/test" in f or "test_" in f for f in all_files):
            change_types.append("test")
            commit_body_parts.append("- Update test suite")

        if any(
            f.endswith(".py") and ("app/" in f or "src/" in f or "trading/" in f)
            for f in all_files
        ):
            change_types.append("feat")
            commit_body_parts.append("- Update application code")

        if any(
            "requirements" in f or "pyproject" in f or "setup.py" in f
            for f in all_files
        ):
            change_types.append("build")
            commit_body_parts.append("- Update dependencies/package configuration")

        if any(
            f.endswith((".sh", ".ps1", ".py")) and "test" not in f for f in all_files
        ):
            change_types.append("chore")
            commit_body_parts.append("- Add utility scripts")

        # Determine primary type (prioritize feat > fix > docs > test > build > chore)
        commit_type = "chore"
        type_priority = {
            "feat": 1,
            "fix": 2,
            "docs": 3,
            "test": 4,
            "build": 5,
            "chore": 6,
        }
        for ct in change_types:
            if ct in type_priority and type_priority[ct] < type_priority.get(
                commit_type, 99
            ):
                commit_type = ct

        # Build subject line
        if total_count == 1:
            if summary["untracked_count"] == 1:
                file_name = Path(all_files[0]).name
                commit_subject = f"add {file_name}"
            else:
                file_name = Path(all_files[0]).name
                commit_subject = f"update {file_name}"
        elif python_files > 0 and python_files == total_count:
            commit_subject = "update Python code"
        elif script_files > 0:
            commit_subject = "add utility scripts"
        elif doc_files > 0 and doc_files == total_count:
            commit_subject = "update documentation"
        elif config_files > 0:
            commit_subject = "update configuration"
        else:
            commit_subject = "update project files"

        # Output commit message format
        print("```")
        print(f"{commit_type}: {commit_subject}")
        print()

        if commit_body_parts:
            for part in commit_body_parts:
                print(part)

        print()
        print(
            f"Files changed: {total_count} "
            f"({summary['modified_count']} modified, {summary['untracked_count']} new)"
        )

        if summary["modified_count"] > 0:
            print(f"Lines: +{lines_added}/-{lines_removed} (net: {net_changes})")
        print("```")
        print()

    # Option to show detailed diff
    if summary["modified_count"] > 0:
        try:
            show_diff = input("Show detailed diff? (y/n) ").strip().lower()
            if show_diff == "y":
                print()
                diff_output, _ = run_git_command(["git", "diff"])
                if diff_output:
                    print(diff_output)
        except KeyboardInterrupt:
            print("\n")
            pass

    print()
    print("=" * 50)


if __name__ == "__main__":
    main()
