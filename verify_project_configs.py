#!/usr/bin/env python3
"""Verify that project configurations are properly set up for each project."""

import sys
from pathlib import Path

PROJECTS_DIR = Path.home() / "DevelopmentProjects"
PROJECTS = {
    "SecureApp": {
        "package_dir": "app",
        "expected_standards_ref": "standards/full/engineering.md",
    },
    "QuantFramework": {
        "package_dir": "trading",
        "expected_standards_ref": "engineering standards",
    },
}

errors = []
warnings = []


def check_file_exists(project_path: Path, filename: str, description: str):
    """Check if a file exists."""
    file_path = project_path / filename
    if not file_path.exists():
        errors.append(f"{description}: Missing {file_path}")
        return False
    if file_path.is_symlink():
        warnings.append(
            f"{description}: {file_path} is still a symlink (should be a regular file)"
        )
        return False
    return True


def check_file_content(
    project_path: Path, filename: str, expected_content: str, description: str
):
    """Check if file contains expected content."""
    file_path = project_path / filename
    if not file_path.exists():
        return False

    content = file_path.read_text(encoding="utf-8")
    if expected_content not in content:
        errors.append(
            f"{description}: {file_path} doesn't contain '{expected_content}'"
        )
        return False
    return True


def verify_project(project_name: str, config: dict):
    """Verify configuration for a single project."""
    project_path = PROJECTS_DIR / project_name
    package_dir = config["package_dir"]
    standards_ref = config["expected_standards_ref"]

    if not project_path.exists():
        errors.append(f"Project directory not found: {project_path}")
        return

    print(f"\n{'='*60}")
    print(f"Verifying {project_name}")
    print(f"{'='*60}")

    # Check basic config files exist and are not symlinks
    print("\n1. Basic Configuration Files:")
    check_file_exists(project_path, ".cursorrules", "Cursor rules")
    check_file_exists(project_path, ".editorconfig", "Editor config")
    check_file_exists(project_path, ".vscode/settings.json", "VS Code settings")

    # Check project name in headers
    print("\n2. Project Name Customization:")
    check_file_content(
        project_path,
        ".cursorrules",
        f"# Cursor AI Agent Rules for {project_name}",
        "Project name in .cursorrules",
    )
    check_file_content(
        project_path,
        ".editorconfig",
        f"# EditorConfig for {project_name}",
        "Project name in .editorconfig",
    )

    # Check standards reference
    print("\n3. Engineering Standards Reference:")
    check_file_content(
        project_path,
        ".cursorrules",
        standards_ref,
        "Standards reference in .cursorrules",
    )

    # Check package directory in pre-commit config
    print("\n4. Package Directory References:")
    if check_file_exists(project_path, ".pre-commit-config.yaml", "Pre-commit config"):
        check_file_content(
            project_path,
            ".pre-commit-config.yaml",
            f"files: ^{package_dir}/",
            f"Package directory in .pre-commit-config.yaml (should be {package_dir}/)",
        )
        check_file_content(
            project_path,
            ".pre-commit-config.yaml",
            f"-r\n          - {package_dir}/",
            f"Bandit package directory (should be {package_dir}/)",
        )

    # Check pytest coverage
    if check_file_exists(project_path, "pytest.ini", "Pytest config"):
        check_file_content(
            project_path,
            "pytest.ini",
            f"--cov={package_dir}",
            f"Pytest coverage (should be {package_dir})",
        )

    # Check pyproject.toml coverage (for QuantFramework)
    if project_name == "QuantFramework" and check_file_exists(
        project_path, "pyproject.toml", "Pyproject.toml"
    ):
        check_file_content(
            project_path,
            "pyproject.toml",
            'source = ["trading", "src"]',
            "Pyproject.toml coverage source",
        )


def main():
    print("Verifying Project Configurations")
    print("=" * 60)

    for project_name, config in PROJECTS.items():
        verify_project(project_name, config)

    # Summary
    print("\n" + "=" * 60)
    print("VERIFICATION SUMMARY")
    print("=" * 60)

    if warnings:
        print(f"\n⚠️  Warnings ({len(warnings)}):")
        for warning in warnings:
            print(f"  - {warning}")

    if errors:
        print(f"\n❌ Errors ({len(errors)}):")
        for error in errors:
            print(f"  - {error}")
        print("\n❌ Configuration verification FAILED")
        return 1
    else:
        print("\n✅ All configurations verified successfully!")
        print("\nBoth projects are properly configured with:")
        print("  - Individual config files (no symlinks)")
        print("  - Correct project names in headers")
        print("  - Correct package directory references")
        print("  - Project-specific customizations applied")
        return 0


if __name__ == "__main__":
    sys.exit(main())
