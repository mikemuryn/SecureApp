#!/usr/bin/env python3
"""Remove master config setup and restore individual config files for each project."""

import shutil
from pathlib import Path

PROJECTS_DIR = Path.home() / "DevelopmentProjects"
MASTER_CONFIG_DIR = PROJECTS_DIR / ".cursor-master-config"
PROJECTS = ["SecureApp", "QuantFramework"]

# Project-specific configurations
PROJECT_CONFIGS = {
    "SecureApp": {
        "package_dir": "app",
        "standards_ref": "`standards/full/engineering.md`",
        "project_specific": "",
    },
    "QuantFramework": {
        "package_dir": "trading",
        "standards_ref": "engineering standards",
        "project_specific": ", if present",
    },
}

# SecureApp config content
CURSORRULES_CONTENT = """# Cursor AI Agent Rules for {project_name}

## Default Agent Configuration
- **Primary Agent**: Cursor Agent (auto)
- **Verification Agent**: Codex (runs after Cursor Agent completes)

## Workflow
1. **Cursor Agent** performs the primary task
2. **Codex** verifies and provides input/review after Cursor Agent finishes
3. User reviews and accepts changes

## Engineering Standards

**All coding standards, guidelines, and technical requirements are defined in:**
- `standards/full/engineering.md` (standards submodule)

This includes:
- Code style (PEP 8, black, type hints, formatting)
- Security practices
- Testing requirements
- Documentation standards
- Performance guidelines
- And all other engineering standards

**Always reference and enforce {standards_ref} for all code-related decisions.**

## Communication Style

When communicating with the user, writing code comments,
documentation, or any text output:

### Language & Clarity
- Use clear, straightforward language
- Write short, impactful sentences with varied sentence structure
- Organize ideas with bullet points for greater readability
- Add frequent line breaks to separate concepts
- Use active voice; avoid passive constructions
- Focus on practical and actionable insights

### Content Quality
- Support points with specific examples, citations, personal anecdotes, or data
- Pose thought-provoking questions to engage the reader when appropriate
- Address the reader directly using "you" and "your"
- Steer clear of cliches and metaphors
- Avoid making broad generalizations
- Skip introductory phrases like "in conclusion" or "in summary"
- Stick to the requested output
- Prioritize readability and fluidity with natural human tone

### Formatting & Style
- Do not include warnings, notes, or unnecessary extras unless explicitly requested
- Avoid hashtags, semicolons, emojis, and asterisks unless explicitly asked
- Read the tone of the request and match it appropriately
- Refrain from using adjectives or adverbs excessively

### Forbidden Words & Phrases
Do not use these words or phrases:
- accordingly, additionally, arguably, certainly, consequently, hence,
  however, indeed, moreover, nevertheless, notwithstanding, thus,
  undoubtedly
- adept, commendable, efficient, ever-evolving, exciting, exemplary,
  innovative, invaluable, robust, seamless, synergistic,
  thought-provoking, transformative, utmost, vibrant, vital
- efficiency, innovation, institution, integration, implementation,
  landscape, optimization, realm, tapestry, transformation
- aligns, augmented, delve, embark, facilitate, maximize, underscores,
  utilize, a testament to
"""

EDITORCONFIG_CONTENT = """# EditorConfig for {project_name}

root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 4

[*.{{py,pyi}}]
indent_size = 4
max_line_length = 88

[*.{{yml,yaml}}]
indent_size = 2

[*.{{json,js,ts}}]
indent_size = 2

[*.md]
trim_trailing_whitespace = false

[Makefile]
indent_style = tab

[*.{{sh,bash}}]
end_of_line = lf
"""


def get_settings_json(package_dir: str) -> str:
    """Generate settings.json with project-specific package directory."""
    return """{{
  // Cursor AI Agent Configuration
  "cursor.aiAgent": "auto",
  "cursor.chat.defaultAgent": "cursor",
  "cursor.chat.enableCodexVerification": true,
  "cursor.chat.agentWorkflow": [
    {{
      "agent": "cursor",
      "step": "primary"
    }},
    {{
      "agent": "codex",
      "step": "verification",
      "trigger": "after_cursor_complete",
      "action": "review_and_verify"
    }}
  ],
  // General editor settings
  "editor.formatOnSave": true,
  "editor.defaultFormatter": "ms-python.black-formatter",
  "[python]": {{
    "editor.defaultFormatter": "ms-python.black-formatter",
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {{
      "source.organizeImports": "explicit"
    }}
  }},
  // Python settings
  "python.defaultInterpreterPath": "${{workspaceFolder}}/.venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.flake8Enabled": true,
  "python.linting.mypyEnabled": true,
  "python.formatting.provider": "black",
  "python.formatting.blackArgs": [
    "--line-length=88"
  ],
  "isort.args": [
    "--profile=black"
  ]
}}
"""


def restore_config_file(project_path: Path, filename: str, content: str):
    """Restore a config file, removing symlink if present."""
    file_path = project_path / filename

    # Remove symlink if it exists
    if file_path.is_symlink():
        print(f"  Removing symlink: {filename}")
        file_path.unlink()

    # Create directory if needed
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # Write the file
    file_path.write_text(content, encoding="utf-8")
    print(f"  ✓ Created: {filename}")


def update_project_specific_configs(
    project_path: Path, project_name: str, package_dir: str
):
    """Update project-specific config files with correct package directory."""
    # Update .pre-commit-config.yaml
    precommit_path = project_path / ".pre-commit-config.yaml"
    if precommit_path.exists():
        content = precommit_path.read_text(encoding="utf-8")
        # Replace app/ with the correct package directory
        if "files: ^app/" in content or "files: ^app/" in content:
            content = content.replace("files: ^app/", f"files: ^{package_dir}/")
            content = content.replace("files: ^app/", f"files: ^{package_dir}/")
        if "-r\n          - app/" in content:
            content = content.replace(
                "-r\n          - app/", f"-r\n          - {package_dir}/"
            )
        precommit_path.write_text(content, encoding="utf-8")
        print(f"  ✓ Updated: .pre-commit-config.yaml (package_dir: {package_dir}/)")

    # Update pytest.ini
    pytest_path = project_path / "pytest.ini"
    if pytest_path.exists():
        content = pytest_path.read_text(encoding="utf-8")
        # Replace --cov=app with correct package
        if f"--cov={package_dir}" not in content:
            content = content.replace("--cov=app", f"--cov={package_dir}")
        pytest_path.write_text(content, encoding="utf-8")
        print(f"  ✓ Updated: pytest.ini (coverage: {package_dir})")

    # Update pyproject.toml coverage section if exists
    pyproject_path = project_path / "pyproject.toml"
    if pyproject_path.exists():
        content = pyproject_path.read_text(encoding="utf-8")
        # Update coverage source if it references app/
        if "[tool.coverage.run]" in content and 'source = ["app"]' in content:
            # Check if it should be trading or trading, src
            if package_dir == "trading":
                # QuantFramework might use both trading and src
                if 'source = ["trading", "src"]' not in content:
                    content = content.replace(
                        'source = ["app"]', 'source = ["trading", "src"]'
                    )
                    pyproject_path.write_text(content, encoding="utf-8")
                    print("  ✓ Updated: pyproject.toml (coverage source)")
            else:
                content = content.replace(
                    'source = ["app"]', f'source = ["{package_dir}"]'
                )
                pyproject_path.write_text(content, encoding="utf-8")
                print("  ✓ Updated: pyproject.toml (coverage source)")


def main():
    print("Removing master config setup and restoring individual config files...")
    print()

    # Process each project
    for project_name in PROJECTS:
        project_path = PROJECTS_DIR / project_name

        if not project_path.exists():
            print(f"Error: Project {project_name} not found at {project_path}")
            continue

        print(f"Processing {project_name}...")

        # Get project-specific configuration
        config = PROJECT_CONFIGS.get(project_name, PROJECT_CONFIGS["SecureApp"])
        package_dir = config["package_dir"]
        standards_ref = config["standards_ref"]
        project_specific = config["project_specific"]

        # Restore .cursorrules
        cursorrules_content = CURSORRULES_CONTENT.format(
            project_name=project_name,
            project_specific=project_specific,
            standards_ref=standards_ref,
        )
        restore_config_file(project_path, ".cursorrules", cursorrules_content)

        # Restore .editorconfig
        editorconfig_content = EDITORCONFIG_CONTENT.format(project_name=project_name)
        restore_config_file(project_path, ".editorconfig", editorconfig_content)

        # Restore .vscode/settings.json
        settings_json_content = get_settings_json(package_dir)
        restore_config_file(
            project_path, ".vscode/settings.json", settings_json_content
        )

        # Update project-specific files that need package directory customization
        update_project_specific_configs(project_path, project_name, package_dir)

        print()

    # Remove master config directory
    if MASTER_CONFIG_DIR.exists():
        print(f"Removing master config directory: {MASTER_CONFIG_DIR}")
        shutil.rmtree(MASTER_CONFIG_DIR)
        print("  ✓ Master config directory removed")

    print()
    print("✓ Master config setup removed successfully!")
    print()
    print("Each project now has its own configuration files:")
    for project_name in PROJECTS:
        project_path = PROJECTS_DIR / project_name
        print(f"  - {project_path}/.cursorrules")
        print(f"  - {project_path}/.editorconfig")
        print(f"  - {project_path}/.vscode/settings.json")


if __name__ == "__main__":
    main()
