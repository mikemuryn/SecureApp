#!/bin/bash
# Replicate workspace setup from SecureApp to QuantFramework
# This ensures both projects have consistent configuration files

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECTS_DIR="$(dirname "$SCRIPT_DIR")"
SOURCE_PROJECT="SecureApp"
TARGET_PROJECT="QuantFramework"

SOURCE_PATH="$PROJECTS_DIR/$SOURCE_PROJECT"
TARGET_PATH="$PROJECTS_DIR/$TARGET_PROJECT"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "Replicating workspace setup from $SOURCE_PROJECT to $TARGET_PROJECT..."
echo ""

# Verify source exists
if [ ! -d "$SOURCE_PATH" ]; then
    echo -e "${RED}✗${NC}  Source project $SOURCE_PROJECT not found at $SOURCE_PATH"
    exit 1
fi

# Verify target exists
if [ ! -d "$TARGET_PATH" ]; then
    echo -e "${RED}✗${NC}  Target project $TARGET_PROJECT not found at $TARGET_PATH"
    exit 1
fi

# Function to copy or update a file
copy_config_file() {
    local source_file="$1"
    local target_file="$2"
    local description="$3"
    local is_workspace="${4:-false}"

    if [ ! -f "$source_file" ]; then
        echo -e "${YELLOW}⚠${NC}  Source file not found: $source_file"
        return 1
    fi

    # For workspace files, we need to update the path
    if [ "$is_workspace" = "true" ]; then
        # Extract project name from target path
        local project_name="$(basename "$TARGET_PATH")"
        # Copy and update the workspace file
        cp "$source_file" "$target_file"
        # Update the folder path if needed (workspace files use ".")
        # The workspace file typically uses "." which is correct for each project
        echo -e "${GREEN}✓${NC}  Updated $description"
    else
        # Regular file copy
        if [ -f "$target_file" ]; then
            # Backup existing file
            if [ ! -L "$target_file" ]; then
                echo -e "${YELLOW}⚠${NC}  $description exists, backing up..."
                cp "$target_file" "${target_file}.backup.$(date +%Y%m%d_%H%M%S)"
            fi
        fi
        cp "$source_file" "$target_file"
        echo -e "${GREEN}✓${NC}  Copied $description"
    fi
}

# 1. Workspace file
echo "1. Workspace configuration..."
WORKSPACE_SOURCE="$SOURCE_PATH/${SOURCE_PROJECT}.code-workspace"
WORKSPACE_TARGET="$TARGET_PATH/${TARGET_PROJECT}.code-workspace"
if [ -f "$WORKSPACE_SOURCE" ]; then
    # Read and update the workspace file
    python3 << EOF
import json
import sys

source_file = "$WORKSPACE_SOURCE"
target_file = "$WORKSPACE_TARGET"

with open(source_file, 'r') as f:
    workspace = json.load(f)

# Workspace files typically use "." for the folder path which is correct
# We just need to ensure settings are replicated
with open(target_file, 'w') as f:
    json.dump(workspace, f, indent='\t', ensure_ascii=False)

print("Updated workspace file with settings from source")
EOF
    echo -e "${GREEN}✓${NC}  Updated ${TARGET_PROJECT}.code-workspace"
else
    echo -e "${YELLOW}⚠${NC}  Source workspace file not found, skipping..."
fi

# 2. Pre-commit config (project-specific, so we copy as template)
echo ""
echo "2. Pre-commit configuration..."
PRE_COMMIT_SOURCE="$SOURCE_PATH/.pre-commit-config.yaml"
PRE_COMMIT_TARGET="$TARGET_PATH/.pre-commit-config.yaml"
if [ -f "$PRE_COMMIT_SOURCE" ]; then
    copy_config_file "$PRE_COMMIT_SOURCE" "$PRE_COMMIT_TARGET" ".pre-commit-config.yaml"
    echo -e "${YELLOW}ℹ${NC}  Review and update .pre-commit-config.yaml paths if needed"
else
    echo -e "${YELLOW}⚠${NC}  Source .pre-commit-config.yaml not found, skipping..."
fi

# 3. pyproject.toml (copy structure, project-specific values may differ)
echo ""
echo "3. Python project configuration..."
PYPROJECT_SOURCE="$SOURCE_PATH/pyproject.toml"
PYPROJECT_TARGET="$TARGET_PATH/pyproject.toml"
if [ -f "$PYPROJECT_SOURCE" ]; then
    if [ -f "$PYPROJECT_TARGET" ]; then
        echo -e "${YELLOW}⚠${NC}  pyproject.toml exists in target, creating merge comparison..."
        echo -e "${YELLOW}ℹ${NC}  Compare $PYPROJECT_SOURCE with $PYPROJECT_TARGET"
        echo -e "${YELLOW}ℹ${NC}  Update target manually if needed"
    else
        copy_config_file "$PYPROJECT_SOURCE" "$PYPROJECT_TARGET" "pyproject.toml"
        echo -e "${YELLOW}ℹ${NC}  Update project name and other project-specific values"
    fi
else
    echo -e "${YELLOW}⚠${NC}  Source pyproject.toml not found, skipping..."
fi

# 4. pytest.ini (usually project-specific)
echo ""
echo "4. Pytest configuration..."
PYTEST_SOURCE="$SOURCE_PATH/pytest.ini"
PYTEST_TARGET="$TARGET_PATH/pytest.ini"
if [ -f "$PYTEST_SOURCE" ]; then
    if [ -f "$PYTEST_TARGET" ]; then
        echo -e "${YELLOW}⚠${NC}  pytest.ini exists in target, comparing..."
        if ! diff -q "$PYTEST_SOURCE" "$PYTEST_TARGET" > /dev/null 2>&1; then
            echo -e "${YELLOW}ℹ${NC}  Differences found. Review manually."
            echo -e "${YELLOW}ℹ${NC}  Source: $PYTEST_SOURCE"
            echo -e "${YELLOW}ℹ${NC}  Target: $PYTEST_TARGET"
        else
            echo -e "${GREEN}✓${NC}  pytest.ini already matches"
        fi
    else
        copy_config_file "$PYTEST_SOURCE" "$PYTEST_TARGET" "pytest.ini"
        echo -e "${YELLOW}ℹ${NC}  Update coverage paths if project structure differs"
    fi
else
    echo -e "${YELLOW}⚠${NC}  Source pytest.ini not found, skipping..."
fi

# 5. tox.ini (if exists)
echo ""
echo "5. Tox configuration..."
TOX_SOURCE="$SOURCE_PATH/tox.ini"
TOX_TARGET="$TARGET_PATH/tox.ini"
if [ -f "$TOX_SOURCE" ]; then
    copy_config_file "$TOX_SOURCE" "$TOX_TARGET" "tox.ini"
else
    echo -e "${YELLOW}ℹ${NC}  No tox.ini in source, skipping..."
fi

# 6. .gitignore (merge approach - don't overwrite, show differences)
echo ""
echo "6. Git ignore configuration..."
GITIGNORE_SOURCE="$SOURCE_PATH/.gitignore"
GITIGNORE_TARGET="$TARGET_PATH/.gitignore"
if [ -f "$GITIGNORE_SOURCE" ] && [ -f "$GITIGNORE_TARGET" ]; then
    echo -e "${YELLOW}ℹ${NC}  Both .gitignore files exist, compare manually if needed"
elif [ -f "$GITIGNORE_SOURCE" ] && [ ! -f "$GITIGNORE_TARGET" ]; then
    copy_config_file "$GITIGNORE_SOURCE" "$GITIGNORE_TARGET" ".gitignore"
else
    echo -e "${YELLOW}⚠${NC}  Source .gitignore not found, skipping..."
fi

echo ""
echo -e "${GREEN}✓${NC}  Workspace replication complete!"
echo ""
echo "Summary:"
echo "  - Workspace file: ${TARGET_PROJECT}.code-workspace"
echo "  - Configuration files copied/updated"
echo ""
echo "Next steps:"
echo "  1. Review and update project-specific paths in copied files"
echo "  2. Update pre-commit hooks if project structure differs:"
echo "     cd $TARGET_PATH && pre-commit install"
echo "  3. Test the workspace: cursor ${TARGET_PROJECT}.code-workspace"
echo ""
echo "Note: .cursorrules, .editorconfig, and .vscode/settings.json"
echo "      are managed by the master config (symlinks)."
