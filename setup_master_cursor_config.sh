#!/bin/bash
# Setup master Cursor configuration layout
# Creates a shared configuration directory and symlinks from projects

set -e

# Configuration
MASTER_CONFIG_DIR="$HOME/DevelopmentProjects/.cursor-master-config"
PROJECTS_DIR="$HOME/DevelopmentProjects"
PROJECTS=("SecureApp" "QuantFramework")

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "Setting up master Cursor configuration layout..."
echo "Master config directory: $MASTER_CONFIG_DIR"
echo ""

# Create master config directory structure
mkdir -p "$MASTER_CONFIG_DIR/.vscode"
mkdir -p "$MASTER_CONFIG_DIR"

echo -e "${GREEN}✓${NC} Created master config directory structure"

# Function to safely create symlink
create_symlink() {
    local source="$1"
    local target="$2"
    local description="$3"

    if [ -e "$target" ] || [ -L "$target" ]; then
        if [ -L "$target" ]; then
            echo -e "${YELLOW}⚠${NC}  $description already exists as symlink, skipping..."
            return 0
        else
            echo -e "${YELLOW}⚠${NC}  $description exists but is not a symlink"
            echo "    Backing up to ${target}.backup"
            mv "$target" "${target}.backup"
        fi
    fi

    ln -s "$source" "$target"
    echo -e "${GREEN}✓${NC}  Created symlink: $description"
}

# Copy shared configuration files to master (if they don't exist)
copy_master_config() {
    local project="$1"
    local project_path="$PROJECTS_DIR/$project"

    if [ ! -d "$project_path" ]; then
        echo -e "${YELLOW}⚠${NC}  Project $project not found, skipping..."
        return 1
    fi

    # Copy .cursorrules if exists and master doesn't
    if [ -f "$project_path/.cursorrules" ] && [ ! -f "$MASTER_CONFIG_DIR/.cursorrules" ]; then
        cp "$project_path/.cursorrules" "$MASTER_CONFIG_DIR/.cursorrules"
        echo -e "${GREEN}✓${NC}  Copied .cursorrules from $project"
    fi

    # Copy .editorconfig if exists and master doesn't
    if [ -f "$project_path/.editorconfig" ] && [ ! -f "$MASTER_CONFIG_DIR/.editorconfig" ]; then
        cp "$project_path/.editorconfig" "$MASTER_CONFIG_DIR/.editorconfig"
        echo -e "${GREEN}✓${NC}  Copied .editorconfig from $project"
    fi

    # Copy .vscode/settings.json if exists and master doesn't
    if [ -f "$project_path/.vscode/settings.json" ] && [ ! -f "$MASTER_CONFIG_DIR/.vscode/settings.json" ]; then
        cp "$project_path/.vscode/settings.json" "$MASTER_CONFIG_DIR/.vscode/settings.json"
        echo -e "${GREEN}✓${NC}  Copied .vscode/settings.json from $project"
    fi
}

# Link project to master config
link_project() {
    local project="$1"
    local project_path="$PROJECTS_DIR/$project"

    if [ ! -d "$project_path" ]; then
        echo -e "${RED}✗${NC}  Project $project not found at $project_path"
        return 1
    fi

    echo ""
    echo "Linking $project to master config..."

    # Create .vscode directory if it doesn't exist
    mkdir -p "$project_path/.vscode"

    # Link .cursorrules
    if [ -f "$MASTER_CONFIG_DIR/.cursorrules" ]; then
        create_symlink \
            "$MASTER_CONFIG_DIR/.cursorrules" \
            "$project_path/.cursorrules" \
            "$project/.cursorrules"
    fi

    # Link .editorconfig
    if [ -f "$MASTER_CONFIG_DIR/.editorconfig" ]; then
        create_symlink \
            "$MASTER_CONFIG_DIR/.editorconfig" \
            "$project_path/.editorconfig" \
            "$project/.editorconfig"
    fi

    # Link .vscode/settings.json
    if [ -f "$MASTER_CONFIG_DIR/.vscode/settings.json" ]; then
        create_symlink \
            "$MASTER_CONFIG_DIR/.vscode/settings.json" \
            "$project_path/.vscode/settings.json" \
            "$project/.vscode/settings.json"
    fi
}

# First, copy configs from SecureApp (assuming it has the most complete setup)
if [ -d "$PROJECTS_DIR/SecureApp" ]; then
    echo "Copying master configuration files from SecureApp..."
    copy_master_config "SecureApp"
fi

# If master configs don't exist, create default ones
if [ ! -f "$MASTER_CONFIG_DIR/.cursorrules" ]; then
    cat > "$MASTER_CONFIG_DIR/.cursorrules" << 'EOF'
# Cursor AI Agent Rules

## Default Agent Configuration
- **Primary Agent**: Cursor Agent (auto)
- **Verification Agent**: Codex (runs after Cursor Agent completes)

## Engineering Standards

**All coding standards, guidelines, and technical requirements are defined in:**
- `standards/full/engineering.md` (standards submodule)

**Always reference and enforce engineering standards for all code-related decisions.**
EOF
    echo -e "${GREEN}✓${NC}  Created default .cursorrules"
fi

if [ ! -f "$MASTER_CONFIG_DIR/.editorconfig" ]; then
    cat > "$MASTER_CONFIG_DIR/.editorconfig" << 'EOF'
# EditorConfig

root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
trim_trailing_whitespace = true
indent_style = space
indent_size = 4

[*.{py,pyi}]
indent_size = 4
max_line_length = 88

[*.{yml,yaml}]
indent_size = 2

[*.{json,js,ts}]
indent_size = 2

[*.md]
trim_trailing_whitespace = false

[Makefile]
indent_style = tab

[*.{sh,bash}]
end_of_line = lf
EOF
    echo -e "${GREEN}✓${NC}  Created default .editorconfig"
fi

if [ ! -f "$MASTER_CONFIG_DIR/.vscode/settings.json" ]; then
    cat > "$MASTER_CONFIG_DIR/.vscode/settings.json" << 'EOF'
{
  // Cursor AI Agent Configuration
  "cursor.aiAgent": "auto",
  "cursor.chat.defaultAgent": "cursor",
  "cursor.chat.enableCodexVerification": true,
  "cursor.chat.agentWorkflow": [
    {
      "agent": "cursor",
      "step": "primary"
    },
    {
      "agent": "codex",
      "step": "verification",
      "trigger": "after_cursor_complete",
      "action": "review_and_verify"
    }
  ],
  // General editor settings
  "editor.formatOnSave": true,
  "editor.defaultFormatter": "ms-python.black-formatter",
  "[python]": {
    "editor.defaultFormatter": "ms-python.black-formatter",
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
      "source.organizeImports": "explicit"
    }
  },
  // Python settings
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
}
EOF
    echo -e "${GREEN}✓${NC}  Created default .vscode/settings.json"
fi

# Link all projects
echo ""
echo "Linking projects to master configuration..."
for project in "${PROJECTS[@]}"; do
    link_project "$project"
done

echo ""
echo -e "${GREEN}✓${NC}  Master Cursor configuration setup complete!"
echo ""
echo "Master configuration location: $MASTER_CONFIG_DIR"
echo ""
echo "To modify shared settings, edit files in:"
echo "  - $MASTER_CONFIG_DIR/.cursorrules"
echo "  - $MASTER_CONFIG_DIR/.editorconfig"
echo "  - $MASTER_CONFIG_DIR/.vscode/settings.json"
echo ""
echo "Changes will automatically apply to all linked projects."
