#!/bin/bash
# Remove master config setup and restore individual config files for each project

set -e

PROJECTS_DIR="$HOME/DevelopmentProjects"
MASTER_CONFIG_DIR="$PROJECTS_DIR/.cursor-master-config"
PROJECTS=("SecureApp" "QuantFramework")

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "Removing master config setup and restoring individual config files..."
echo ""

# Function to restore config file from backup or master
restore_config_file() {
    local project="$1"
    local filename="$2"
    local project_path="$PROJECTS_DIR/$project"
    local file_path="$project_path/$filename"
    local backup_path="${file_path}.backup"
    local master_path="$MASTER_CONFIG_DIR/$filename"

    # Remove symlink if it exists
    if [ -L "$file_path" ]; then
        echo -e "${YELLOW}Removing symlink:${NC} $project/$filename"
        rm "$file_path"
    fi

    # Restore from backup if it exists
    if [ -f "$backup_path" ]; then
        echo -e "${GREEN}Restoring from backup:${NC} $project/$filename"
        cp "$backup_path" "$file_path"
    # Copy from master config if it exists
    elif [ -f "$master_path" ]; then
        echo -e "${GREEN}Copying from master config:${NC} $project/$filename"
        cp "$master_path" "$file_path"
    # For .vscode/settings.json, check nested path
    elif [ "$filename" = ".vscode/settings.json" ] && [ -f "$MASTER_CONFIG_DIR/.vscode/settings.json" ]; then
        mkdir -p "$project_path/.vscode"
        echo -e "${GREEN}Copying from master config:${NC} $project/$filename"
        cp "$MASTER_CONFIG_DIR/.vscode/settings.json" "$file_path"
    else
        echo -e "${YELLOW}Warning:${NC} No source found for $project/$filename, skipping..."
        return 1
    fi
}

# Process each project
for project in "${PROJECTS[@]}"; do
    project_path="$PROJECTS_DIR/$project"

    if [ ! -d "$project_path" ]; then
        echo -e "${RED}Error:${NC} Project $project not found at $project_path"
        continue
    fi

    echo "Processing $project..."

    # Restore .cursorrules
    if [ -f "$project_path/.cursorrules.backup" ] || [ -f "$MASTER_CONFIG_DIR/.cursorrules" ]; then
        restore_config_file "$project" ".cursorrules"
    fi

    # Restore .editorconfig
    if [ -f "$project_path/.editorconfig.backup" ] || [ -f "$MASTER_CONFIG_DIR/.editorconfig" ]; then
        restore_config_file "$project" ".editorconfig"
    fi

    # Restore .vscode/settings.json
    mkdir -p "$project_path/.vscode"
    if [ -f "$project_path/.vscode/settings.json.backup" ] || [ -f "$MASTER_CONFIG_DIR/.vscode/settings.json" ]; then
        restore_config_file "$project" ".vscode/settings.json"
    fi

    echo ""
done

# Remove master config directory
if [ -d "$MASTER_CONFIG_DIR" ]; then
    echo -e "${YELLOW}Removing master config directory:${NC} $MASTER_CONFIG_DIR"
    rm -rf "$MASTER_CONFIG_DIR"
    echo -e "${GREEN}✓${NC}  Master config directory removed"
fi

echo ""
echo -e "${GREEN}✓${NC}  Master config setup removed successfully!"
echo ""
echo "Each project now has its own configuration files:"
for project in "${PROJECTS[@]}"; do
    echo "  - $PROJECTS_DIR/$project/.cursorrules"
    echo "  - $PROJECTS_DIR/$project/.editorconfig"
    echo "  - $PROJECTS_DIR/$project/.vscode/settings.json"
done
