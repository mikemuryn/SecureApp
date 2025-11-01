#!/bin/bash
# Setup git aliases for commit review workflow

echo "Setting up git aliases for commit review..."
echo ""

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "Error: Not in a git repository"
    exit 1
fi

PROJECT_ROOT=$(git rev-parse --show-toplevel)
SCRIPT_PATH="$PROJECT_ROOT/git-commit-review"

# Make sure the script is executable
chmod +x "$SCRIPT_PATH"

# Create git alias
git config alias.commit-review '!f() { bash '"$SCRIPT_PATH"' "$@"; }; f'

# Create shorter alias
git config alias.cr '!f() { bash '"$SCRIPT_PATH"' "$@"; }; f'

echo "✅ Git aliases configured!"
echo ""
echo "Usage:"
echo "  git commit-review   # or: git cr"
echo ""
echo "This will:"
echo "  1. Generate a commit message from your changes"
echo "  2. Display it for review"
echo "  3. Ask for confirmation (y/n/e)"
echo "     - y: Commit with the message"
echo "     - n: Cancel"
echo "     - e: Edit the message before committing"
echo ""
echo "Note: The standard 'git commit' will still work as before (opens editor)."
