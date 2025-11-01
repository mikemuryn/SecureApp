#!/bin/bash
# Fix line endings and permissions for commit review scripts

echo "Fixing line endings and permissions..."
echo ""

# Fix line endings (remove CRLF) - silent, no error if already fixed
sed -i 's/\r$//' git-commit-review setup_git_aliases.sh 2>/dev/null || true

# Make executable
chmod +x git-commit-review setup_git_aliases.sh

# Verify files exist
if [ ! -f "git-commit-review" ]; then
    echo "Error: git-commit-review not found"
    exit 1
fi

if [ ! -x "git-commit-review" ]; then
    echo "Warning: git-commit-review is not executable, fixing..."
    chmod +x git-commit-review
fi

echo "✅ Fixed line endings and permissions!"
echo ""
echo "Next steps:"
echo "  1. Run: bash setup_git_aliases.sh"
echo "  2. Then: git cr"
