#!/bin/bash
# Fix git hook permissions and line endings

HOOK_FILE=".git/hooks/prepare-commit-msg"

if [ ! -f "$HOOK_FILE" ]; then
    echo "Error: $HOOK_FILE does not exist"
    exit 1
fi

# Fix line endings (remove CRLF if present)
sed -i 's/\r$//' "$HOOK_FILE"

# Make executable
chmod +x "$HOOK_FILE"

# Verify it's executable
if [ -x "$HOOK_FILE" ]; then
    echo "✓ Git hook is now executable"
else
    echo "✗ Failed to make hook executable"
    exit 1
fi

# Verify shebang
if head -1 "$HOOK_FILE" | grep -q "^#!/bin/bash"; then
    echo "✓ Shebang is correct"
else
    echo "⚠ Warning: Shebang may be incorrect"
fi

echo "Hook fixed! Try 'git commit' again."
