#!/bin/bash
# Test script to verify commit message generation works

PROJECT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$PROJECT_ROOT" ]; then
    echo "Error: Not in a git repository"
    exit 1
fi

cd "$PROJECT_ROOT" || exit 1

echo "Testing commit message generation..."
echo "======================================"
echo ""

# Test generate_commit_msg.sh
echo "1. Testing generate_commit_msg.sh:"
if [ -f "$PROJECT_ROOT/generate_commit_msg.sh" ]; then
    MSG=$(bash "$PROJECT_ROOT/generate_commit_msg.sh" 2>&1)
    if [ -n "$MSG" ]; then
        echo "   ✓ Generated message:"
        echo "$MSG" | head -5 | sed 's/^/      /'
    else
        echo "   ✗ No message generated"
    fi
else
    echo "   ✗ generate_commit_msg.sh not found"
fi
echo ""

# Test show_changes.sh extraction
echo "2. Testing show_changes.sh extraction:"
if [ -f "$PROJECT_ROOT/show_changes.sh" ]; then
    OUTPUT=$(bash "$PROJECT_ROOT/show_changes.sh" 2>&1)
    if echo "$OUTPUT" | grep -q '```'; then
        echo "   ✓ Found commit message section in output"
        # Try to extract
        IN_SECTION=0
        EXTRACTED=""
        while IFS= read -r line; do
            if [ "$line" = '```' ]; then
                if [ "$IN_SECTION" -eq 0 ]; then
                    IN_SECTION=1
                else
                    break
                fi
            elif [ "$IN_SECTION" -eq 1 ]; then
                if [ -z "$EXTRACTED" ]; then
                    EXTRACTED="$line"
                else
                    EXTRACTED="$EXTRACTED"$'\n'"$line"
                fi
            fi
        done <<< "$OUTPUT"

        if [ -n "$EXTRACTED" ]; then
            echo "   ✓ Extracted message:"
            echo "$EXTRACTED" | head -5 | sed 's/^/      /'
        else
            echo "   ✗ Could not extract message"
        fi
    else
        echo "   ✗ No commit message section found in output"
    fi
else
    echo "   ✗ show_changes.sh not found"
fi
echo ""

# Test hook directly
echo "3. Testing prepare-commit-msg hook:"
TMP_FILE=$(mktemp)
if [ -f "$PROJECT_ROOT/.git/hooks/prepare-commit-msg" ]; then
    # Simulate hook call
    bash "$PROJECT_ROOT/.git/hooks/prepare-commit-msg" "$TMP_FILE" "" ""
    if [ -s "$TMP_FILE" ]; then
        NON_COMMENT=$(grep -v "^#" "$TMP_FILE" | grep -v "^[[:space:]]*$" | head -3)
        if [ -n "$NON_COMMENT" ]; then
            echo "   ✓ Hook generated message:"
            echo "$NON_COMMENT" | sed 's/^/      /'
        else
            echo "   ✗ Hook created file but message is empty or only comments"
        fi
    else
        echo "   ✗ Hook did not create a message file"
    fi
    rm -f "$TMP_FILE"
else
    echo "   ✗ prepare-commit-msg hook not found"
fi
echo ""

echo "======================================"
echo "Test complete. If all tests pass, the hook should work."
echo ""
echo "To verify, try: git commit"
echo "The commit message should be auto-generated."
