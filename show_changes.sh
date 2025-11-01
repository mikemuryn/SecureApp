#!/bin/bash
# Show git changes summary for the current project
# Automatically detects which project (SecureApp or QuantFramework) and shows changes

# Get the current directory name
PROJECT_DIR=$(basename "$(pwd)")
PROJECT_ROOT="$(pwd)"

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "Error: Not in a git repository"
    exit 1
fi

# Get project name
PROJECT_NAME="$PROJECT_DIR"

echo "=========================================="
echo "Changes Summary: $PROJECT_NAME"
echo "=========================================="
echo ""
echo "Project Directory: $PROJECT_ROOT"
echo ""

# Check if there are any changes
if [ -z "$(git status --porcelain)" ] && [ -z "$(git ls-files --others --exclude-standard)" ]; then
    echo "✅ No changes since last commit"
    echo ""
    exit 0
fi

# Modified files
MODIFIED=$(git diff --name-only)
# New untracked files
UNTRACKED=$(git ls-files --others --exclude-standard)

# Show modified files
if [ -n "$MODIFIED" ]; then
    echo "## Modified Files"
    echo ""
    git diff --stat
    echo ""
fi

# Show new files
if [ -n "$UNTRACKED" ]; then
    echo "## New Files"
    echo ""
    git ls-files --others --exclude-standard | while read -r file; do
        echo "  + $file"
    done
    echo ""
fi

# Automatic Summary Analysis
echo "## Automatic Summary"
echo ""

# Count changes
MODIFIED_COUNT=$(echo "$MODIFIED" | grep -c . || echo "0")
UNTRACKED_COUNT=$(echo "$UNTRACKED" | grep -c . || echo "0")
TOTAL_COUNT=$((MODIFIED_COUNT + UNTRACKED_COUNT))

echo "**Total Changes:** $TOTAL_COUNT files (${MODIFIED_COUNT} modified, ${UNTRACKED_COUNT} new)"
echo ""

# Categorize files
if [ -n "$MODIFIED" ] || [ -n "$UNTRACKED" ]; then
    ALL_FILES=$(echo -e "$MODIFIED\n$UNTRACKED" | grep -v '^$')

    # Count by file type
    PYTHON_FILES=$(echo "$ALL_FILES" | grep -c '\.py$' || echo "0")
    CONFIG_FILES=$(echo "$ALL_FILES" | grep -E -c '\.(toml|yaml|yml|json|ini|cfg)$' || echo "0")
    DOC_FILES=$(echo "$ALL_FILES" | grep -E -c '\.(md|txt|rst)$' || echo "0")
    SCRIPT_FILES=$(echo "$ALL_FILES" | grep -E -c '\.(sh|ps1|bat)$' || echo "0")
    TEST_FILES=$(echo "$ALL_FILES" | grep -c '/test' || echo "0")
    CONFIG_DIR_FILES=$(echo "$ALL_FILES" | grep -E -c '(^\.|config/|\.cursor)' || echo "0")

    if [ "$PYTHON_FILES" -gt 0 ] || [ "$CONFIG_FILES" -gt 0 ] || [ "$DOC_FILES" -gt 0 ] || \
       [ "$SCRIPT_FILES" -gt 0 ] || [ "$TEST_FILES" -gt 0 ] || [ "$CONFIG_DIR_FILES" -gt 0 ]; then
        echo "**By Category:**"
        [ "$PYTHON_FILES" -gt 0 ] && echo "  • Python files: $PYTHON_FILES"
        [ "$TEST_FILES" -gt 0 ] && echo "  • Test files: $TEST_FILES"
        [ "$CONFIG_FILES" -gt 0 ] && echo "  • Config files: $CONFIG_FILES"
        [ "$CONFIG_DIR_FILES" -gt 0 ] && echo "  • Configuration/root files: $CONFIG_DIR_FILES"
        [ "$DOC_FILES" -gt 0 ] && echo "  • Documentation: $DOC_FILES"
        [ "$SCRIPT_FILES" -gt 0 ] && echo "  • Scripts: $SCRIPT_FILES"
        echo ""
    fi

    # Analyze change types (for commit message)
    LINES_ADDED=0
    LINES_REMOVED=0
    NET_CHANGES=0

    if [ -n "$MODIFIED" ]; then
        LINES_ADDED=$(git diff --numstat | awk '{sum+=$1} END {print sum+0}')
        LINES_REMOVED=$(git diff --numstat | awk '{sum+=$2} END {print sum+0}')
        NET_CHANGES=$((LINES_ADDED - LINES_REMOVED))

        echo "**Code Changes:**"
        echo "  • Lines added: $LINES_ADDED"
        echo "  • Lines removed: $LINES_REMOVED"
        if [ "$NET_CHANGES" -gt 0 ]; then
            echo "  • Net change: +$NET_CHANGES lines"
        elif [ "$NET_CHANGES" -lt 0 ]; then
            echo "  • Net change: $NET_CHANGES lines"
        else
            echo "  • Net change: 0 lines"
        fi
        echo ""
    fi

    # Generate commit message summary
    echo "## Suggested Commit Message"
    echo ""

    # Build commit message components
    COMMIT_TYPE=""
    COMMIT_SCOPE=""
    COMMIT_SUBJECT=""
    COMMIT_BODY=""

    # Determine type and scope
    CHANGE_TYPES=()

    if echo "$ALL_FILES" | grep -q "\.cursorrules"; then
        CHANGE_TYPES+=("config")
        COMMIT_BODY+="- Update Cursor AI agent configuration"$'\n'
    fi

    if echo "$ALL_FILES" | grep -q -E "(verify_|guide)"; then
        CHANGE_TYPES+=("docs")
        COMMIT_BODY+="- Add verification scripts and documentation"$'\n'
    fi

    if echo "$ALL_FILES" | grep -q -E "(test_|tests/)"; then
        CHANGE_TYPES+=("test")
        COMMIT_BODY+="- Update test suite"$'\n'
    fi

    if echo "$ALL_FILES" | grep -q -E "(app/|src/|trading/).*\.py$"; then
        CHANGE_TYPES+=("feat")
        COMMIT_BODY+="- Update application code"$'\n'
    fi

    if echo "$ALL_FILES" | grep -q -E "(requirements|pyproject|setup\.py)"; then
        CHANGE_TYPES+=("build")
        COMMIT_BODY+="- Update dependencies/package configuration"$'\n'
    fi

    if echo "$ALL_FILES" | grep -E "\.(sh|ps1|py)$" | grep -v test | grep -q .; then
        CHANGE_TYPES+=("chore")
        COMMIT_BODY+="- Add utility scripts"$'\n'
    fi

    # Determine primary type (prioritize feat > fix > docs > test > build > chore)
    if [[ " ${CHANGE_TYPES[@]} " =~ " feat " ]]; then
        COMMIT_TYPE="feat"
    elif [[ " ${CHANGE_TYPES[@]} " =~ " fix " ]]; then
        COMMIT_TYPE="fix"
    elif [[ " ${CHANGE_TYPES[@]} " =~ " docs " ]]; then
        COMMIT_TYPE="docs"
    elif [[ " ${CHANGE_TYPES[@]} " =~ " test " ]]; then
        COMMIT_TYPE="test"
    elif [[ " ${CHANGE_TYPES[@]} " =~ " build " ]]; then
        COMMIT_TYPE="build"
    else
        COMMIT_TYPE="chore"
    fi

    # Build subject line with better context
    if [ "$TOTAL_COUNT" -eq 1 ]; then
        if [ "$UNTRACKED_COUNT" -eq 1 ]; then
            FILE_NAME=$(basename "$(echo "$UNTRACKED" | head -1)")
            # Remove extension for cleaner message
            FILE_BASE=$(echo "$FILE_NAME" | sed 's/\.[^.]*$//')
            COMMIT_SUBJECT="add $FILE_BASE"
        else
            FILE_NAME=$(basename "$(echo "$MODIFIED" | head -1)")
            FILE_BASE=$(echo "$FILE_NAME" | sed 's/\.[^.]*$//')
            COMMIT_SUBJECT="update $FILE_BASE"
        fi
    elif [ "$PYTHON_FILES" -gt 0 ] && [ "$PYTHON_FILES" -eq "$TOTAL_COUNT" ]; then
        # More specific if all Python files
        if echo "$ALL_FILES" | grep -q "^app/"; then
            COMMIT_SUBJECT="update application code"
        elif echo "$ALL_FILES" | grep -q "^tests/"; then
            COMMIT_SUBJECT="add test coverage"
        else
            COMMIT_SUBJECT="update Python code"
        fi
    elif [ "$SCRIPT_FILES" -gt 0 ]; then
        if [ "$SCRIPT_FILES" -eq 1 ]; then
            SCRIPT_NAME=$(basename "$(echo "$ALL_FILES" | grep -E "\.(sh|ps1|py)$" | head -1)" | sed 's/\.[^.]*$//')
            COMMIT_SUBJECT="add $SCRIPT_NAME script"
        else
            COMMIT_SUBJECT="add utility scripts"
        fi
    elif [ "$DOC_FILES" -gt 0 ] && [ "$DOC_FILES" -eq "$TOTAL_COUNT" ]; then
        if [ "$DOC_FILES" -eq 1 ]; then
            DOC_NAME=$(basename "$(echo "$ALL_FILES" | grep -E "\.md$" | head -1)" .md)
            COMMIT_SUBJECT="add $DOC_NAME documentation"
        else
            COMMIT_SUBJECT="update documentation"
        fi
    elif [ "$CONFIG_FILES" -gt 0 ]; then
        COMMIT_SUBJECT="update configuration"
    else
        COMMIT_SUBJECT="update project files"
    fi

    # Output commit message format
    echo '```'
    echo "$COMMIT_TYPE: $COMMIT_SUBJECT"
    echo ""
    if [ -n "$COMMIT_BODY" ]; then
        echo -n "$COMMIT_BODY"
    fi
    echo ""
    echo "Files changed: $TOTAL_COUNT ($MODIFIED_COUNT modified, $UNTRACKED_COUNT new)"
    if [ "$LINES_ADDED" -gt 0 ] || [ "$LINES_REMOVED" -gt 0 ]; then
        echo "Lines: +$LINES_ADDED/-$LINES_REMOVED (net: $NET_CHANGES)"
    fi
    echo '```'
    echo ""
fi

# Option to show detailed diff (skip if non-interactive)
if [ -n "$MODIFIED" ] && [ -t 0 ]; then
    read -p "Show detailed diff? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git diff
    fi
fi

echo ""
echo "=========================================="
