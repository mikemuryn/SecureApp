#!/bin/bash
# Enhanced commit message generator with better heuristics
# Falls back to LLM if available, otherwise uses improved pattern matching

PROJECT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$PROJECT_ROOT" ]; then
    echo "Error: Not in a git repository" >&2
    exit 1
fi

cd "$PROJECT_ROOT" || exit 1

# Get changes
STAGED=$(git diff --cached --name-only 2>/dev/null || true)
UNTRACKED=$(git ls-files --others --exclude-standard 2>/dev/null || true)

if [ -z "$STAGED" ] && [ -z "$UNTRACKED" ]; then
    exit 1
fi

ALL_FILES=$(echo -e "$STAGED\n$UNTRACKED" | grep -v '^$')
TOTAL_COUNT=$(echo "$ALL_FILES" | wc -l | tr -d ' ')

# Analyze file patterns and changes for better messages
COMMIT_TYPE="chore"
COMMIT_SUBJECT=""
COMMIT_BODY=""

# Count by category
FEATURE_FILES=()
FIX_FILES=()
DOC_FILES=()
TEST_FILES=()
CONFIG_FILES=()
SCRIPT_FILES=()

for file in $ALL_FILES; do
    file_lower=$(echo "$file" | tr '[:upper:]' '[:lower:]')

    # Feature/application code
    if echo "$file" | grep -qE "^app/|^src/"; then
        FEATURE_FILES+=("$file")

    # Fixes (check file names and git diff for fix patterns)
    elif echo "$file_lower" | grep -qE "(fix|bug|error|issue|patch)"; then
        FIX_FILES+=("$file")
    elif [ -n "$STAGED" ] && echo "$STAGED" | grep -q "$file" && git diff --cached "$file" 2>/dev/null | grep -qiE "(fix|bug|error|resolve|correct)"; then
        FIX_FILES+=("$file")

    # Documentation (prioritize docs over scripts if both present)
    elif echo "$file_lower" | grep -qE "(readme|guide|doc|changelog|contrib|architect|\.md$)"; then
        DOC_FILES+=("$file")

    # Tests
    elif echo "$file" | grep -qE "^tests/|test_.*\.py$|.*_test\.py$"; then
        TEST_FILES+=("$file")

    # Configuration
    elif echo "$file" | grep -qE "\.(toml|yaml|yml|ini|json)$|^\.git|workflow|config/"; then
        CONFIG_FILES+=("$file")

    # Scripts (only if not already categorized)
    elif echo "$file" | grep -qE "\.(sh|ps1|py)$" && ! echo "$file" | grep -qE "test|spec"; then
        # Check if it's a commit/git related script
        if echo "$file_lower" | grep -qE "(commit|git)"; then
            # These are important utility scripts, categorize as chore with better description
            SCRIPT_FILES+=("$file")
        elif [ ! -d "$file" ]; then
            SCRIPT_FILES+=("$file")
        fi
    fi
done

# Determine commit type and subject based on file analysis
if [ ${#FEATURE_FILES[@]} -gt 0 ]; then
    COMMIT_TYPE="feat"
    if [ ${#FEATURE_FILES[@]} -eq 1 ]; then
        BASE=$(basename "${FEATURE_FILES[0]}" .py)
        COMMIT_SUBJECT="add $BASE functionality"
    else
        COMMIT_SUBJECT="add features (${#FEATURE_FILES[@]} files)"
    fi
    COMMIT_BODY="- Update application code: $(echo "${FEATURE_FILES[@]}" | tr ' ' ',' | head -c 60)..."$'\n'

elif [ ${#FIX_FILES[@]} -gt 0 ]; then
    COMMIT_TYPE="fix"
    if [ ${#FIX_FILES[@]} -eq 1 ]; then
        BASE=$(basename "${FIX_FILES[0]}")
        COMMIT_SUBJECT="fix issue in $BASE"
    else
        COMMIT_SUBJECT="fix issues (${#FIX_FILES[@]} files)"
    fi
    COMMIT_BODY="- Fix bugs/issues: $(echo "${FIX_FILES[@]}" | tr ' ' ',' | head -c 60)..."$'\n'

elif [ ${#TEST_FILES[@]} -gt 0 ]; then
    COMMIT_TYPE="test"
    COMMIT_SUBJECT="add tests (${#TEST_FILES[@]} files)"
    COMMIT_BODY="- Add test coverage: $(echo "${TEST_FILES[@]}" | tr ' ' ',' | head -c 60)..."$'\n'

elif [ ${#DOC_FILES[@]} -gt 0 ]; then
    COMMIT_TYPE="docs"
    if [ ${#DOC_FILES[@]} -eq 1 ]; then
        BASE=$(basename "${DOC_FILES[0]}" .md)
        COMMIT_SUBJECT="add $BASE documentation"
    else
        COMMIT_SUBJECT="update documentation (${#DOC_FILES[@]} files)"
    fi
    COMMIT_BODY="- Documentation updates: $(echo "${DOC_FILES[@]}" | tr ' ' ',' | head -c 60)..."$'\n'

elif [ ${#SCRIPT_FILES[@]} -gt 0 ]; then
    COMMIT_TYPE="chore"
    if [ ${#SCRIPT_FILES[@]} -eq 1 ]; then
        SCRIPT_BASE=$(basename "${SCRIPT_FILES[0]}" | sed 's/\.[^.]*$//')
        COMMIT_SUBJECT="add $SCRIPT_BASE script"
    else
        COMMIT_SUBJECT="add utility scripts (${#SCRIPT_FILES[@]} files)"
    fi
    COMMIT_BODY="- Add scripts: $(echo "${SCRIPT_FILES[@]}" | tr ' ' ',' | head -c 60)..."$'\n'

elif [ ${#CONFIG_FILES[@]} -gt 0 ]; then
    COMMIT_TYPE="config"
    COMMIT_SUBJECT="update configuration"
    COMMIT_BODY="- Config changes: $(echo "${CONFIG_FILES[@]}" | tr ' ' ',' | head -c 60)..."$'\n'

else
    # Generic fallback with file count
    COMMIT_TYPE="chore"
    COMMIT_SUBJECT="update $TOTAL_COUNT files"
fi

# Add specific file mentions for small changes
if [ $TOTAL_COUNT -le 5 ]; then
    COMMIT_BODY+=""
    for file in $ALL_FILES; do
        if [ -n "$STAGED" ] && echo "$STAGED" | grep -q "$file"; then
            COMMIT_BODY+="- Modify: $file"$'\n'
        else
            COMMIT_BODY+="- Add: $file"$'\n'
        fi
    done
fi

# Output commit message
echo "$COMMIT_TYPE: $COMMIT_SUBJECT"
echo ""
if [ -n "$COMMIT_BODY" ]; then
    echo -n "$COMMIT_BODY"
fi
