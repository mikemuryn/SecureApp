#!/bin/bash
# Quick test of enhanced commit message generation

echo "Testing enhanced commit message generator..."
echo ""

# Stage some test files to simulate a real scenario
# (This is just for testing - won't actually commit)

# Test 1: Script files
echo "=== Test 1: Script files ==="
echo "Files: generate_commit_msg_enhanced.sh, git-commit-review"
echo "Expected: 'chore: add utility scripts'"
echo ""

# Test 2: Doc + Script files (should prioritize docs)
echo "=== Test 2: Documentation + Scripts ==="
echo "Files: COMMIT_MESSAGE_LLM_INTEGRATION.md, generate_commit_msg_enhanced.sh"
echo "Expected: 'docs: update documentation (1 files)'"
echo ""

# Test 3: Single script
echo "=== Test 3: Single script ==="
echo "Files: git-commit-review"
echo "Expected: 'chore: add utility scripts (1 files)' or 'chore: add git-commit-review script'"
echo ""

# Actually run the script
echo "=== Running actual script ==="
echo ""
if [ -f "generate_commit_msg_enhanced.sh" ]; then
    bash generate_commit_msg_enhanced.sh
else
    echo "Error: generate_commit_msg_enhanced.sh not found"
fi
