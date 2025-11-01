#!/bin/bash
# Generate commit message from current git changes
# Extracts the commit message from show_changes.sh output

# Get the project root
PROJECT_ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$PROJECT_ROOT" ]; then
    echo "Error: Not in a git repository" >&2
    exit 1
fi

cd "$PROJECT_ROOT" || exit 1

# Check if show_changes.sh exists
if [ ! -f "$PROJECT_ROOT/show_changes.sh" ]; then
    echo "Error: show_changes.sh not found" >&2
    exit 1
fi

# Run show_changes.sh and extract the commit message
bash "$PROJECT_ROOT/show_changes.sh" 2>/dev/null | \
    awk '/^```$/,/^```$/' | \
    sed '1d;$d' | \
    grep -v '^$'
