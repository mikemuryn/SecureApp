# Git Commit Message Generation Guide

## Quick Start - Automatic Commit with Review (Recommended) ⭐

**No editor, command-line review, automatic commit:**

```bash
# First time setup:
bash setup_git_aliases.sh

# Then use:
git commit-review
# or the shorter alias:
git cr
```

**What it does:**

1. ✅ Generates commit message from your changes
2. ✅ Displays it on the command line (no editor)
3. ✅ Asks for confirmation: `y` (commit), `n` (cancel), `e` (edit)
4. ✅ Commits automatically if you confirm

---

## Files That Generate Commit Messages

### 1. `git-commit-review` (NEW - Recommended) ⭐

**Purpose**: Generate commit message, show for review, commit automatically

**Location**: Project root

**Usage**:

```bash
# Direct usage:
./git-commit-review

# Or via git alias (after setup):
git commit-review
git cr  # shorter alias
```

**Features**:

- No editor opens
- Shows message on command line
- Quick review and confirmation
- Commits directly if approved
- Option to edit before committing

**Example Output**:

```
==========================================
Generated Commit Message:
==========================================

fix: correct authentication tuple unpacking in CLI

- Fix authentication checks in cmd_upload, cmd_download, cmd_list, cmd_delete
- Fix authentication check in cmd_backup

Files changed: 5 (4 modified, 1 new)

==========================================

Commit with this message? (y/n/e for edit): y
✅ Committed successfully!
```

---

### 2. `show_changes.sh` / `show_changes.py` / `show_changes.ps1`

**Purpose**: Display changes summary with suggested commit message

**Location**: Project root

**Usage**:

```bash
./show_changes.sh
# Shows full summary + suggested commit message
```

**Output**: Full change summary with a "Suggested Commit Message" section at the bottom

---

### 3. `generate_commit_msg.sh`

**Purpose**: Extract just the commit message (no summary, clean output)

**Location**: Project root

**Usage**:

```bash
./generate_commit_msg.sh > commit_msg.txt
# Then use: git commit -F commit_msg.txt
```

**Output**: Clean commit message only (can be piped to file or used directly)

---

### 4. `.git/hooks/prepare-commit-msg` (Optional)

**Purpose**: Automatically generate commit message when you run `git commit`

**Location**: `.git/hooks/prepare-commit-msg`

**Note**: This opens the editor. If you want command-line review instead, use `git commit-review` above.

**How it works**:

- Runs automatically when you execute `git commit`
- Generates commit message from current changes
- Populates the commit message file before the editor opens
- You can edit the message before committing

**Usage**:

```bash
git commit
# Commit message is auto-generated and opened in editor
# Edit if needed, save and close
```

**To disable**: Remove or rename `.git/hooks/prepare-commit-msg`

---

## Which Method to Use?

### For Command-Line Review (Recommended) ⭐

```bash
git commit-review
# or: git cr
```

- ✅ No editor opens
- ✅ Message shown on command line
- ✅ Quick review and confirmation
- ✅ Automatic commit if approved

### For Manual Review

```bash
./show_changes.sh
# Review the full summary, then copy the commit message manually
```

### For Editor-Based Workflow

```bash
git commit
# Opens editor with auto-generated message (if hook enabled)
```

### For Scripting/Automation

```bash
git commit -m "$(./generate_commit_msg.sh | head -1)"
# Uses just the subject line
```

or

```bash
./generate_commit_msg.sh > /tmp/commit_msg.txt
git commit -F /tmp/commit_msg.txt
# Uses the full message
```

---

## Commit Message Format

The generated messages follow **Conventional Commits** format:

```
<type>: <subject>

<body>

<footer>
```

**Types used**:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test updates
- `build`: Build system/dependencies
- `chore`: Maintenance tasks

---

## Examples

### Example 1: Using git commit-review (Recommended)

```bash
$ git cr
==========================================
Generated Commit Message:
==========================================

feat: add automatic commit message generation

- Add git-commit-review script for command-line review
- Add setup_git_aliases.sh for easy configuration
- Update GIT_COMMIT_MESSAGE_GUIDE.md with new workflow

Files changed: 3 (1 modified, 2 new)
Lines: +127/-45 (net: +82)

==========================================

Commit with this message? (y/n/e for edit): y
✅ Committed successfully!
```

### Example 2: Using show_changes.sh

```bash
$ ./show_changes.sh
# ... full output ...
## Suggested Commit Message

```

docs: add verification scripts and documentation

- Update Cursor AI agent configuration
- Add verification scripts and documentation
- Add utility scripts

Files changed: 5 (2 modified, 3 new)
Lines: +162/-0 (net: +162)

```

```

Then copy the message and commit:

```bash
git commit -m "docs: add verification scripts and documentation

- Update Cursor AI agent configuration
- Add verification scripts and documentation
- Add utility scripts"
```

### Example 3: Using generate_commit_msg.sh

```bash
$ git commit -F <(./generate_commit_msg.sh)
# Commits with generated message directly
```

---

## Configuration

### Setup git aliases (one-time):

```bash
bash setup_git_aliases.sh
```

This creates:

- `git commit-review` - Full alias
- `git cr` - Short alias

### Disable the git hook (if you prefer command-line review):

```bash
mv .git/hooks/prepare-commit-msg .git/hooks/prepare-commit-msg.disabled
```

### Re-enable the git hook:

```bash
mv .git/hooks/prepare-commit-msg.disabled .git/hooks/prepare-commit-msg
chmod +x .git/hooks/prepare-commit-msg
```

---

## Troubleshooting

#### Issue: "Aborting commit due to empty commit message"

This means the hook ran but didn't generate a message. Try:

1. **Test the hook manually:**

    ```bash
    bash test_commit_hook.sh
    ```

2. **Check if scripts are executable:**

    ```bash
    chmod +x generate_commit_msg.sh show_changes.sh .git/hooks/prepare-commit-msg
    ```

3. **Verify you have changes to commit:**

    ```bash
    git status
    # Make sure there are staged changes (git add) or untracked files
    ```

4. **Test message generation directly:**

    ```bash
    bash generate_commit_msg.sh
    # Should output a commit message
    ```

5. **Use git commit-review instead:**
    ```bash
    git commit-review
    # This shows the message on command line and doesn't use the hook
    ```

#### Issue: "cannot exec '.git/hooks/prepare-commit-msg': No such file or directory"

1. **Fix permissions and line endings:**

    ```bash
    chmod +x .git/hooks/prepare-commit-msg
    sed -i 's/\r$//' .git/hooks/prepare-commit-msg  # Fix Windows line endings
    ```

2. **Or use the fix script:**

    ```bash
    bash fix_git_hook.sh
    ```

3. **Or just use git commit-review:**
    ```bash
    git commit-review
    # Doesn't need the hook at all
    ```

---

## Summary

- **For command-line review (no editor)**: Use `git commit-review` or `git cr`
- **For full change summary**: Use `show_changes.sh`
- **For scripting**: Use `generate_commit_msg.sh`
- **For editor-based workflow**: Use `git commit` (requires hook enabled)
