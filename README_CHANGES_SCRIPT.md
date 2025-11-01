# Changes Summary Scripts

Dynamic scripts that automatically detect the current project and show git changes for that project only.

## Usage

### Linux/WSL/macOS

```bash
./show_changes.sh
```

or

```bash
python3 show_changes.py
```

### Windows PowerShell

```powershell
.\show_changes.ps1
```

or

```powershell
python show_changes.py
```

## Features

- **Auto-detection**: Automatically detects which project you're in (SecureApp or QuantFramework)
- **Project-specific**: Only shows changes for the current project
- **Summary view**: Shows modified and new files with counts
- **Detailed view**: Option to view full git diff
- **Cross-platform**: Works on Linux, Windows, and macOS

## What It Shows

1. **Project Information**: Current project name and directory
2. **Modified Files**: Files changed since last commit (with git diff --stat)
3. **New Files**: Untracked files that are new
4. **Summary**: Count of modified and new files
5. **Optional**: Full detailed diff on request

## Example Output

```
==========================================
Changes Summary: SecureApp
==========================================

Project Directory: /home/user/DevelopmentProjects/SecureApp

## Modified Files

 .cursorrules                      | 45 +++++++++++++++++++++++++++++++
 verify_system_agents.sh          | 117 ++++++++++++++++++++++++++++++++++++++++++++

## New Files

  + show_changes.sh
  + VERIFY_AGENTS_GUIDE.md
  + CURSOR_CUSTOM_INSTRUCTIONS_GUIDE.md

## Automatic Summary

**Total Changes:** 5 files (2 modified, 3 new)

**By Category:**
  • Configuration/root files: 2
  • Scripts: 2
  • Documentation: 2

**Code Changes:**
  • Lines added: 162
  • Lines removed: 0
  • Net change: +162 lines

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

## Why Not a Static File?

- **Dynamic**: Shows current state, not historical documentation
- **Project-aware**: Automatically detects which project you're in
- **Real-time**: Always up-to-date with current git status
- **Reusable**: Same script works for both SecureApp and QuantFramework
