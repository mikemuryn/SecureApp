# Cursor Workspace Strategy: Separate Workspaces vs. Symlinks

## Recommendation: Separate Workspaces (Standard Approach)

**Use separate workspace files for each project** - this is the standard, recommended approach.

### Why Separate Workspaces?

1. **Standard Practice**: Each project has its own workspace file (e.g., `SecureApp.code-workspace`, `QuantFramework.code-workspace`)
2. **No Git Issues**: No symlink tracking complications in git
3. **Project-Specific Settings**: Easy to have project-specific configurations
4. **Simplicity**: No need to manage symlinks or master config updates
5. **Cursor Works as Expected**: Cursor/VS Code works best with separate workspaces

### Workspace Files Structure

```
~/DevelopmentProjects/
├── SecureApp/
│   ├── SecureApp.code-workspace  ← Open this for SecureApp
│   ├── .vscode/
│   │   └── settings.json         ← Project-specific (or symlink to master)
│   ├── .cursorrules              ← Project-specific (or symlink to master)
│   └── .editorconfig             ← Project-specific (or symlink to master)
│
└── QuantFramework/
    ├── QuantFramework.code-workspace  ← Open this for QuantFramework
    ├── .vscode/
    │   └── settings.json              ← Project-specific (or symlink to master)
    ├── .cursorrules                   ← Project-specific (or symlink to master)
    └── .editorconfig                  ← Project-specific (or symlink to master)
```

## Hybrid Approach: Best of Both Worlds

You can use **symlinks for shared configs** while keeping **separate workspace files**:

### Shared via Symlinks (Optional):

- `.cursorrules` - Cursor AI rules
- `.editorconfig` - Editor formatting rules
- `.vscode/settings.json` - Editor/formatting settings

### Separate per Project (Recommended):

- `*.code-workspace` files - **Always separate**
- `.pre-commit-config.yaml` - Project-specific (may have different paths)
- `pytest.ini` - Project-specific (may have different coverage paths)
- `pyproject.toml` - Project-specific (different project names/dependencies)

## Opening Projects in Cursor

### Method 1: Open Workspace File (Recommended)

```bash
cursor ~/DevelopmentProjects/SecureApp/SecureApp.code-workspace
cursor ~/DevelopmentProjects/QuantFramework/QuantFramework.code-workspace
```

### Method 2: Open Folder

```bash
cursor ~/DevelopmentProjects/SecureApp
cursor ~/DevelopmentProjects/QuantFramework
```

### Method 3: From File Menu

1. File → Open Workspace from File...
2. Select the `.code-workspace` file

## Current Setup

Your current setup uses:

- ✅ **Separate workspace files** (already done)
- ✅ **Symlinks for shared configs** (via master config)

This is the **optimal hybrid approach**!

## What Changed

The symlinks were created for shared configuration files (`.cursorrules`, `.editorconfig`, `.vscode/settings.json`), but:

- **Workspace files remain separate** (as they should be)
- **Git tracks symlinks normally** - no issues
- **show_changes.ps1 works fine** - it uses git commands which operate on the working directory
