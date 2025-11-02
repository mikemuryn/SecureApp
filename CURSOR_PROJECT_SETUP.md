# Cursor Master Configuration Setup

This guide explains how to use the master Cursor configuration layout across multiple projects.

## Overview

The master configuration setup allows you to:

- Maintain a single source of truth for Cursor/VS Code settings
- Share `.cursorrules`, `.editorconfig`, and `.vscode/settings.json` across projects
- Update settings once and have them apply to all projects automatically

## Setup

Run the setup script to create the master configuration and link your projects:

```bash
chmod +x setup_master_cursor_config.sh
./setup_master_cursor_config.sh
```

This will:

1. Create `~/DevelopmentProjects/.cursor-master-config/` directory
2. Copy configuration files from SecureApp (or create defaults)
3. Create symbolic links in SecureApp and QuantFramework pointing to the master config

## Master Configuration Location

All shared configurations are stored in:

```
~/DevelopmentProjects/.cursor-master-config/
├── .cursorrules
├── .editorconfig
└── .vscode/
    └── settings.json
```

## Project-Specific Overrides

While most settings are shared, each project can still have project-specific files:

- `*.code-workspace` files (like `SecureApp.code-workspace`) remain project-specific
- `.pre-commit-config.yaml` remains project-specific (may have project-specific paths)
- Project-specific `.vscode/settings.json` overrides can be added if needed

## Adding a New Project

To add a new project to the master configuration:

1. Edit `setup_master_cursor_config.sh` and add your project name to the `PROJECTS` array:

    ```bash
    PROJECTS=("SecureApp" "QuantFramework" "YourNewProject")
    ```

2. Run the setup script again:

    ```bash
    ./setup_master_cursor_config.sh
    ```

    The script will safely handle existing symlinks and create new ones.

## Modifying Shared Settings

To modify settings that apply to all projects:

1. Edit files directly in `~/DevelopmentProjects/.cursor-master-config/`
2. Changes take effect immediately in all linked projects
3. You may need to reload Cursor windows for some changes to apply

## Opening a Specific Project in Cursor

### Method 1: From Command Line (Recommended)

Open Cursor with a specific project directory:

**Windows (PowerShell/WSL):**

```bash
cursor /home/mikemuryn/DevelopmentProjects/SecureApp
# or
cursor ~/DevelopmentProjects/QuantFramework
```

**Windows (Command Prompt):**

```cmd
cursor C:\Users\YourName\path\to\project
```

**WSL:**

```bash
cursor ~/DevelopmentProjects/SecureApp
```

### Method 2: From Cursor File Menu

1. Open Cursor
2. File → Open Folder (or `Ctrl+K Ctrl+O`)
3. Navigate to your project directory
4. Select the folder and click "Select Folder"

### Method 3: Open Recent

1. File → Open Recent (or `Ctrl+R`)
2. Select your project from the list

### Method 4: Open Workspace File

If a project has a `.code-workspace` file:

```bash
cursor SecureApp.code-workspace
```

Or double-click the `.code-workspace` file in your file manager.

### Method 5: From Terminal (Within Project)

If you're already in a project directory:

```bash
cursor .
```

### Method 6: Create Desktop Shortcuts

You can create shortcuts that open specific projects:

**Windows:**
Create a shortcut with target:

```
"C:\Users\YourName\AppData\Local\Programs\cursor\Cursor.exe" "C:\path\to\project"
```

**Linux/WSL:**
Create a `.desktop` file:

```ini
[Desktop Entry]
Name=SecureApp
Exec=cursor /home/mikemuryn/DevelopmentProjects/SecureApp
Type=Application
```

## Verifying Symlinks

To verify that symlinks are set up correctly:

```bash
ls -la ~/DevelopmentProjects/SecureApp/.cursorrules
ls -la ~/DevelopmentProjects/SecureApp/.editorconfig
ls -la ~/DevelopmentProjects/SecureApp/.vscode/settings.json
```

They should show as symlinks pointing to `.cursor-master-config/`.

## Troubleshooting

### Symlinks Not Working on Windows

If you're using WSL, symlinks should work. However, if you're accessing files from Windows directly:

1. Ensure you have Developer Mode enabled in Windows Settings
2. Or use WSL to run the setup script:
    ```bash
    wsl bash setup_master_cursor_config.sh
    ```

### Settings Not Applying

1. Reload Cursor window: `Ctrl+Shift+P` → "Developer: Reload Window"
2. Check that symlinks exist: `ls -la project/.cursorrules`
3. Verify Cursor can read the files (check permissions)

### Project-Specific Override Needed

If a project needs different settings:

1. Remove the symlink: `rm project/.vscode/settings.json`
2. Create a local file: `cp ~/.cursor-master-config/.vscode/settings.json project/.vscode/settings.json`
3. Edit the local file as needed

### Adding More Shared Configs

To share additional configuration files:

1. Add the file to `~/.cursor-master-config/`
2. Add a symlink creation step in `setup_master_cursor_config.sh`
3. Run the setup script

## Structure

```
~/DevelopmentProjects/
├── .cursor-master-config/          # Master configuration
│   ├── .cursorrules
│   ├── .editorconfig
│   └── .vscode/
│       └── settings.json
├── SecureApp/                      # Project with symlinks
│   ├── .cursorrules → ../.cursor-master-config/.cursorrules
│   ├── .editorconfig → ../.cursor-master-config/.editorconfig
│   ├── .vscode/
│   │   └── settings.json → ../../.cursor-master-config/.vscode/settings.json
│   └── SecureApp.code-workspace    # Project-specific
└── QuantFramework/                 # Project with symlinks
    ├── .cursorrules → ../.cursor-master-config/.cursorrules
    ├── .editorconfig → ../.cursor-master-config/.editorconfig
    └── .vscode/
        └── settings.json → ../../.cursor-master-config/.vscode/settings.json
```
