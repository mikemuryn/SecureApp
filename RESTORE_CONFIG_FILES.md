# Restore Individual Config Files - Manual Instructions

Since the master config symlinks have been set up, here are the steps to restore individual files:

## Quick Fix: Run the Python Script

```bash
python3 remove_master_config.py
```

This script will:

1. Remove symlinks from both projects
2. Create individual config files with SecureApp formatting
3. Remove the master config directory

## Manual Steps (if script doesn't work)

### For SecureApp:

1. Remove symlinks (if they exist):

    ```bash
    cd ~/DevelopmentProjects/SecureApp
    rm -f .cursorrules .editorconfig .vscode/settings.json
    ```

2. Restore from backups:
    ```bash
    cp .cursorrules.backup .cursorrules
    cp .editorconfig.backup .editorconfig
    mkdir -p .vscode
    cp .vscode/settings.json.backup .vscode/settings.json
    ```

### For QuantFramework:

1. Remove symlinks (if they exist):

    ```bash
    cd ~/DevelopmentProjects/QuantFramework
    rm -f .cursorrules .editorconfig .vscode/settings.json
    ```

2. Copy from SecureApp backups (same formatting):

    ```bash
    cp ../SecureApp/.cursorrules.backup .cursorrules
    # Edit .cursorrules: Change "SecureApp" to "QuantFramework"

    cp ../SecureApp/.editorconfig.backup .editorconfig
    # Edit .editorconfig: Change "SecureApp" to "QuantFramework"

    mkdir -p .vscode
    cp ../SecureApp/.vscode/settings.json.backup .vscode/settings.json
    # No change needed - settings.json is the same for both
    ```

3. Remove master config directory:
    ```bash
    rm -rf ~/DevelopmentProjects/.cursor-master-config
    ```
