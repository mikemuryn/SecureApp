# Copy Workspace Layout/Display from SecureApp to QuantFramework

## Understanding Workspace Layout in Cursor/VS Code

The workspace layout (panel positions, open files, editor groups, sidebar positions) is stored separately from configuration files. Here's how to replicate it:

## Method 1: Manual Layout Replication (Recommended)

### Step 1: Note Your SecureApp Layout

When you have SecureApp open with your preferred layout:

1. **Panels/Sidebars:**
    - Which sidebars are visible? (Explorer, Search, Source Control, etc.)
    - Where are they positioned? (Left, Right)
    - Bottom panel visibility? (Terminal, Problems, Output, Debug Console)

2. **Editor Layout:**
    - Single editor or split view?
    - How many editor groups?
    - Which files are typically open?

3. **Views Visibility:**
    - Explorer: Folders/files shown
    - Source Control: Git status view
    - Extensions: Installed extensions list

### Step 2: Apply to QuantFramework

1. Open QuantFramework workspace:

    ```bash
    cursor ~/DevelopmentProjects/QuantFramework/QuantFramework.code-workspace
    ```

2. Manually configure:
    - **View Menu** → Toggle views (Explorer, Search, etc.)
    - **View Menu** → Appearance → Move panels to desired positions
    - **Terminal Menu** → New Terminal (creates bottom panel if needed)

3. Cursor will remember this layout for QuantFramework workspace

## Method 2: Copy Workspace Storage (Advanced)

Cursor stores workspace state in:

- **Windows**: `%APPDATA%\Cursor\User\workspaceStorage\{workspace-id}\`
- **Linux/WSL**: `~/.config/Cursor/User/workspaceStorage/{workspace-id}/`

### Steps:

1. **Find SecureApp workspace storage:**

    ```bash
    # In WSL or Linux
    ls -la ~/.config/Cursor/User/workspaceStorage/
    ```

2. **Find workspace IDs:**
    - Each folder is a workspace ID (hash)
    - Find the one for SecureApp by checking `workspace.json` inside each folder

3. **Copy workspace state:**

    ```bash
    # Backup first!
    cp -r ~/.config/Cursor/User/workspaceStorage/{secureapp-id} \
         ~/.config/Cursor/User/workspaceStorage/{secureapp-id}.backup

    # Note: This may not work perfectly due to path differences
    ```

**⚠️ Warning**: This method can cause issues since workspace IDs are unique. Not recommended.

## Method 3: Use Workspace Layout Extension

Install the "Workspace Layout" extension if available, which allows saving/loading workspace layouts.

## Method 4: Create Layout Settings in Workspace File

Some layout preferences can be set in the workspace file:

```json
{
    "folders": [
        {
            "path": "."
        }
    ],
    "settings": {
        // Your existing settings...

        // Panel position (bottom, left, right)
        "workbench.panel.defaultLocation": "bottom",

        // Sidebar position (left, right)
        "workbench.sideBar.location": "left",

        // Explorer auto reveal
        "explorer.autoReveal": true,

        // Editor layout
        "workbench.editor.openPositioning": "right"
    },
    "extensions": {
        "recommendations": [
            // Extension IDs you use
        ]
    }
}
```

## Quick Setup Checklist

When opening QuantFramework workspace:

- [ ] Open Explorer sidebar (Ctrl+Shift+E)
- [ ] Position terminal at bottom (View → Appearance → Terminal)
- [ ] Show Source Control panel if needed
- [ ] Set up your preferred editor split layout
- [ ] Configure any custom views you use in SecureApp

Cursor will save this layout automatically for the QuantFramework workspace.

## Pro Tip: Standardize Your Layout

Once you've set up QuantFramework with your preferred layout, it will be remembered. You can also:

1. Set up keyboard shortcuts for common layout switches
2. Use workspaces to quickly switch between project layouts
3. Use the Command Palette (Ctrl+Shift+P) → "View: Reset View Locations"
