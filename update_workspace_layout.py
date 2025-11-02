#!/usr/bin/env python3
"""Add layout settings to workspace files for consistent display."""

import json
from pathlib import Path

PROJECTS_DIR = Path.home() / "DevelopmentProjects"

# Common layout settings to apply
LAYOUT_SETTINGS = {
    # Panel settings
    "workbench.panel.defaultLocation": "bottom",
    "workbench.sideBar.location": "left",
    # Explorer settings
    "explorer.autoReveal": "focusNoScroll",
    "explorer.confirmDelete": False,
    "explorer.confirmDragAndDrop": False,
    # Editor settings
    "workbench.editor.openPositioning": "right",
    "workbench.editor.enablePreview": False,
    "workbench.editor.closeOnFileDelete": True,
    # Editor layout
    "editor.minimap.enabled": True,
    "editor.minimap.maxColumn": 120,
    "editor.lineNumbers": "on",
    # Breadcrumbs
    "breadcrumbs.enabled": True,
    "breadcrumbs.filePath": "on",
    # Activity bar visibility
    "workbench.activityBar.visible": True,
    # Status bar
    "workbench.statusBar.visible": True,
}


def update_workspace_file(project_name: str):
    """Update workspace file with layout settings."""
    workspace_file = PROJECTS_DIR / project_name / f"{project_name}.code-workspace"

    if not workspace_file.exists():
        print(f"⚠️  Workspace file not found: {workspace_file}")
        return False

    # Read existing workspace
    with open(workspace_file, "r", encoding="utf-8") as f:
        workspace = json.load(f)

    # Ensure settings object exists
    if "settings" not in workspace:
        workspace["settings"] = {}

    # Merge layout settings (don't overwrite existing settings)
    updated = False
    for key, value in LAYOUT_SETTINGS.items():
        if key not in workspace["settings"]:
            workspace["settings"][key] = value
            updated = True
            print(f"  ✓ Added: {key}")

    if updated:
        # Write back with proper formatting
        with open(workspace_file, "w", encoding="utf-8") as f:
            json.dump(workspace, f, indent="\t", ensure_ascii=False)
        print(f"✅ Updated {project_name}.code-workspace with layout settings")
        return True
    else:
        print(f"ℹ️  {project_name}.code-workspace already has layout settings")
        return False


def main():
    print("Adding layout settings to workspace files...")
    print("=" * 60)

    projects = ["SecureApp", "QuantFramework"]
    updated_count = 0

    for project in projects:
        print(f"\nProcessing {project}...")
        if update_workspace_file(project):
            updated_count += 1

    print("\n" + "=" * 60)
    print(f"✅ Updated {updated_count} workspace file(s)")
    print("\nNote: These settings provide default layout preferences.")
    print("Actual panel positions and open files are remembered per workspace.")
    print("\nTo apply layout:")
    print("1. Close and reopen the workspace")
    print("2. Manually arrange panels to your preference")
    print("3. Cursor will remember the layout for future sessions")


if __name__ == "__main__":
    main()
