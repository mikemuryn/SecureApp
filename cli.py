#!/usr/bin/env python3
"""
SecureApp Command Line Interface
Provides CLI access to SecureApp functionality
"""

import argparse
import getpass
import sys
from pathlib import Path

from app.auth.authentication import AuthenticationManager
from app.encryption.file_crypto import FileEncryption
from app.models.database import DatabaseManager
from app.utils.audit_logger import AuditLogger
from app.utils.file_manager import FileAccessManager
from config.settings import DATABASE_URL, LOG_FILE  # noqa: F405


def init_managers():
    """Initialize all managers"""
    db_manager = DatabaseManager(DATABASE_URL)
    auth_manager = AuthenticationManager(db_manager)
    audit_logger = AuditLogger(LOG_FILE, db_manager)
    file_manager = FileAccessManager(db_manager, FileEncryption, audit_logger)
    return db_manager, auth_manager, file_manager


def cmd_upload(args):
    """Upload a file"""
    _, auth_manager, file_manager = init_managers()

    # Authenticate
    success, message = auth_manager.authenticate_user(args.username, args.password)
    if not success:
        print(f"❌ Authentication failed: {message}")
        return 1

    file_path = Path(args.file)
    if not file_path.exists():
        print(f"❌ File not found: {file_path}")
        return 1

    success, message = file_manager.upload_file(file_path, args.username, args.password)
    if success:
        print(f"✅ {message}")
        return 0
    else:
        print(f"❌ {message}")
        return 1


def cmd_download(args):
    """Download a file"""
    _, auth_manager, file_manager = init_managers()

    # Authenticate
    success, message = auth_manager.authenticate_user(args.username, args.password)
    if not success:
        print(f"❌ Authentication failed: {message}")
        return 1

    success, temp_path, message = file_manager.download_file(
        args.file_id, args.username, args.password
    )
    if success and temp_path:
        output_path = Path(args.output) if args.output else temp_path
        if output_path != temp_path:
            import shutil

            shutil.move(str(temp_path), str(output_path))
        print(f"✅ File downloaded to: {output_path}")
        return 0
    else:
        print(f"❌ {message}")
        return 1


def cmd_list(args):
    """List files"""
    _, auth_manager, file_manager = init_managers()

    # Authenticate
    success, message = auth_manager.authenticate_user(args.username, args.password)
    if not success:
        print(f"❌ Authentication failed: {message}")
        return 1

    files, total = file_manager.list_user_files(args.username, limit=args.limit)
    if not files:
        print("No files found")
        return 0

    print(f"\n📁 Found {total} file(s)")
    print("-" * 80)
    print(f"{'ID':<6} {'Filename':<30} {'Size':<12} {'Owner':<15} {'Created'}")
    print("-" * 80)

    for file_info in files:
        size_str = f"{file_info['size']:,} bytes"
        created_str = (
            file_info["created_at"].strftime("%Y-%m-%d")
            if file_info.get("created_at")
            else "N/A"
        )
        print(
            f"{file_info['id']:<6} "
            f"{file_info['filename'][:29]:<30} "
            f"{size_str:<12} "
            f"{file_info['owner']:<15} "
            f"{created_str}"
        )

    if total > len(files):
        print(f"\n... showing {len(files)} of {total} files (use --limit to see more)")

    return 0


def cmd_delete(args):
    """Delete a file"""
    _, auth_manager, file_manager = init_managers()

    # Authenticate
    success, message = auth_manager.authenticate_user(args.username, args.password)
    if not success:
        print(f"❌ Authentication failed: {message}")
        return 1

    if not args.yes:
        confirm = input(
            f"Are you sure you want to delete file {args.file_id}? (yes/no): "
        )
        if confirm.lower() != "yes":
            print("Cancelled")
            return 0

    success, message = file_manager.delete_file(args.file_id, args.username)
    if success:
        print(f"✅ {message}")
        return 0
    else:
        print(f"❌ {message}")
        return 1


def cmd_backup(args):
    """Create a backup"""
    _, auth_manager, file_manager = init_managers()

    # Authenticate as admin
    user = auth_manager.get_user_by_username(args.username)
    if not user or user.role != "admin":
        success, message = auth_manager.authenticate_user(args.username, args.password)
        if not success:
            print(f"❌ Authentication failed: {message}")
            return 1

        # Check if admin
        user = auth_manager.get_user_by_username(args.username)
        if not user or user.role != "admin":
            print("❌ Admin privileges required for backup")
            return 1

    backup_path = Path(args.output)
    success, message = file_manager.export_backup(backup_path)
    if success:
        print(f"✅ Backup created: {message}")
        return 0
    else:
        print(f"❌ {message}")
        return 1


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="SecureApp CLI - Secure file management from command line",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Common arguments
    def add_auth_args(p):
        p.add_argument(
            "--username", "-u", required=True, help="Username for authentication"
        )
        p.add_argument(
            "--password",
            "-p",
            help="Password (will prompt if not provided)",
        )

    # Upload command
    upload_parser = subparsers.add_parser("upload", help="Upload a file")
    add_auth_args(upload_parser)
    upload_parser.add_argument("file", help="Path to file to upload")
    upload_parser.set_defaults(func=cmd_upload)

    # Download command
    download_parser = subparsers.add_parser("download", help="Download a file")
    add_auth_args(download_parser)
    download_parser.add_argument("file_id", type=int, help="File ID to download")
    download_parser.add_argument(
        "--output", "-o", help="Output file path (default: original filename)"
    )
    download_parser.set_defaults(func=cmd_download)

    # List command
    list_parser = subparsers.add_parser("list", help="List files")
    add_auth_args(list_parser)
    list_parser.add_argument(
        "--limit", "-l", type=int, default=50, help="Maximum number of files to show"
    )
    list_parser.set_defaults(func=cmd_list)

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a file")
    add_auth_args(delete_parser)
    delete_parser.add_argument("file_id", type=int, help="File ID to delete")
    delete_parser.add_argument(
        "--yes", "-y", action="store_true", help="Skip confirmation prompt"
    )
    delete_parser.set_defaults(func=cmd_delete)

    # Backup command
    backup_parser = subparsers.add_parser(
        "backup", help="Create system backup (admin only)"
    )
    add_auth_args(backup_parser)
    backup_parser.add_argument(
        "--output", "-o", required=True, help="Output directory for backup"
    )
    backup_parser.set_defaults(func=cmd_backup)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Prompt for password if not provided
    if not args.password and hasattr(args, "password"):
        args.password = getpass.getpass("Password: ")

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n❌ Cancelled by user")
        return 1
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
