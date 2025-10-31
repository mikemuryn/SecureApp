# SecureApp User Guide

**Version:** 1.0
**Last Updated:** October 2025

Welcome to SecureApp! This guide will help you use SecureApp to securely manage your confidential files.

---

## 📋 Table of Contents

1. [Getting Started](#getting-started)
2. [User Interface Overview](#user-interface-overview)
3. [Managing Files](#managing-files)
4. [File Security Features](#file-security-features)
5. [User Management](#user-management)
6. [Advanced Features](#advanced-features)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)

---

## 🚀 Getting Started

### First Launch

1. **Run SecureApp**: Launch the application by running `python main.py`

2. **Default Login**:
    - **Username:** `admin`
    - **Password:** `Admin123!`
    - ⚠️ **Important:** Change this password immediately after first login!

3. **Initial Setup**:
    - The application will automatically create necessary directories
    - Database is initialized on first run
    - You can start uploading files immediately

### Changing Your Password

1. Log in to SecureApp
2. Navigate to the **Settings** tab
3. Click **"Change Password"**
4. Enter your current password and new password
5. Click **"Update Password"**

### Setting Up Password Recovery

1. Go to the **Settings** tab
2. Scroll to **"Security Questions"**
3. Select a security question
4. Enter your answer
5. Click **"Save Recovery Question"**

This allows you to recover your password if you forget it.

---

## 🖥️ User Interface Overview

### Main Window

SecureApp has a modern, tabbed interface:

- **File Management Tab**: Upload, download, and manage your files
- **User Management Tab** (Admin only): Create and manage users
- **Audit Log Tab** (Admin only): View security audit logs
- **Settings Tab**: Change password, theme, and recovery questions

### Dark Mode

SecureApp defaults to **dark mode** for a comfortable viewing experience. You can toggle between dark and light themes using the **☀️/🌙** button in the top-right corner.

### Keyboard Shortcuts

- `Ctrl+U` - Upload file
- `Ctrl+D` - Download selected file
- `Ctrl+F` - Focus search box
- `Ctrl+Q` - Quit application
- `F5` - Refresh file list
- `Delete` - Delete selected file (with confirmation)
- `Esc` - Close dialogs or clear selection

---

## 📁 Managing Files

### Uploading Files

**Method 1: Using the Button**

1. Click **"Select File to Upload"**
2. Choose your file from the file browser
3. Enter your password for encryption
4. Click **"Upload"**

**Method 2: Drag and Drop**

1. Drag a file from your file explorer
2. Drop it onto the upload area in SecureApp
3. Enter your password
4. Click **"Upload"**

**Batch Upload:**

- You can select multiple files when using the file browser
- Each file will be encrypted individually with your password

### Downloading Files

1. Select a file from the file list
2. Click **"Download Selected"**
3. Enter your password for decryption
4. Choose where to save the file
5. The file will be decrypted and saved

### Deleting Files

1. Select a file from the file list
2. Click **"Delete Selected"**
3. Confirm the deletion
4. ⚠️ **Warning:** Deleted files cannot be recovered!

### Searching Files

1. Use the search box at the top of the file list
2. Type part of the filename
3. The list filters automatically as you type
4. Click **"Clear"** to reset the search

---

## 🔒 File Security Features

### File Encryption

- All files are encrypted using **AES-256** encryption
- Files are encrypted with your password using PBKDF2 key derivation
- Each file is encrypted independently
- Encrypted files are stored in `data/encrypted/`

### File Versioning

SecureApp automatically creates versions when you upload a file with the same name:

- Previous versions are preserved
- You can view version history for any file
- Only the latest version appears in the main file list
- Click **"View Versions"** to see version history

### File Tagging

Organize your files with tags:

1. Select a file
2. Click **"Manage Tags"**
3. Add tags with custom colors
4. Use tags to categorize and find files quickly

### File Sharing

Share files with other users:

1. Select a file you own
2. Click **"Share File"**
3. Enter the username of the person to share with
4. Choose permission level:
    - **Read**: Can only download the file
    - **Write**: Can download and create new versions
    - **Admin**: Full control (use with caution)
5. Click **"Share"**

To revoke sharing:

1. Select the shared file
2. Click **"Share File"**
3. Click **"Revoke Access"** for the user

---

## 👥 User Management (Admin Only)

### Creating Users

1. Navigate to **"User Management"** tab
2. Fill in user details:
    - **Username**: Must be unique
    - **Email**: User's email address
    - **Password**: Strong password (min 8 chars, uppercase, lowercase, numbers, special chars)
    - **Role**: Choose from:
        - **user**: Regular user (default)
        - **admin**: Full access to all features
        - **readonly**: Can only view files, no upload/download
3. Click **"Create User"**

### User Roles

- **Admin**: Full access to all files, user management, audit logs
- **User**: Can upload, download, and manage their own files
- **Readonly**: Can only view files (no upload/download)

---

## ⚙️ Advanced Features

### Export File List

Export a CSV list of your files:

1. In **File Management** tab
2. Click **"Export File List"**
3. Choose save location
4. A CSV file with file details will be created

### System Backup (Admin Only)

Create a full system backup:

1. Click **"Create Backup"** in File Management tab
2. Choose backup location
3. The backup includes:
    - All encrypted files
    - Database metadata
    - User information
    - File permissions and tags

### Audit Logs (Admin Only)

View security audit logs:

1. Go to **"Audit Log"** tab
2. View recent security events:
    - Login attempts
    - File access
    - User creation
    - Password changes
3. Click **"Refresh Log"** to update

---

## 🛠️ Command Line Interface (CLI)

SecureApp also provides a command-line interface for automation and scripting.

### Installing CLI

The CLI is included with SecureApp. Make it executable:

```bash
chmod +x cli.py
```

### Basic Usage

**List files:**

```bash
python cli.py list --username youruser --limit 50
```

**Upload a file:**

```bash
python cli.py upload --username youruser --file /path/to/file.txt
```

**Download a file:**

```bash
python cli.py download --username youruser --file-id 123 --output /path/to/save
```

**Delete a file:**

```bash
python cli.py delete --username youruser --file-id 123 --yes
```

**Create backup (admin):**

```bash
python cli.py backup --username admin --output /backup/path
```

### CLI Help

Get help for any command:

```bash
python cli.py --help
python cli.py upload --help
```

---

## ❓ Troubleshooting

### "Authentication failed"

- Check your username and password
- Ensure caps lock is off
- Contact admin if account is locked (too many failed attempts)

### "File not found"

- The file may have been deleted
- Check you have permission to access the file
- Verify the file ID is correct (CLI)

### "Access denied"

- You don't have permission for this file
- Contact the file owner to share it with you
- Admin users have access to all files

### Application won't start

- Check Python version (3.8+ required)
- Verify all dependencies are installed: `pip install -r requirements.txt`
- Check logs in `logs/SecureApp.log`

### Files upload slowly

- Large files take longer to encrypt
- Check available disk space
- Ensure no other processes are using the database

---

## 💡 Best Practices

### Security

1. **Use Strong Passwords**
    - Minimum 8 characters
    - Mix of uppercase, lowercase, numbers, and special characters
    - Don't reuse passwords

2. **Change Default Password**
    - Change the admin password immediately
    - Regularly update passwords

3. **Limit Admin Access**
    - Only grant admin role to trusted users
    - Regular users should have "user" role

4. **Regular Backups**
    - Create backups regularly
    - Store backups in a secure location
    - Test backup restoration

5. **Audit Logs**
    - Review audit logs regularly
    - Look for suspicious activity
    - Monitor failed login attempts

### File Management

1. **Use Tags**
    - Tag files for easy organization
    - Use consistent tagging conventions
    - Color-code by category

2. **Version Control**
    - Upload new versions instead of deleting old files
    - Add notes when creating versions
    - Review version history periodically

3. **File Sharing**
    - Share only with trusted users
    - Use "Read" permission when possible
    - Revoke access when no longer needed

4. **Search and Filter**
    - Use search to find files quickly
    - Clear search to see all files
    - Use tags in combination with search

### Performance

1. **Large File Sets**
    - Use search to filter files
    - The UI limits display to 1000 files for performance
    - Use CLI for bulk operations

2. **Regular Cleanup**
    - Delete old/unused files
    - Archive old versions if needed
    - Keep database size manageable

---

## 📞 Support

### Getting Help

1. Check this user guide
2. Review the troubleshooting section
3. Check logs in `logs/SecureApp.log`
4. Contact your system administrator

### Reporting Issues

When reporting issues, please provide:

- SecureApp version
- Operating system
- Error messages from logs
- Steps to reproduce the issue

---

## 📝 License

See LICENSE file for details.

---

**Thank you for using SecureApp!** 🔒
