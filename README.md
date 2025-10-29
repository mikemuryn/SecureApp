# SecureApp

A standalone desktop application for secure management of confidential trading algorithms and project files with robust authentication and encryption.

## 🔐 Security Features

- **Strong Authentication**: Password-based login with account lockout protection
- **File Encryption**: AES-256 encryption for all confidential files
- **Session Management**: Secure session handling with automatic timeouts
- **Audit Logging**: Comprehensive logging of all user activities
- **Role-Based Access**: Admin, User, and Read-only permission levels
- **Secure Storage**: Encrypted local database for user and file management

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone or download the application**:
   ```bash
   cd SecureApp
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python main.py
   ```

### Default Login

- **Username**: `admin`
- **Password**: `Admin123!`
- **Role**: Administrator

**⚠️ Important**: Change the default admin password immediately after first login!

## 📁 Project Structure

```
SecureApp/
├── app/
│   ├── auth/           # Authentication and session management
│   ├── encryption/     # File encryption/decryption
│   ├── models/         # Database models
│   ├── utils/          # Utilities and audit logging
│   └── views/          # UI components (future)
├── config/
│   └── settings.py     # Application configuration
├── data/
│   ├── encrypted/      # Encrypted files storage
│   └── database/       # SQLite database
├── logs/               # Audit logs
├── temp/               # Temporary files (auto-cleaned)
├── main.py            # Application entry point
├── requirements.txt   # Python dependencies
└── README.md         # This file
```

## 🔧 Features

### File Management
- **Upload**: Encrypt and store confidential files
- **Download**: Decrypt and access files with password
- **Delete**: Remove files (owner or admin only)
- **List**: View all accessible files with metadata

### User Management (Admin Only)
- **Create Users**: Add new users with different roles
- **Role Assignment**: Admin, User, or Read-only permissions
- **Password Management**: Strong password requirements

### Security Monitoring (Admin Only)
- **Audit Logs**: View all user activities and security events
- **Failed Login Tracking**: Monitor authentication attempts
- **File Access Logging**: Track all file operations

## 🛡️ Security Implementation

### Encryption
- **Algorithm**: AES-256 encryption
- **Key Derivation**: PBKDF2 with 100,000 iterations
- **Salt**: Random 16-byte salt per file
- **Password**: User password required for encryption/decryption

### Authentication
- **Password Hashing**: bcrypt with salt
- **Session Management**: Secure tokens with timeout
- **Account Lockout**: 5 failed attempts = 15-minute lockout
- **Password Requirements**: 8+ chars, mixed case, numbers, special chars

### Database Security
- **SQLite**: Local encrypted database
- **User Isolation**: Users can only access their own files
- **Admin Override**: Administrators have full access
- **Audit Trail**: All operations logged with timestamps

## ⚙️ Configuration

Edit `config/settings.py` to customize:

- **Session timeout** (default: 30 minutes)
- **File size limits** (default: 100MB)
- **Password requirements**
- **Logging levels**
- **Database location**

## 🔍 Usage Examples

### Uploading a File
1. Login to the application
2. Go to "File Management" tab
3. Click "Select File to Upload"
4. Choose your confidential file
5. Enter your password for encryption
6. File is encrypted and stored securely

### Downloading a File
1. Select a file from the list
2. Click "Download Selected"
3. Enter your password for decryption
4. Choose save location
5. File is decrypted and saved

### Creating Users (Admin)
1. Login as admin
2. Go to "User Management" tab
3. Fill in user details
4. Select role (user/admin/readonly)
5. Click "Create User"

## 🚨 Security Best Practices

1. **Change Default Password**: Immediately change admin password
2. **Strong Passwords**: Use complex passwords for all accounts
3. **Regular Backups**: Backup the `data/` directory regularly
4. **Secure Environment**: Run on trusted, secure systems only
5. **Monitor Logs**: Regularly check audit logs for suspicious activity

## 🐛 Troubleshooting

### Common Issues

**"Database initialization failed"**
- Ensure write permissions in the application directory
- Check if SQLite is properly installed

**"Login failed"**
- Verify username and password
- Check if account is locked (wait 15 minutes)
- Ensure caps lock is off

**"File upload failed"**
- Check file size (max 100MB)
- Ensure sufficient disk space
- Verify file permissions

### Log Files

- **Application Log**: `logs/SecureApp.log`
- **Audit Log**: Database audit_logs table
- **Error Logs**: Check console output

## 📝 License

This application is provided as-is for educational and development purposes. Use at your own risk.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## ⚠️ Disclaimer

This software is provided for educational purposes only. The authors are not responsible for any data loss or security breaches. Always maintain proper backups and follow security best practices.
