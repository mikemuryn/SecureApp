# SecureApp Documentation

## Overview

SecureApp is a desktop application for secure management of confidential files with robust authentication and encryption capabilities.

## Features

- **Strong Authentication**: Password-based login with account lockout protection
- **File Encryption**: AES-256 encryption for all confidential files
- **Session Management**: Secure session handling with automatic timeouts
- **Audit Logging**: Comprehensive logging of all user activities
- **Role-Based Access**: Admin, User, and Read-only permission levels
- **Secure Storage**: Encrypted local database for user and file management

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/mikemuryn/SecureApp.git
   cd SecureApp
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python main.py
   ```

### Docker Installation

1. Build the Docker image:
   ```bash
   docker build -t secureapp .
   ```

2. Run with Docker Compose:
   ```bash
   docker-compose up -d
   ```

## Usage

### Default Login

- **Username**: `admin`
- **Password**: `Admin123!`
- **Role**: Administrator

**⚠️ Important**: Change the default admin password immediately after first login!

### File Management

1. **Upload Files**: Click "Upload File" to encrypt and store files
2. **Download Files**: Select a file and click "Download" to decrypt and save
3. **Delete Files**: Select a file and click "Delete" to remove from storage

### User Management (Admin Only)

1. **Create Users**: Add new users with different roles
2. **View Audit Logs**: Monitor all user activities
3. **Manage Permissions**: Control file access levels

## Security Features

### Authentication
- Password strength validation
- Account lockout after failed attempts
- Session timeout protection
- Secure password hashing with bcrypt

### Encryption
- AES-256 encryption for all files
- Unique encryption keys per file
- Secure key derivation using PBKDF2

### Audit Trail
- Complete activity logging
- User action tracking
- Security event monitoring
- Compliance reporting

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test categories
pytest -m unit
pytest -m integration
pytest -m security
```

### Code Quality

```bash
# Format code
black .

# Lint code
flake8 .

# Type checking
mypy app/
```

### Docker Development

```bash
# Build development image
docker build -t secureapp-dev .

# Run with development settings
docker run -v $(pwd):/app secureapp-dev
```

## Configuration

### Environment Variables

- `DATABASE_URL`: Database connection string
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `SESSION_TIMEOUT`: Session timeout in seconds
- `MAX_LOGIN_ATTEMPTS`: Maximum failed login attempts

### Settings File

Edit `config/settings.py` to modify:
- Password requirements
- File size limits
- Session timeouts
- Encryption settings

## Troubleshooting

### Common Issues

1. **ModuleNotFoundError**: Install missing dependencies
   ```bash
   pip install -r requirements.txt
   ```

2. **Database Errors**: Check file permissions and disk space

3. **Encryption Issues**: Verify password strength and file integrity

### Log Files

- **Application Log**: `logs/SecureApp.log`
- **Audit Log**: Database audit_logs table
- **Error Logs**: Check console output

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security

For security issues, please email security@example.com instead of using the issue tracker.

## Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the troubleshooting guide
