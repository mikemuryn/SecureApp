# Test fixtures and utilities for SecureApp

import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from app.models.database import DatabaseManager, SecureFile, User


@pytest.fixture
def temp_directory():
    """Create a temporary directory for testing"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)


@pytest.fixture
def temp_db_file():
    """Create a temporary database file"""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    yield f"sqlite:///{db_path}"
    os.unlink(db_path)


@pytest.fixture
def temp_log_file():
    """Create a temporary log file"""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
        tmp_path = tmp.name
    yield tmp_path
    os.unlink(tmp_path)


@pytest.fixture
def sample_user_data():
    """Sample user data for testing"""
    return {
        "username": "testuser",
        "email": "test@example.com",
        "password": "TestPassword123!",
        "role": "user",
    }


@pytest.fixture
def sample_admin_data():
    """Sample admin user data for testing"""
    return {
        "username": "admin",
        "email": "admin@example.com",
        "password": "AdminPassword123!",
        "role": "admin",
    }


@pytest.fixture
def mock_user():
    """Create a mock user object"""
    user = Mock(spec=User)
    user.id = 1
    user.username = "testuser"
    user.email = "test@example.com"
    user.role = "user"
    user.is_active = True
    user.created_at = datetime.utcnow()
    user.last_login = None
    user.failed_attempts = 0
    user.locked_until = None
    return user


@pytest.fixture
def mock_admin_user():
    """Create a mock admin user object"""
    user = Mock(spec=User)
    user.id = 2
    user.username = "admin"
    user.email = "admin@example.com"
    user.role = "admin"
    user.is_active = True
    user.created_at = datetime.utcnow()
    user.last_login = None
    user.failed_attempts = 0
    user.locked_until = None
    return user


@pytest.fixture
def mock_secure_file():
    """Create a mock secure file object"""
    file_obj = Mock(spec=SecureFile)
    file_obj.id = 1
    file_obj.filename = "test_file.txt"
    file_obj.original_path = "/path/to/original/test_file.txt"
    file_obj.encrypted_path = "/path/to/encrypted/test_file.txt.enc"
    file_obj.file_hash = "abcd1234efgh5678"
    file_obj.file_size = 1024
    file_obj.owner_id = 1
    file_obj.created_at = datetime.utcnow()
    file_obj.last_accessed = None
    file_obj.access_count = 0
    file_obj.is_encrypted = True
    return file_obj


@pytest.fixture
def mock_session():
    """Create a mock session object"""
    session = Mock()
    session.session_id = "test_session_123"
    session.user_id = "testuser"
    session.created_at = datetime.utcnow()
    session.expires_at = datetime.utcnow() + timedelta(hours=1)
    session.is_active = True
    return session


@pytest.fixture
def sample_file_content():
    """Sample file content for testing"""
    return (
        "This is sample file content for testing "
        "encryption and decryption functionality."
    )


@pytest.fixture
def sample_large_file_content():
    """Sample large file content for performance testing"""
    return "Sample content " * 10000  # ~150KB of content


@pytest.fixture
def encryption_password():
    """Standard encryption password for testing"""
    return "TestEncryptionPassword123!"


@pytest.fixture
def weak_passwords():
    """List of weak passwords for testing"""
    return [
        "123456",
        "password",
        "abc",
        "test",
        "qwerty",
        "1234567890",
        "letmein",
        "welcome",
    ]


@pytest.fixture
def strong_passwords():
    """List of strong passwords for testing"""
    return [
        "StrongPassword123!",
        "MySecure@Pass2024",
        "Complex#Pass99$",
        "Super$ecure123!",
        "Test@Pass456#",
    ]


@pytest.fixture
def invalid_emails():
    """List of invalid email addresses for testing"""
    return [
        "invalid-email",
        "@example.com",
        "test@",
        "test.example.com",
        "test@.com",
        "test@example.",
        "",
    ]


@pytest.fixture
def valid_emails():
    """List of valid email addresses for testing"""
    return [
        "test@example.com",
        "user.name@domain.co.uk",
        "admin+test@company.org",
        "test123@subdomain.example.net",
    ]


@pytest.fixture
def mock_file_paths():
    """Mock file paths for testing"""
    return {
        "original": "/tmp/test_file.txt",
        "encrypted": "/tmp/test_file.txt.enc",
        "decrypted": "/tmp/test_file_decrypted.txt",
        "temp": "/tmp/temp_file.txt",
    }


@pytest.fixture
def audit_events():
    """Sample audit events for testing"""
    return [
        {
            "action": "LOGIN",
            "username": "testuser",
            "resource": "authentication",
            "success": True,
            "timestamp": datetime.utcnow(),
        },
        {
            "action": "FILE_UPLOAD",
            "username": "testuser",
            "resource": "test_file.txt",
            "success": True,
            "timestamp": datetime.utcnow(),
        },
        {
            "action": "FILE_DOWNLOAD",
            "username": "testuser",
            "resource": "test_file.txt",
            "success": True,
            "timestamp": datetime.utcnow(),
        },
    ]


@pytest.fixture
def mock_database_session():
    """Create a mock database session"""
    session = Mock()
    session.query.return_value.filter.return_value.first.return_value = None
    session.query.return_value.filter.return_value.all.return_value = []
    session.add = Mock()
    session.commit = Mock()
    session.rollback = Mock()
    session.close = Mock()
    return session


@pytest.fixture
def mock_database_manager():
    """Create a mock database manager"""
    db_manager = Mock(spec=DatabaseManager)
    db_manager.get_session.return_value = mock_database_session()
    db_manager.close_session = Mock()
    db_manager.create_tables = Mock()
    return db_manager


# Performance testing fixtures
@pytest.fixture
def performance_test_files():
    """Create files of various sizes for performance testing"""
    files = {}
    sizes = [1024, 10240, 102400, 1048576]  # 1KB, 10KB, 100KB, 1MB

    for size in sizes:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            content = "A" * size
            tmp.write(content)
            files[f"{size}_bytes"] = tmp.name

    yield files

    # Cleanup
    for file_path in files.values():
        os.unlink(file_path)


# Security testing fixtures
@pytest.fixture
def malicious_filenames():
    """List of potentially malicious filenames for testing"""
    return [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "test<script>alert('xss')</script>.txt",
        "test'; DROP TABLE users; --.txt",
        "test\x00null.txt",
        "test\nnewline.txt",
        "test\ttab.txt",
    ]


@pytest.fixture
def sql_injection_attempts():
    """List of SQL injection attempts for testing"""
    return [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "admin'--",
        "admin'/*",
        "' UNION SELECT * FROM users--",
        "1' OR '1'='1' --",
    ]
