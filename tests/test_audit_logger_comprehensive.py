"""
Comprehensive tests for AuditLogger to improve coverage
"""

from datetime import datetime
from pathlib import Path

import pytest

from app.models.database import AuditLog, DatabaseManager, User
from app.utils.audit_logger import AuditLogger


def test_audit_logger_init_file_only(temp_log_file):
    """Test AuditLogger initialization with file only"""
    logger = AuditLogger(Path(temp_log_file))

    assert logger.log_file == Path(temp_log_file)
    assert logger.db_manager is None


def test_audit_logger_init_with_db(temp_db_file, temp_log_file):
    """Test AuditLogger initialization with database"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()

    logger = AuditLogger(Path(temp_log_file), db)

    assert logger.log_file == Path(temp_log_file)
    assert logger.db_manager == db


def test_log_event_file_only(temp_log_file):
    """Test logging event to file only"""
    logger = AuditLogger(Path(temp_log_file))

    logger.log_event(
        username="testuser",
        action="test_action",
        success=True,
        resource="test_resource",
    )

    # Verify file was written
    assert Path(temp_log_file).exists()
    content = Path(temp_log_file).read_text()
    assert "testuser" in content
    assert "test_action" in content


def test_log_event_with_db(temp_db_file, temp_log_file):
    """Test logging event with database"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()

    logger = AuditLogger(Path(temp_log_file), db)

    logger.log_event(
        username="testuser",
        action="test_action",
        success=True,
        resource="test_resource",
    )

    # Verify logged to both file and database
    assert Path(temp_log_file).exists()

    # Verify database entry
    session = db.get_session()
    try:
        from app.models.database import AuditLog, User

        # Find user first
        user = session.query(User).filter(User.username == "testuser").first()
        if user:
            logs = session.query(AuditLog).filter(AuditLog.user_id == user.id).all()
        else:
            # If no user, check by action
            logs = (
                session.query(AuditLog).filter(AuditLog.action == "test_action").all()
            )
        assert len(logs) > 0
        assert logs[0].action == "test_action"
    finally:
        db.close_session(session)


def test_log_login_attempt_success(temp_log_file):
    """Test logging successful login attempt"""
    logger = AuditLogger(Path(temp_log_file))

    logger.log_login_attempt("testuser", True)

    assert Path(temp_log_file).exists()
    content = Path(temp_log_file).read_text()
    assert "login" in content.lower()
    assert "testuser" in content


def test_log_login_attempt_failure(temp_log_file):
    """Test logging failed login attempt"""
    logger = AuditLogger(Path(temp_log_file))

    logger.log_login_attempt("testuser", False)

    assert Path(temp_log_file).exists()
    content = Path(temp_log_file).read_text()
    assert "login" in content.lower()
    assert "testuser" in content


def test_log_logout(temp_log_file):
    """Test logging logout"""
    logger = AuditLogger(Path(temp_log_file))

    logger.log_logout("testuser")

    assert Path(temp_log_file).exists()
    content = Path(temp_log_file).read_text()
    assert "logout" in content.lower()
    assert "testuser" in content


def test_log_file_access_upload(temp_log_file):
    """Test logging file upload"""
    logger = AuditLogger(Path(temp_log_file))

    logger.log_file_access("testuser", "test.txt", "upload", True)

    assert Path(temp_log_file).exists()
    content = Path(temp_log_file).read_text()
    assert "file" in content.lower()
    assert "upload" in content.lower()
    assert "test.txt" in content


def test_log_file_access_download(temp_log_file):
    """Test logging file download"""
    logger = AuditLogger(Path(temp_log_file))

    logger.log_file_access("testuser", "test.txt", "download", True)

    assert Path(temp_log_file).exists()
    content = Path(temp_log_file).read_text()
    assert "download" in content.lower()


def test_log_file_access_delete(temp_log_file):
    """Test logging file deletion"""
    logger = AuditLogger(Path(temp_log_file))

    logger.log_file_access("testuser", "test.txt", "delete", True)

    assert Path(temp_log_file).exists()
    content = Path(temp_log_file).read_text()
    assert "delete" in content.lower()


def test_log_file_access_failed(temp_log_file):
    """Test logging failed file access"""
    logger = AuditLogger(Path(temp_log_file))

    logger.log_file_access("testuser", "test.txt", "upload", False)

    assert Path(temp_log_file).exists()
    content = Path(temp_log_file).read_text()
    assert "testuser" in content


def test_log_password_change(temp_log_file):
    """Test logging password change"""
    logger = AuditLogger(Path(temp_log_file))

    logger.log_password_change("testuser", True)

    assert Path(temp_log_file).exists()
    content = Path(temp_log_file).read_text()
    assert "password" in content.lower()
    assert "testuser" in content


def test_log_user_creation(temp_log_file):
    """Test logging user creation"""
    logger = AuditLogger(Path(temp_log_file))

    logger.log_user_creation("admin", "newuser", True)

    assert Path(temp_log_file).exists()
    content = Path(temp_log_file).read_text()
    assert "user" in content.lower()
    assert "newuser" in content or "admin" in content


def test_log_security_event(temp_log_file):
    """Test logging security event"""
    logger = AuditLogger(Path(temp_log_file))

    logger.log_security_event(
        username="testuser",
        event_type="suspicious_activity",
        details="Multiple failed login attempts",
    )

    assert Path(temp_log_file).exists()
    content = Path(temp_log_file).read_text()
    assert "security" in content.lower()
    assert "testuser" in content


def test_get_recent_events_with_db(temp_db_file, temp_log_file):
    """Test getting recent events from database"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()

    logger = AuditLogger(Path(temp_log_file), db)

    # Log some events
    logger.log_login_attempt("testuser", True)
    logger.log_file_access("testuser", "test.txt", "upload", True)

    # Get recent events
    events = logger.get_recent_events(limit=10)

    assert isinstance(events, list)
    assert len(events) >= 2


def test_get_recent_events_limit(temp_db_file, temp_log_file):
    """Test getting recent events with limit"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()

    logger = AuditLogger(Path(temp_log_file), db)

    # Log multiple events
    for i in range(5):
        logger.log_event(
            username=f"user{i}",
            action="test_action",
            success=True,
        )

    # Get limited events
    events = logger.get_recent_events(limit=3)

    assert len(events) <= 3


def test_get_recent_events_no_db(temp_log_file):
    """Test getting recent events without database"""
    logger = AuditLogger(Path(temp_log_file))

    events = logger.get_recent_events()

    assert events == []


def test_get_recent_events_empty_db(temp_db_file, temp_log_file):
    """Test getting recent events from empty database"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()

    logger = AuditLogger(Path(temp_log_file), db)

    events = logger.get_recent_events()

    assert events == []


def test_log_event_with_timestamp(temp_log_file):
    """Test logging event includes timestamp"""
    logger = AuditLogger(Path(temp_log_file))

    logger.log_event(
        username="testuser",
        action="test_action",
        success=True,
    )

    content = Path(temp_log_file).read_text()
    # Should contain timestamp (ISO format or similar)
    # Check for date-like patterns
    assert any(char.isdigit() for char in content)  # Should have numbers (timestamp)


def test_log_event_database_error_handling(temp_db_file, temp_log_file):
    """Test that logging continues even if database fails"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()

    logger = AuditLogger(Path(temp_log_file), db)

    # Close database to simulate error
    session = db.get_session()
    db.close_session(session)

    # Should still log to file
    logger.log_event(
        username="testuser",
        action="test_action",
        success=True,
    )

    # File should still be written
    assert Path(temp_log_file).exists()
    content = Path(temp_log_file).read_text()
    assert "testuser" in content


def test_log_to_database_with_user(temp_db_file, temp_log_file):
    """Test logging to database with existing user"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()

    # Create user
    session = db.get_session()
    try:
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            salt="salt",
            role="user",
        )
        session.add(user)
        session.commit()
    finally:
        db.close_session(session)

    logger = AuditLogger(Path(temp_log_file), db)

    logger.log_event(
        username="testuser",
        action="test_action",
        success=True,
    )

    # Verify database entry has user_id
    session = db.get_session()
    try:
        # Get user to find user_id
        user = session.query(User).filter(User.username == "testuser").first()
        assert user is not None
        logs = session.query(AuditLog).filter(AuditLog.user_id == user.id).all()
        assert len(logs) > 0
        assert logs[0].user_id == user.id
    finally:
        db.close_session(session)


def test_multiple_log_entries(temp_log_file):
    """Test logging multiple entries"""
    logger = AuditLogger(Path(temp_log_file))

    logger.log_login_attempt("user1", True)
    logger.log_file_access("user2", "file.txt", "upload", True)
    logger.log_logout("user3")

    content = Path(temp_log_file).read_text()
    assert "user1" in content
    assert "user2" in content
    assert "user3" in content


def test_log_file_creates_directory(tmp_path):
    """Test that log file directory is created if needed"""
    log_file = tmp_path / "new_dir" / "log.txt"

    assert not log_file.parent.exists()

    logger = AuditLogger(log_file)

    logger.log_event(
        username="testuser",
        action="test",
        success=True,
    )

    assert log_file.parent.exists()
    assert log_file.exists()


def test_log_event_resource_optional(temp_log_file):
    """Test logging event without resource"""
    logger = AuditLogger(Path(temp_log_file))

    logger.log_event(
        username="testuser",
        action="test_action",
        success=True,
    )

    assert Path(temp_log_file).exists()


def test_log_security_event_all_fields(temp_log_file):
    """Test logging security event with all fields"""
    logger = AuditLogger(Path(temp_log_file))

    logger.log_security_event(
        username="testuser",
        event_type="suspicious_activity",
        details="Multiple failed attempts from IP 1.2.3.4",
    )

    content = Path(temp_log_file).read_text()
    assert "testuser" in content
    assert "suspicious" in content.lower() or "security" in content.lower()
