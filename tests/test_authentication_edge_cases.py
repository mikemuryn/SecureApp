"""
Edge case tests for AuthenticationManager to improve coverage
"""

from datetime import datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from app.auth.authentication import AuthenticationManager
from app.models.database import DatabaseManager, User


def test_authenticate_user_exception_handling(temp_db_file, monkeypatch):
    """Test authenticate_user exception handling path"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database connection failed")

    monkeypatch.setattr(db, "get_session", raise_exception)

    ok, msg = auth.authenticate_user("testuser", "password")
    assert ok is False
    assert "error" in msg.lower() or "fail" in msg.lower()


def test_authenticate_user_with_expired_lockout(temp_db_file):
    """Test authenticate_user with expired lockout"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")

    # Manually set locked_until to past date
    session = db.get_session()
    try:
        user = session.query(User).filter(User.username == "testuser").first()
        user.locked_until = datetime.utcnow() - timedelta(hours=1)  # Expired
        user.failed_attempts = 5
        session.commit()
    finally:
        db.close_session(session)

    # Should be able to login now (lockout expired)
    ok, msg = auth.authenticate_user("testuser", "StrongPassword123!")
    assert ok is True


def test_create_user_exception_handling(temp_db_file, monkeypatch):
    """Test create_user exception handling"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    result = auth.create_user(
        "testuser", "test@example.com", "StrongPassword123!", "user"
    )
    assert result is False


def test_change_password_exception_handling(temp_db_file, monkeypatch):
    """Test change_password exception handling"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    ok, msg = auth.change_password("testuser", "StrongPassword123!", "NewPass123!")
    assert ok is False
    assert "failed" in msg.lower() or "error" in msg.lower()


def test_get_user_by_username_not_found(temp_db_file):
    """Test get_user_by_username when user doesn't exist"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    user = auth.get_user_by_username("nonexistent")
    assert user is None


def test_get_user_by_username_exception_handling(temp_db_file, monkeypatch):
    """Test get_user_by_username exception handling"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    # Mock get_session to raise exception, but it's caught in finally
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    # Exception is raised but not caught in get_user_by_username
    # So it will propagate - test that it raises
    with pytest.raises(RuntimeError):
        auth.get_user_by_username("testuser")


def test_set_recovery_question_exception_handling(temp_db_file, monkeypatch):
    """Test set_recovery_question exception handling"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    ok, msg = auth.set_recovery_question("testuser", "Question?", "Answer")
    assert ok is False
    assert "failed" in msg.lower()


def test_request_password_reset_exception_handling(temp_db_file, monkeypatch):
    """Test request_password_reset exception handling"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")
    auth.set_recovery_question("testuser", "Question?", "Answer")

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    ok, msg, token = auth.request_password_reset("testuser", "Answer")
    assert ok is False
    assert token == ""


def test_reset_password_exception_handling(temp_db_file, monkeypatch):
    """Test reset_password exception handling"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")
    auth.set_recovery_question("testuser", "Question?", "Answer")

    success, _, token = auth.request_password_reset("testuser", "Answer")
    assert success is True

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    ok, msg = auth.reset_password("testuser", token, "NewPass123!")
    assert ok is False
    assert "failed" in msg.lower()


def test_admin_reset_password_exception_handling(temp_db_file, monkeypatch):
    """Test admin_reset_password exception handling"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("admin", "admin@example.com", "AdminPass123!", "admin")
    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    ok, msg = auth.admin_reset_password("admin", "testuser", "NewPass123!")
    assert ok is False
    assert "failed" in msg.lower()


def test_authenticate_user_locked_until_message(temp_db_file):
    """Test authenticate_user returns proper lockout message"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")

    # Lock the account
    session = db.get_session()
    try:
        user = session.query(User).filter(User.username == "testuser").first()
        lockout_time = datetime.utcnow() + timedelta(minutes=15)
        user.locked_until = lockout_time
        session.commit()
    finally:
        db.close_session(session)

    ok, msg = auth.authenticate_user("testuser", "StrongPassword123!")
    assert ok is False
    assert "locked" in msg.lower()
    assert str(lockout_time) in msg or "locked until" in msg.lower()


def test_change_password_with_wrong_old_password(temp_db_file):
    """Test change_password with wrong old password"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")

    ok, msg = auth.change_password("testuser", "WrongPassword!", "NewPass123!")
    assert ok is False
    assert "incorrect" in msg.lower() or "invalid" in msg.lower()
