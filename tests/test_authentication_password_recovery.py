"""
Tests for Authentication Password Recovery features
"""

from datetime import datetime, timedelta

import pytest

from app.auth.authentication import AuthenticationManager
from app.models.database import DatabaseManager, User


def test_set_recovery_question_success(temp_db_file):
    """Test successfully setting recovery question"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")

    success, message = auth.set_recovery_question(
        "testuser", "What is your pet's name?", "Fluffy"
    )

    assert success is True
    assert "successfully" in message.lower()

    # Verify question is saved
    user = auth.get_user_by_username("testuser")
    assert user.recovery_question == "What is your pet's name?"
    assert user.recovery_answer_hash is not None


def test_set_recovery_question_user_not_found(temp_db_file):
    """Test setting recovery question for non-existent user"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    success, message = auth.set_recovery_question("nonexistent", "Question?", "Answer")

    assert success is False
    assert "not found" in message.lower()


def test_set_recovery_question_answer_case_insensitive(temp_db_file):
    """Test that recovery answer is case-insensitive"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")

    # Set with lowercase
    auth.set_recovery_question("testuser", "Question?", "fluffy")

    # Request reset with uppercase should work
    success, msg, token = auth.request_password_reset("testuser", "FLUFFY")
    assert success is True
    assert token is not None


def test_request_password_reset_success(temp_db_file):
    """Test successful password reset request"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")
    auth.set_recovery_question("testuser", "What is your pet's name?", "Fluffy")

    success, message, token = auth.request_password_reset("testuser", "Fluffy")

    assert success is True
    assert "token" in message.lower()
    assert token is not None
    assert len(token) > 0

    # Verify token is saved
    user = auth.get_user_by_username("testuser")
    assert user.password_reset_token == token
    assert user.password_reset_expires is not None
    assert user.password_reset_expires > datetime.utcnow()


def test_request_password_reset_user_not_found(temp_db_file):
    """Test password reset request for non-existent user"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    success, message, token = auth.request_password_reset("nonexistent", "Answer")

    assert success is False
    assert "not found" in message.lower()
    assert token == ""


def test_request_password_reset_no_recovery_question(temp_db_file):
    """Test password reset request when recovery question not set"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")

    success, message, token = auth.request_password_reset("testuser", "Answer")

    assert success is False
    assert "not set" in message.lower()
    assert token == ""


def test_request_password_reset_wrong_answer(temp_db_file):
    """Test password reset request with wrong answer"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")
    auth.set_recovery_question("testuser", "Question?", "CorrectAnswer")

    success, message, token = auth.request_password_reset("testuser", "WrongAnswer")

    assert success is False
    assert "incorrect" in message.lower()
    assert token == ""


def test_reset_password_success(temp_db_file):
    """Test successful password reset"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")
    auth.set_recovery_question("testuser", "Question?", "Answer")

    # Request reset
    success, msg, token = auth.request_password_reset("testuser", "Answer")
    assert success is True

    # Reset password
    success, message = auth.reset_password("testuser", token, "NewStrongPass456!")

    assert success is True
    assert "successfully" in message.lower()

    # Verify old password doesn't work
    ok, _ = auth.authenticate_user("testuser", "StrongPassword123!")
    assert ok is False

    # Verify new password works
    ok, _ = auth.authenticate_user("testuser", "NewStrongPass456!")
    assert ok is True

    # Verify token is cleared
    user = auth.get_user_by_username("testuser")
    assert user.password_reset_token is None
    assert user.password_reset_expires is None


def test_reset_password_user_not_found(temp_db_file):
    """Test password reset for non-existent user"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    success, message = auth.reset_password("nonexistent", "token", "NewPass123!")

    assert success is False
    assert "not found" in message.lower()


def test_reset_password_invalid_token(temp_db_file):
    """Test password reset with invalid token"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")
    auth.set_recovery_question("testuser", "Question?", "Answer")

    # Request reset
    success, _, token = auth.request_password_reset("testuser", "Answer")
    assert success is True

    # Try with wrong token
    success, message = auth.reset_password("testuser", "wrong_token", "NewPass123!")

    assert success is False
    assert "invalid" in message.lower()


def test_reset_password_expired_token(temp_db_file):
    """Test password reset with expired token"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")
    auth.set_recovery_question("testuser", "Question?", "Answer")

    # Request reset
    success, _, token = auth.request_password_reset("testuser", "Answer")
    assert success is True

    # Manually expire the token
    session = db.get_session()
    try:
        user = session.query(User).filter(User.username == "testuser").first()
        user.password_reset_expires = datetime.utcnow() - timedelta(hours=1)
        session.commit()
    finally:
        db.close_session(session)

    # Try to reset with expired token
    success, message = auth.reset_password("testuser", token, "NewPass123!")

    assert success is False
    assert "expired" in message.lower()


def test_reset_password_weak_password(temp_db_file):
    """Test password reset with weak password"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")
    auth.set_recovery_question("testuser", "Question?", "Answer")

    # Request reset
    success, _, token = auth.request_password_reset("testuser", "Answer")
    assert success is True

    # Try to reset with weak password
    success, message = auth.reset_password("testuser", token, "weak")

    assert success is False
    assert "validation" in message.lower()


def test_admin_reset_password_success(temp_db_file):
    """Test successful admin password reset"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    # Create admin and regular user
    auth.create_user("admin", "admin@example.com", "AdminPass123!", "admin")
    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")

    # Admin resets user password
    success, message = auth.admin_reset_password("admin", "testuser", "NewUserPass456!")

    assert success is True
    assert "successfully" in message.lower()

    # Verify old password doesn't work
    ok, _ = auth.authenticate_user("testuser", "StrongPassword123!")
    assert ok is False

    # Verify new password works
    ok, _ = auth.authenticate_user("testuser", "NewUserPass456!")
    assert ok is True


def test_admin_reset_password_not_admin(temp_db_file):
    """Test admin reset password by non-admin user"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("regular", "regular@example.com", "RegularPass123!", "user")
    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")

    # Regular user tries to reset password
    success, message = auth.admin_reset_password("regular", "testuser", "NewPass123!")

    assert success is False
    assert "admin" in message.lower()


def test_admin_reset_password_admin_not_found(temp_db_file):
    """Test admin reset password when admin doesn't exist"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")

    success, message = auth.admin_reset_password(
        "nonexistent_admin", "testuser", "NewPass123!"
    )

    assert success is False
    assert "admin" in message.lower() or "not found" in message.lower()


def test_admin_reset_password_target_not_found(temp_db_file):
    """Test admin reset password for non-existent target user"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("admin", "admin@example.com", "AdminPass123!", "admin")

    success, message = auth.admin_reset_password("admin", "nonexistent", "NewPass123!")

    assert success is False
    assert "not found" in message.lower()


def test_admin_reset_password_weak_password(temp_db_file):
    """Test admin reset password with weak password"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("admin", "admin@example.com", "AdminPass123!", "admin")
    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")

    success, message = auth.admin_reset_password("admin", "testuser", "weak")

    assert success is False
    assert "validation" in message.lower()


def test_admin_reset_password_clears_lockout(temp_db_file):
    """Test that admin reset clears account lockout"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("admin", "admin@example.com", "AdminPass123!", "admin")
    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")

    # Lock the account
    session = db.get_session()
    try:
        user = session.query(User).filter(User.username == "testuser").first()
        user.locked_until = datetime.utcnow() + timedelta(hours=1)
        user.failed_attempts = 5
        session.commit()
    finally:
        db.close_session(session)

    # Admin resets password
    success, _ = auth.admin_reset_password("admin", "testuser", "NewPass123!")

    assert success is True

    # Verify lockout is cleared
    user = auth.get_user_by_username("testuser")
    assert user.locked_until is None
    assert user.failed_attempts == 0


def test_password_recovery_full_workflow(temp_db_file):
    """Test complete password recovery workflow"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    # Create user
    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")

    # Set recovery question
    success, _ = auth.set_recovery_question(
        "testuser", "What is your mother's maiden name?", "Smith"
    )
    assert success is True

    # Request reset
    success, msg, token = auth.request_password_reset("testuser", "Smith")
    assert success is True
    assert token is not None

    # Reset password
    success, _ = auth.reset_password("testuser", token, "NewSecurePass789!")
    assert success is True

    # Verify authentication with new password
    ok, _ = auth.authenticate_user("testuser", "NewSecurePass789!")
    assert ok is True


def test_multiple_reset_requests_invalidates_previous_token(temp_db_file):
    """Test that multiple reset requests invalidate previous tokens"""
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("testuser", "test@example.com", "StrongPassword123!", "user")
    auth.set_recovery_question("testuser", "Question?", "Answer")

    # First reset request
    success1, _, token1 = auth.request_password_reset("testuser", "Answer")
    assert success1 is True

    # Second reset request
    success2, _, token2 = auth.request_password_reset("testuser", "Answer")
    assert success2 is True

    # First token should be invalid
    success, message = auth.reset_password("testuser", token1, "NewPass123!")
    assert success is False
    assert "invalid" in message.lower()

    # Second token should work
    success, message = auth.reset_password("testuser", token2, "NewPass123!")
    assert success is True
