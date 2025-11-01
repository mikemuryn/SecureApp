"""
Comprehensive tests for SessionManager to improve coverage
"""

import time
from datetime import datetime, timedelta

import pytest

from app.auth.session_manager import SessionManager


def test_session_manager_init_default():
    """Test SessionManager initialization with default timeout"""
    sm = SessionManager()

    assert sm.session_timeout == 1800  # 30 minutes default
    assert sm.max_sessions_per_user == 3
    assert isinstance(sm.sessions, dict)
    assert len(sm.sessions) == 0


def test_session_manager_init_custom_timeout():
    """Test SessionManager initialization with custom timeout"""
    sm = SessionManager(session_timeout=3600)

    assert sm.session_timeout == 3600
    assert sm.max_sessions_per_user == 3


def test_create_session():
    """Test creating a session"""
    sm = SessionManager(session_timeout=60)
    token = sm.create_session("testuser", "user")

    assert token is not None
    assert len(token) > 0
    assert token in sm.sessions
    assert sm.sessions[token]["username"] == "testuser"
    assert sm.sessions[token]["role"] == "user"
    assert "created_at" in sm.sessions[token]
    assert "last_activity" in sm.sessions[token]


def test_validate_session_valid():
    """Test validating a valid session"""
    sm = SessionManager(session_timeout=60)
    token = sm.create_session("testuser", "user")

    ok, data = sm.validate_session(token)

    assert ok is True
    assert data is not None
    assert data["username"] == "testuser"
    assert data["role"] == "user"


def test_validate_session_invalid_token():
    """Test validating invalid token"""
    sm = SessionManager(session_timeout=60)
    ok, data = sm.validate_session("invalid_token")

    assert ok is False
    assert data is None


def test_validate_session_expired():
    """Test validating expired session"""
    sm = SessionManager(session_timeout=1)  # 1 second timeout
    token = sm.create_session("testuser", "user")

    # Wait for expiration
    time.sleep(1.5)

    ok, data = sm.validate_session(token)

    assert ok is False
    assert data is None


def test_refresh_session_valid():
    """Test refreshing valid session"""
    sm = SessionManager(session_timeout=60)
    token = sm.create_session("testuser", "user")

    original_activity = sm.sessions[token]["last_activity"]

    # Wait a bit
    time.sleep(0.1)

    success = sm.refresh_session(token)

    assert success is True
    assert sm.sessions[token]["last_activity"] > original_activity


def test_refresh_session_invalid():
    """Test refreshing invalid session"""
    sm = SessionManager(session_timeout=60)
    success = sm.refresh_session("invalid_token")

    assert success is False


def test_refresh_session_expired():
    """Test refreshing expired session"""
    sm = SessionManager(session_timeout=1)
    token = sm.create_session("testuser", "user")

    # Wait for session to expire
    time.sleep(1.5)

    # validate_session removes expired sessions (line 75 in session_manager.py)
    # So if we validate first, the session will be removed
    # Then refresh_session will return False because session doesn't exist
    is_valid, _ = sm.validate_session(token)
    assert is_valid is False  # Session is expired, validation removes it

    # Now refresh_session will fail because session was removed
    success = sm.refresh_session(token)
    assert success is False  # Session no longer exists (was removed by validate)


def test_destroy_session():
    """Test destroying a session"""
    sm = SessionManager(session_timeout=60)
    token = sm.create_session("testuser", "user")

    assert token in sm.sessions

    success = sm.destroy_session(token)

    assert success is True
    assert token not in sm.sessions


def test_destroy_session_invalid():
    """Test destroying invalid session"""
    sm = SessionManager(session_timeout=60)
    success = sm.destroy_session("invalid_token")

    assert success is False


def test_destroy_user_sessions():
    """Test destroying all sessions for a user"""
    sm = SessionManager(session_timeout=60)

    # Create multiple sessions for same user
    token1 = sm.create_session("testuser", "user")
    token2 = sm.create_session("testuser", "user")
    token3 = sm.create_session("otheruser", "user")

    assert token1 in sm.sessions
    assert token2 in sm.sessions
    assert token3 in sm.sessions

    destroyed = sm.destroy_user_sessions("testuser")

    assert destroyed == 2
    assert token1 not in sm.sessions
    assert token2 not in sm.sessions
    assert token3 in sm.sessions  # Other user's session still exists


def test_destroy_user_sessions_no_sessions():
    """Test destroying sessions for user with no sessions"""
    sm = SessionManager(session_timeout=60)

    destroyed = sm.destroy_user_sessions("nonexistent")

    assert destroyed == 0


def test_session_limit_enforcement():
    """Test that max_sessions_per_user limit is enforced"""
    sm = SessionManager(session_timeout=60)
    sm.max_sessions_per_user = 2

    # Create 3 sessions (exceeds limit)
    token1 = sm.create_session("testuser", "user")
    token2 = sm.create_session("testuser", "user")
    token3 = sm.create_session("testuser", "user")

    # Should have only 2 sessions (oldest removed)
    user_sessions = [s for s in sm.sessions.values() if s["username"] == "testuser"]
    assert len(user_sessions) == 2

    # token1 should be removed (oldest)
    assert token1 not in sm.sessions
    assert token2 in sm.sessions
    assert token3 in sm.sessions


def test_cleanup_user_sessions():
    """Test cleanup of expired sessions for a user"""
    sm = SessionManager(session_timeout=1)

    # Create expired session
    token1 = sm.create_session("testuser", "user")
    sm.sessions[token1]["last_activity"] = datetime.utcnow() - timedelta(seconds=2)

    # Create valid session
    token2 = sm.create_session("testuser", "user")

    # Create new session (should trigger cleanup)
    token3 = sm.create_session("testuser", "user")

    # Expired session should be cleaned up
    assert token1 not in sm.sessions
    assert token2 in sm.sessions or token3 in sm.sessions


def test_cleanup_expired_sessions():
    """Test cleanup of all expired sessions"""
    sm = SessionManager(session_timeout=1)

    # Create expired session
    token1 = sm.create_session("testuser1", "user")
    sm.sessions[token1]["last_activity"] = datetime.utcnow() - timedelta(seconds=2)

    # Create valid session
    token2 = sm.create_session("testuser2", "user")

    # Cleanup
    sm.cleanup_expired_sessions()

    # Expired session should be removed
    assert token1 not in sm.sessions
    assert token2 in sm.sessions


def test_cleanup_expired_sessions_no_expired():
    """Test cleanup when no expired sessions"""
    sm = SessionManager(session_timeout=60)

    token = sm.create_session("testuser", "user")

    sm.cleanup_expired_sessions()

    # Session should still exist
    assert token in sm.sessions


def test_get_active_sessions():
    """Test getting all active sessions"""
    sm = SessionManager(session_timeout=60)

    token1 = sm.create_session("user1", "user")
    token2 = sm.create_session("user2", "admin")

    sessions = sm.get_active_sessions()

    assert isinstance(sessions, dict)
    assert len(sessions) == 2
    assert token1 in sessions
    assert token2 in sessions
    assert sessions[token1]["username"] == "user1"
    assert sessions[token2]["username"] == "user2"


def test_get_active_sessions_empty():
    """Test getting active sessions when none exist"""
    sm = SessionManager(session_timeout=60)

    sessions = sm.get_active_sessions()

    assert isinstance(sessions, dict)
    assert len(sessions) == 0


def test_session_data_structure():
    """Test that session data has correct structure"""
    sm = SessionManager(session_timeout=60)
    token = sm.create_session("testuser", "admin")

    session_data = sm.sessions[token]

    assert "username" in session_data
    assert "role" in session_data
    assert "created_at" in session_data
    assert "last_activity" in session_data
    assert "token" in session_data
    assert session_data["token"] == token
    assert session_data["username"] == "testuser"
    assert session_data["role"] == "admin"
    assert isinstance(session_data["created_at"], datetime)
    assert isinstance(session_data["last_activity"], datetime)


def test_validate_session_updates_last_activity():
    """Test that validate_session updates last_activity"""
    sm = SessionManager(session_timeout=60)
    token = sm.create_session("testuser", "user")

    original_activity = sm.sessions[token]["last_activity"]

    time.sleep(0.1)

    sm.validate_session(token)

    assert sm.sessions[token]["last_activity"] > original_activity


def test_multiple_users_sessions():
    """Test sessions for multiple users"""
    sm = SessionManager(session_timeout=60)

    token1 = sm.create_session("user1", "user")
    token2 = sm.create_session("user2", "user")
    token3 = sm.create_session("user3", "admin")

    assert len(sm.sessions) == 3
    assert sm.sessions[token1]["username"] == "user1"
    assert sm.sessions[token2]["username"] == "user2"
    assert sm.sessions[token3]["username"] == "user3"


def test_session_token_uniqueness():
    """Test that session tokens are unique"""
    sm = SessionManager(session_timeout=60)

    tokens = []
    for _ in range(10):
        token = sm.create_session("testuser", "user")
        tokens.append(token)

    # All tokens should be unique
    assert len(tokens) == len(set(tokens))


def test_is_session_expired():
    """Test internal _is_session_expired method"""
    sm = SessionManager(session_timeout=1)

    # Create session
    token = sm.create_session("testuser", "user")

    # Make it expired
    sm.sessions[token]["last_activity"] = datetime.utcnow() - timedelta(seconds=2)

    is_expired = sm._is_session_expired(sm.sessions[token])

    assert is_expired is True


def test_is_session_not_expired():
    """Test that valid session is not expired"""
    sm = SessionManager(session_timeout=60)

    token = sm.create_session("testuser", "user")

    is_expired = sm._is_session_expired(sm.sessions[token])

    assert is_expired is False


def test_refresh_extends_session():
    """Test that refresh extends session beyond original timeout"""
    sm = SessionManager(session_timeout=2)

    token = sm.create_session("testuser", "user")

    # Wait 1 second
    time.sleep(1)

    # Refresh
    sm.refresh_session(token)

    # Wait another 1.5 seconds (total 2.5, but refreshed 1 second ago)
    time.sleep(1.5)

    # Should still be valid (refreshed extended it)
    ok, _ = sm.validate_session(token)
    assert ok is True


def test_session_cleanup_on_create():
    """Test that creating new session cleans up expired ones for user"""
    sm = SessionManager(session_timeout=1)

    # Create expired session
    token1 = sm.create_session("testuser", "user")
    sm.sessions[token1]["last_activity"] = datetime.utcnow() - timedelta(seconds=2)

    # Create new session (should cleanup expired)
    token2 = sm.create_session("testuser", "user")

    # Expired session should be gone
    assert token1 not in sm.sessions
    assert token2 in sm.sessions
