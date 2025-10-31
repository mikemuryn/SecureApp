from time import sleep

from app.auth.session_manager import SessionManager


def test_create_and_validate_session():
    sm = SessionManager(session_timeout=5)
    token = sm.create_session("alice", "user")
    assert token
    ok, data = sm.validate_session(token)
    assert ok and data["username"] == "alice"


def test_refresh_and_expire_session():
    sm = SessionManager(session_timeout=1)
    token = sm.create_session("bob", "user")
    sleep(0.5)
    assert sm.refresh_session(token)
    sleep(0.7)
    ok, _ = sm.validate_session(token)
    assert ok  # refreshed extended it
    sleep(1.2)
    ok, _ = sm.validate_session(token)
    assert not ok


def test_destroy_sessions():
    sm = SessionManager(session_timeout=60)
    t1 = sm.create_session("carol", "user")
    t2 = sm.create_session("carol", "user")
    assert sm.destroy_session(t1)
    assert not sm.validate_session(t1)[0]
    destroyed = sm.destroy_user_sessions("carol")
    assert destroyed >= 1
