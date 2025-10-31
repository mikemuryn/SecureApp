from app.auth.session_manager import SessionManager


def test_refresh_and_destroy_invalid_token():
    sm = SessionManager(session_timeout=60)
    assert not sm.refresh_session("nope")
    assert not sm.destroy_session("nope")


def test_get_active_sessions_snapshot():
    sm = SessionManager(session_timeout=60)
    sm.create_session("a", "user")
    snapshot = sm.get_active_sessions()
    assert isinstance(snapshot, dict) and snapshot
