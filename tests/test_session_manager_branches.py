from app.auth.session_manager import SessionManager


def test_max_sessions_rollover():
    sm = SessionManager(session_timeout=60)
    sm.max_sessions_per_user = 2
    t1 = sm.create_session("u", "user")
    t2 = sm.create_session("u", "user")
    # Third should evict oldest (t1)
    t3 = sm.create_session("u", "user")
    assert t1 not in sm.sessions and t2 in sm.sessions and t3 in sm.sessions


def test_get_user_sessions_and_cleanup():
    sm = SessionManager(session_timeout=0)
    t1 = sm.create_session("x", "user")
    # Immediately expired due to zero timeout
    sessions = sm.get_user_sessions("x")
    assert sessions == []
    sm.cleanup_expired_sessions()
    assert t1 not in sm.sessions
