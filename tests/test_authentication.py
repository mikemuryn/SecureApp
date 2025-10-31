import pytest

from app.auth.authentication import AuthenticationManager
from app.models.database import DatabaseManager


def test_password_strength_checks(weak_passwords, strong_passwords):
    auth = AuthenticationManager(db_manager=None)  # db not needed for this
    for pwd in weak_passwords:
        ok, errs = auth.validate_password_strength(pwd)
        assert not ok
        assert len(errs) >= 1
    for pwd in strong_passwords:
        ok, errs = auth.validate_password_strength(pwd)
        assert ok
        assert errs == []


def test_hash_and_verify_roundtrip():
    auth = AuthenticationManager(db_manager=None)
    pw = "StrongPassword123!"
    h = auth.hash_password(pw)
    assert h and isinstance(h, str)
    assert auth.verify_password(pw, h)
    assert not auth.verify_password("wrong", h)


def test_create_and_authenticate_user(temp_db_file):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    assert auth.create_user("alice", "alice@example.com", "StrongPassword123!", "user")

    ok, msg = auth.authenticate_user("alice", "StrongPassword123!")
    assert ok and msg.lower().startswith("login")

    ok, msg = auth.authenticate_user("alice", "wrongpass")
    assert not ok


def test_account_lockout_on_failed_attempts(temp_db_file):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("bob", "bob@example.com", "StrongPassword123!", "user")

    # Exceed max attempts
    for _ in range(auth.max_login_attempts):
        ok, _ = auth.authenticate_user("bob", "wrong")
        assert not ok

    ok, msg = auth.authenticate_user("bob", "StrongPassword123!")
    assert not ok
    assert "locked" in msg.lower()


def test_change_password_flow(temp_db_file):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    auth.create_user("carol", "carol@example.com", "StrongPassword123!", "user")

    ok, msg = auth.change_password("carol", "StrongPassword123!", "NewStrongPass456!")
    assert ok

    ok, _ = auth.authenticate_user("carol", "NewStrongPass456!")
    assert ok
