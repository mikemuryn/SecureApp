import pytest

from app.auth.authentication import AuthenticationManager
from app.models.database import DatabaseManager, User


def test_create_user_duplicate_username(temp_db_file):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    assert auth.create_user("dup", "dup@example.com", "StrongPassword123!", "user")
    # duplicate username
    assert not auth.create_user(
        "dup", "other@example.com", "StrongPassword123!", "user"
    )


def test_create_user_weak_password(temp_db_file):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)
    assert not auth.create_user("weak", "weak@example.com", "short", "user")


def test_auth_inactive_and_unknown_user(temp_db_file):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)
    # unknown
    ok, msg = auth.authenticate_user("nouser", "pwd")
    assert not ok

    # inactive
    ses = db.get_session()
    try:
        u = User(
            username="inactive",
            email="inactive@example.com",
            password_hash=auth.hash_password("StrongPassword123!"),
            salt="y",
            role="user",
            is_active=False,
        )
        ses.add(u)
        ses.commit()
    finally:
        db.close_session(ses)
    ok, msg = auth.authenticate_user("inactive", "StrongPassword123!")
    assert not ok and "disabled" in msg.lower()


def test_get_user_by_username(temp_db_file):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)
    auth.create_user("eve", "eve@example.com", "StrongPassword123!", "user")
    u = auth.get_user_by_username("eve")
    assert u and u.username == "eve"
