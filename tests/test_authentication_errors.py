import types

from app.auth.authentication import AuthenticationManager
from app.models.database import DatabaseManager


class FailingSession:
    def add(self, *_args, **_kwargs):
        pass

    def commit(self):
        raise RuntimeError("commit failed")

    def rollback(self):
        pass

    def close(self):
        pass


def test_create_user_db_exception(temp_db_file, monkeypatch):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)

    monkeypatch.setattr(db, "get_session", lambda: FailingSession())
    ok = auth.create_user("ex", "ex@example.com", "StrongPassword123!", "user")
    assert not ok


def test_change_password_invalid_and_weak(temp_db_file):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)
    auth.create_user("u", "u@example.com", "StrongPassword123!", "user")

    ok, msg = auth.change_password("u", "wrong", "NewStrongPass456!")
    assert not ok and "incorrect" in msg.lower()

    ok, msg = auth.change_password("u", "StrongPassword123!", "short")
    assert not ok and "validation failed" in msg.lower()
