from app.auth.authentication import AuthenticationManager
from app.models.database import DatabaseManager


def test_authenticate_exception_path(temp_db_file, monkeypatch):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)
    monkeypatch.setattr(
        db, "get_session", lambda: (_ for _ in ()).throw(RuntimeError("db fail"))
    )
    ok, msg = auth.authenticate_user("x", "y")
    assert not ok and "error" in msg.lower()


def test_change_password_exception_path(temp_db_file, monkeypatch):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    auth = AuthenticationManager(db)
    auth.create_user("u", "u@example.com", "StrongPassword123!", "user")

    class BadSes:
        def __enter__(self):
            return self

    monkeypatch.setattr(
        db, "get_session", lambda: (_ for _ in ()).throw(RuntimeError("db fail"))
    )
    ok, msg = auth.change_password("u", "StrongPassword123!", "NewStrongPass456!")
    assert not ok and "failed" in msg.lower()
