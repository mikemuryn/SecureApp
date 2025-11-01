import os
import types
from pathlib import Path

from app.encryption.file_crypto import FileEncryption
from app.models.database import DatabaseManager, User
from app.utils.audit_logger import AuditLogger
from app.utils.file_manager import FileAccessManager


def test_upload_missing_file(tmp_path, temp_db_file, temp_log_file):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    ses = db.get_session()
    try:
        u = User(
            username="m",
            email="m@example.com",
            password_hash="x",
            salt="y",
            role="user",
        )
        ses.add(u)
        ses.commit()
    finally:
        db.close_session(ses)
    fam = FileAccessManager(
        db,
        encryption_manager=lambda p: FileEncryption(p),
        audit_logger=AuditLogger(Path(temp_log_file), db),
    )
    ok, msg = fam.upload_file(Path(tmp_path / "nope.txt"), "m", "StrongPassword123!")
    assert not ok and "does not exist" in msg


def test_upload_too_large(tmp_path, temp_db_file, temp_log_file, monkeypatch):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    ses = db.get_session()
    try:
        u = User(
            username="big",
            email="big@example.com",
            password_hash="x",
            salt="y",
            role="user",
        )
        ses.add(u)
        ses.commit()
    finally:
        db.close_session(ses)
    fam = FileAccessManager(
        db,
        encryption_manager=lambda p: FileEncryption(p),
        audit_logger=AuditLogger(Path(temp_log_file), db),
    )
    f = tmp_path / "big.bin"
    f.write_bytes(b"0")

    # monkeypatch Path.stat only in file_manager module to simulate large file
    def fake_stat(self, *args, **kwargs):
        return types.SimpleNamespace(st_size=101 * 1024 * 1024)

    monkeypatch.setattr("app.utils.file_manager.Path.stat", fake_stat)
    ok, msg = fam.upload_file(f, "big", "StrongPassword123!")
    assert not ok and "too large" in msg


def test_list_files_admin_sees_all(tmp_path, temp_db_file, temp_log_file):
    os.chdir(tmp_path)
    db = DatabaseManager(f"sqlite:///{tmp_path/'admin.db'}")
    db.create_tables()
    ses = db.get_session()
    try:
        admin = User(
            username="adminu",
            email="a@example.com",
            password_hash="x",
            salt="y",
            role="admin",
        )
        user = User(
            username="uu",
            email="uu@example.com",
            password_hash="x",
            salt="y",
            role="user",
        )
        ses.add_all([admin, user])
        ses.commit()
    finally:
        db.close_session(ses)
    fam = FileAccessManager(
        db,
        encryption_manager=lambda p: FileEncryption(p),
        audit_logger=AuditLogger(Path(temp_log_file), db),
    )
    f = tmp_path / "c.txt"
    f.write_text("c")
    ok, _ = fam.upload_file(f, "uu", "StrongPassword123!")
    assert ok
    files_admin, total = fam.list_user_files("adminu")
    assert files_admin and files_admin[0]["owner"] == "uu"
