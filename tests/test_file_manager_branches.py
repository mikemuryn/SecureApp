import os
from pathlib import Path

from app.encryption.file_crypto import FileEncryption
from app.models.database import DatabaseManager, User
from app.utils.audit_logger import AuditLogger
from app.utils.file_manager import FileAccessManager


def test_upload_duplicate_and_user_not_found(tmp_path, temp_db_file, temp_log_file):
    os.chdir(tmp_path)
    db = DatabaseManager(f"sqlite:///{tmp_path/'t.db'}")
    db.create_tables()
    ses = db.get_session()
    try:
        u = User(
            username="dupuser",
            email="d@example.com",
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
    f = tmp_path / "a.txt"
    f.write_text("x")
    ok, _ = fam.upload_file(f, "dupuser", "StrongPassword123!")
    assert ok
    ok, msg = fam.upload_file(f, "dupuser", "StrongPassword123!")
    assert not ok and "already exists" in msg
    ok, msg = fam.upload_file(f, "nouser", "StrongPassword123!")
    assert not ok and "User not found" in msg


def test_delete_access_denied_and_file_not_found(tmp_path, temp_db_file, temp_log_file):
    os.chdir(tmp_path)
    db = DatabaseManager(f"sqlite:///{tmp_path/'t2.db'}")
    db.create_tables()
    ses = db.get_session()
    try:
        owner = User(
            username="own",
            email="o@example.com",
            password_hash="x",
            salt="y",
            role="user",
        )
        other = User(
            username="oth",
            email="oth@example.com",
            password_hash="x",
            salt="y",
            role="user",
        )
        ses.add_all([owner, other])
        ses.commit()
    finally:
        db.close_session(ses)
    fam = FileAccessManager(
        db,
        encryption_manager=lambda p: FileEncryption(p),
        audit_logger=AuditLogger(Path(temp_log_file), db),
    )
    src = tmp_path / "b.txt"
    src.write_text("b")
    ok, _ = fam.upload_file(src, "own", "StrongPassword123!")
    file_id = fam.list_user_files("own")[0]["id"]
    ok, msg = fam.delete_file(file_id, "oth")
    assert not ok and "denied" in msg.lower()
    # delete unknown id
    ok, msg = fam.delete_file(99999, "own")
    assert not ok and "not found" in msg.lower()
