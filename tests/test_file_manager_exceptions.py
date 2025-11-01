import os
import types
from pathlib import Path

import pytest

from app.models.database import DatabaseManager, User
from app.utils.audit_logger import AuditLogger
from app.utils.file_manager import FileAccessManager


class RaisingEncryption:
    def __init__(self, *_a, **_k):
        pass

    def encrypt_file(self, *_a, **_k):
        raise RuntimeError("encrypt boom")

    def decrypt_file(self, *_a, **_k):
        raise RuntimeError("decrypt boom")


def setup_user(db, username="u1"):
    ses = db.get_session()
    try:
        u = User(
            username=username,
            email=f"{username}@e.com",
            password_hash="x",
            salt="y",
            role="user",
        )
        ses.add(u)
        ses.commit()
    finally:
        db.close_session(ses)


def test_upload_exception_path(tmp_path, temp_db_file, temp_log_file):
    os.chdir(tmp_path)
    db = DatabaseManager(f"sqlite:///{tmp_path/'ex.db'}")
    db.create_tables()
    setup_user(db, "u1")
    fam = FileAccessManager(
        db,
        encryption_manager=lambda p: RaisingEncryption(),
        audit_logger=AuditLogger(Path(temp_log_file), db),
    )
    f = tmp_path / "x.txt"
    f.write_text("x")
    ok, msg = fam.upload_file(f, "u1", "pass")
    assert not ok and "Upload failed" in msg


def test_download_user_and_file_not_found(tmp_path, temp_db_file, temp_log_file):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    fam = FileAccessManager(
        db,
        encryption_manager=lambda p: RaisingEncryption(),
        audit_logger=AuditLogger(Path(temp_log_file), db),
    )
    ok, path, msg = fam.download_file(1, "nouser", "p")
    assert not ok and msg == "User not found"

    # create user but no file
    setup_user(db, "u2")
    ok, path, msg = fam.download_file(999, "u2", "p")
    assert not ok and msg == "File not found"


def test_download_exception_path(tmp_path, temp_db_file, temp_log_file):
    os.chdir(tmp_path)
    db = DatabaseManager(f"sqlite:///{tmp_path/'d.db'}")
    db.create_tables()
    setup_user(db, "u3")
    # Prepare a real file record with bogus encrypted path to trigger decrypt error
    ses = db.get_session()
    try:
        from app.models.database import SecureFile, User

        u = ses.query(User).filter(User.username == "u3").first()
        sf = SecureFile(
            filename="a.txt",
            original_path=str(tmp_path / "a.txt"),
            encrypted_path=str(tmp_path / "nope.enc"),
            file_hash="h",
            file_size=1,
            owner_id=u.id,
        )
        ses.add(sf)
        ses.commit()
        sfid = sf.id
    finally:
        db.close_session(ses)
    fam = FileAccessManager(
        db,
        encryption_manager=lambda p: RaisingEncryption(),
        audit_logger=AuditLogger(Path(temp_log_file), db),
    )
    ok, path, msg = fam.download_file(sfid, "u3", "p")
    assert not ok and msg.startswith("Download failed")


def test_list_user_files_no_user_and_exception(
    tmp_path, temp_db_file, temp_log_file, monkeypatch
):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    fam = FileAccessManager(
        db,
        encryption_manager=lambda p: RaisingEncryption(),
        audit_logger=AuditLogger(Path(temp_log_file), db),
    )
    files, total = fam.list_user_files("nouser")
    assert files == [] and total == 0

    class BadDB:
        def get_session(self):
            raise RuntimeError("db down")

    fam_bad = FileAccessManager(
        BadDB(),
        encryption_manager=lambda p: RaisingEncryption(),
        audit_logger=AuditLogger(Path(temp_log_file)),
    )
    files, total = fam_bad.list_user_files("any")
    assert files == [] and total == 0


def test_delete_user_not_found_and_exception(
    tmp_path, temp_db_file, temp_log_file, monkeypatch
):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    fam = FileAccessManager(
        db,
        encryption_manager=lambda p: RaisingEncryption(),
        audit_logger=AuditLogger(Path(temp_log_file), db),
    )
    ok, msg = fam.delete_file(1, "nouser")
    assert not ok and msg == "User not found"

    # Setup a user and file, then make unlink raise to hit exception handler
    os.chdir(tmp_path)
    setup_user(db, "own")
    ses = db.get_session()
    try:
        from app.models.database import SecureFile, User

        u = ses.query(User).filter(User.username == "own").first()
        enc = tmp_path / "d.enc"
        enc.write_text("e")
        sf = SecureFile(
            filename="d.txt",
            original_path=str(tmp_path / "d.txt"),
            encrypted_path=str(enc),
            file_hash="hh",
            file_size=1,
            owner_id=u.id,
        )
        ses.add(sf)
        ses.commit()
        sfid = sf.id
    finally:
        db.close_session(ses)

    def boom_unlink(self, *a, **k):
        raise RuntimeError("unlink fail")

    monkeypatch.setattr("pathlib.Path.unlink", boom_unlink)
    ok, msg = fam.delete_file(sfid, "own")
    assert not ok and msg.startswith("Deletion failed")


def test_cleanup_temp_files_paths(tmp_path, temp_db_file, temp_log_file, monkeypatch):
    fam = FileAccessManager(
        DatabaseManager(temp_db_file),
        encryption_manager=lambda p: RaisingEncryption(),
        audit_logger=AuditLogger(Path(temp_log_file)),
    )
    # Create a temp file older than 1h
    old = fam.temp_dir / "old.tmp"
    fam.temp_dir.mkdir(exist_ok=True)
    old.write_text("x")
    # Force mtime to be old by monkeypatching stat
    import datetime as _dt

    real_stat = Path.stat

    class S:
        def __init__(self, mtime):
            self.st_mtime = mtime

    def fake_stat(self):
        return S((_dt.datetime.utcnow() - _dt.timedelta(hours=2)).timestamp())

    monkeypatch.setattr("pathlib.Path.stat", fake_stat)
    fam.cleanup_temp_files()

    # Now simulate iterator raising to hit exception path
    class BadIter:
        def iterdir(self):
            raise RuntimeError("iter fail")

    fam.temp_dir = BadIter()
    fam.cleanup_temp_files()
