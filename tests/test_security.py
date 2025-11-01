from pathlib import Path

from app.models.database import DatabaseManager, User
from app.utils.audit_logger import AuditLogger
from app.utils.file_manager import FileAccessManager


def test_permission_denied_for_non_owner(tmp_path, temp_db_file, temp_log_file):
    db = DatabaseManager(temp_db_file)
    db.create_tables()

    # create owner and other user
    ses = db.get_session()
    try:
        owner = User(
            username="owner",
            email="owner@example.com",
            password_hash="x",
            salt="y",
            role="user",
        )
        other = User(
            username="other",
            email="other@example.com",
            password_hash="x",
            salt="y",
            role="user",
        )
        ses.add_all([owner, other])
        ses.commit()
    finally:
        db.close_session(ses)

    audit = AuditLogger(Path(temp_log_file), db)
    from app.encryption.file_crypto import FileEncryption

    fam = FileAccessManager(
        db, encryption_manager=lambda p: FileEncryption(p), audit_logger=audit
    )

    # chdir into tmp for paths
    import os

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # create a file and upload as owner
        src = tmp_path / "secret.txt"
        src.write_text("secret")
        ok, msg = fam.upload_file(src, "owner", "StrongPassword123!")
        assert ok, msg

        files, _ = fam.list_user_files("owner")
        file_id = files[0]["id"]
        ok, temp_out, message = fam.download_file(
            file_id, "other", "StrongPassword123!"
        )
        assert not ok
        assert "denied" in message.lower()
    finally:
        os.chdir(cwd)
