import os
import tempfile
from pathlib import Path

from app.models.database import DatabaseManager, User
from app.utils.audit_logger import AuditLogger
from app.utils.file_manager import FileAccessManager


def test_file_manager_upload_list_download_delete(
    tmp_path, temp_db_file, temp_log_file
):
    # prepare temp working dirs
    data_dir = tmp_path / "data"
    enc_dir = data_dir / "encrypted"
    temp_dir = tmp_path / "temp"
    enc_dir.mkdir(parents=True)
    temp_dir.mkdir(parents=True)

    # chdir so FileAccessManager/FileEncryption default paths land under tmp
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        db = DatabaseManager(f"sqlite:///{tmp_path/'test.db'}")
        db.create_tables()

        # create a user
        session = db.get_session()
        try:
            u = User(
                username="erin",
                email="erin@example.com",
                password_hash="x",
                salt="y",
                role="user",
            )
            session.add(u)
            session.commit()
        finally:
            db.close_session(session)

        audit = AuditLogger(Path(temp_log_file), db)
        from app.encryption.file_crypto import FileEncryption

        fam = FileAccessManager(
            db, encryption_manager=lambda p: FileEncryption(p), audit_logger=audit
        )

        # create a sample file
        src = tmp_path / "hello.txt"
        src.write_text("hello")

        ok, msg = fam.upload_file(src, "erin", "StrongPassword123!")
        assert ok, msg

        files = fam.list_user_files("erin")
        assert len(files) == 1 and files[0]["filename"] == "hello.txt"

        file_id = files[0]["id"]
        ok, temp_out, _ = fam.download_file(file_id, "erin", "StrongPassword123!")
        assert ok and temp_out.exists() and temp_out.read_text() == "hello"

        ok, msg = fam.delete_file(file_id, "erin")
        assert ok
    finally:
        os.chdir(cwd)
