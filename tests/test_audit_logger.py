from pathlib import Path

from app.models.database import DatabaseManager, User
from app.utils.audit_logger import AuditLogger


def test_audit_logger_file_only(temp_log_file):
    logger = AuditLogger(Path(temp_log_file))
    logger.log_login_attempt("alice", True)
    logger.log_file_access("alice", "x.txt", "upload", True)
    assert Path(temp_log_file).exists()
    text = Path(temp_log_file).read_text()
    assert "login_attempt" in text or "file_upload" in text


def test_audit_logger_with_db(temp_db_file, temp_log_file):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    # create a user to attach to logs optionally
    ses = db.get_session()
    try:
        u = User(
            username="zoe",
            email="zoe@example.com",
            password_hash="x",
            salt="y",
            role="user",
        )
        ses.add(u)
        ses.commit()
    finally:
        db.close_session(ses)

    logger = AuditLogger(Path(temp_log_file), db)
    logger.log_event(username="zoe", action="login", success=True)
    # ensure no exceptions and file written
    assert Path(temp_log_file).exists()
