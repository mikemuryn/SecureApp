from pathlib import Path

from app.models.database import AuditLog, DatabaseManager, User
from app.utils.audit_logger import AuditLogger


def test_audit_logger_variants(temp_db_file, temp_log_file):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    ses = db.get_session()
    try:
        u = User(
            username="logu",
            email="logu@example.com",
            password_hash="x",
            salt="y",
            role="user",
        )
        ses.add(u)
        ses.commit()
        uid = u.id
    finally:
        db.close_session(ses)

    logger = AuditLogger(Path(temp_log_file), db)
    logger.log_password_change("logu", True)
    logger.log_user_creation("child", created_by="logu", success=True)
    logger.log_security_event("logu", "brute_force", "too many attempts")

    # recent events fetch (db path)
    events = logger.get_recent_events(hours=24)
    assert isinstance(events, list)
