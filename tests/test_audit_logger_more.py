import types
from pathlib import Path

from app.utils.audit_logger import AuditLogger


def test_get_recent_events_without_db(temp_log_file):
    logger = AuditLogger(Path(temp_log_file))
    assert logger.get_recent_events() == []


def test_get_recent_events_exception_path(temp_db_file, temp_log_file, monkeypatch):
    # Create logger with dummy db that raises in query flow
    class BadDB:
        def get_session(self):
            class S:
                def __enter__(self):
                    return self

                def __exit__(self, *_):
                    return False

            raise RuntimeError("db fail")

        def close_session(self, _s):
            pass

    logger = AuditLogger(Path(temp_log_file), BadDB())
    evts = logger.get_recent_events()
    assert evts == []
