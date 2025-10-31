from pathlib import Path

from app.utils.audit_logger import AuditLogger


class FailingDB:
    class _Ses:
        def add(self, *_a, **_k):
            pass

        def commit(self):
            raise RuntimeError("db fail")

        def rollback(self):
            pass

        def close(self):
            pass

    def get_session(self):
        return self._Ses()

    def close_session(self, _s):
        pass


def test_audit_db_write_failure_logs_and_continues(tmp_path):
    logf = tmp_path / "audit.log"
    logger = AuditLogger(logf, FailingDB())
    # This should exercise _log_to_database exception handling path
    logger.log_event(username="x", action="file_upload", resource="f.txt", success=True)
    assert logf.exists()
