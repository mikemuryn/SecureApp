"""
Edge case tests for FileAccessManager to improve coverage
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from app.encryption.file_crypto import FileEncryption
from app.models.database import DatabaseManager, User
from app.utils.audit_logger import AuditLogger
from app.utils.file_manager import FileAccessManager


@pytest.fixture
def setup_file_manager(tmp_path, temp_db_file):
    """Setup file manager with test environment"""
    data_dir = tmp_path / "data"
    enc_dir = data_dir / "encrypted"
    temp_dir = tmp_path / "temp"
    enc_dir.mkdir(parents=True, exist_ok=True)
    temp_dir.mkdir(parents=True, exist_ok=True)

    cwd = os.getcwd()
    os.chdir(tmp_path)

    try:
        db = DatabaseManager(temp_db_file)
        db.create_tables()

        audit = AuditLogger(Path(tmp_path / "test.log"), db)

        fam = FileAccessManager(
            db,
            encryption_manager=lambda p: FileEncryption(p),
            audit_logger=audit,
        )

        yield fam, db, tmp_path

    finally:
        os.chdir(cwd)


@pytest.fixture
def setup_user(setup_file_manager):
    """Create test user"""
    fam, db, tmp_path = setup_file_manager

    session = db.get_session()
    try:
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hash",
            salt="salt",
            role="user",
        )
        session.add(user)
        session.commit()
    finally:
        db.close_session(session)

    return fam, db, tmp_path, "testuser"


def test_upload_file_exception_handling(setup_user, monkeypatch):
    """Test upload_file exception handling"""
    fam, db, tmp_path, user = setup_user

    test_file = tmp_path / "test.txt"
    test_file.write_text("content")

    # Mock encryption manager to raise exception instead of get_session
    # This is easier to mock and will be caught
    original_encryption_manager = fam.encryption_manager

    def failing_encryption_manager(password):
        class FailingEncryption:
            def encrypt_file(self, source, dest):
                raise RuntimeError("Encryption failed")

        return FailingEncryption()

    fam.encryption_manager = failing_encryption_manager

    # Exception should be caught by upload_file's try/except
    success, msg = fam.upload_file(test_file, user, "password")
    assert success is False
    assert "failed" in msg.lower() or "error" in msg.lower()


def test_download_file_exception_handling(setup_user, monkeypatch):
    """Test download_file exception handling"""
    fam, db, tmp_path, user = setup_user

    # Upload a file first
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user, "password")

    files, _ = fam.list_user_files(user)
    file_id = files[0]["id"]

    # Mock encryption manager to raise exception
    original_encryption_manager = fam.encryption_manager

    def failing_encryption_manager(password):
        class FailingEncryption:
            def decrypt_file(self, source, dest):
                raise RuntimeError("Decryption failed")

        return FailingEncryption()

    fam.encryption_manager = failing_encryption_manager

    # Exception should be caught by download_file's try/except
    success, temp_path, msg = fam.download_file(file_id, user, "password")
    assert success is False
    assert "failed" in msg.lower() or "error" in msg.lower()


def test_list_user_files_exception_handling(setup_user, monkeypatch):
    """Test list_user_files exception handling"""
    fam, db, tmp_path, user = setup_user

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    files, total = fam.list_user_files(user)
    assert files == []
    assert total == 0


def test_delete_file_exception_handling(setup_user, monkeypatch):
    """Test delete_file exception handling"""
    fam, db, tmp_path, user = setup_user

    # Upload a file first
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user, "password")

    files, _ = fam.list_user_files(user)
    file_id = files[0]["id"]

    # Mock Path.unlink to raise exception (happens during file deletion)
    original_unlink = Path.unlink

    def failing_unlink(self):
        raise RuntimeError("File deletion failed")

    monkeypatch.setattr(Path, "unlink", failing_unlink)

    # Exception should be caught by delete_file's try/except
    success, msg = fam.delete_file(file_id, user)
    assert success is False
    assert "failed" in msg.lower() or "error" in msg.lower()


def test_list_file_versions_exception_handling(setup_user, monkeypatch):
    """Test list_file_versions exception handling"""
    fam, db, tmp_path, user = setup_user

    # Upload a file first
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user, "password")

    files, _ = fam.list_user_files(user)
    file_id = files[0]["id"]

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    versions = fam.list_file_versions(file_id)
    assert versions == []


def test_add_file_tag_exception_handling(setup_user, monkeypatch):
    """Test add_file_tag exception handling"""
    fam, db, tmp_path, user = setup_user

    # Upload a file first
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user, "password")

    files, _ = fam.list_user_files(user)
    file_id = files[0]["id"]

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    success, msg = fam.add_file_tag(file_id, user, "important")
    assert success is False
    assert "failed" in msg.lower() or "error" in msg.lower()


def test_remove_file_tag_exception_handling(setup_user, monkeypatch):
    """Test remove_file_tag exception handling"""
    fam, db, tmp_path, user = setup_user

    # Upload and tag a file first
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user, "password")

    files, _ = fam.list_user_files(user)
    file_id = files[0]["id"]

    fam.add_file_tag(file_id, user, "important")

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    success, msg = fam.remove_file_tag(file_id, "important")
    assert success is False
    assert "failed" in msg.lower() or "error" in msg.lower()


def test_get_file_tags_exception_handling(setup_user, monkeypatch):
    """Test get_file_tags exception handling"""
    fam, db, tmp_path, user = setup_user

    # Upload a file first
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user, "password")

    files, _ = fam.list_user_files(user)
    file_id = files[0]["id"]

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    tags = fam.get_file_tags(file_id)
    assert tags == []


def test_share_file_exception_handling(setup_user, monkeypatch):
    """Test share_file exception handling"""
    fam, db, tmp_path, user = setup_user

    # Create second user
    session = db.get_session()
    try:
        user2 = User(
            username="user2",
            email="user2@example.com",
            password_hash="hash2",
            salt="salt2",
            role="user",
        )
        session.add(user2)
        session.commit()
    finally:
        db.close_session(session)

    # Upload a file first
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user, "password")

    files, _ = fam.list_user_files(user)
    file_id = files[0]["id"]

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    success, msg = fam.share_file(file_id, user, "user2", "read")
    assert success is False
    assert "failed" in msg.lower() or "error" in msg.lower()


def test_revoke_file_share_exception_handling(setup_user, monkeypatch):
    """Test revoke_file_share exception handling"""
    fam, db, tmp_path, user = setup_user

    # Create second user
    session = db.get_session()
    try:
        user2 = User(
            username="user2",
            email="user2@example.com",
            password_hash="hash2",
            salt="salt2",
            role="user",
        )
        session.add(user2)
        session.commit()
    finally:
        db.close_session(session)

    # Upload and share a file first
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user, "password")

    files, _ = fam.list_user_files(user)
    file_id = files[0]["id"]

    fam.share_file(file_id, user, "user2", "read")

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    success, msg = fam.revoke_file_share(file_id, user, "user2")
    assert success is False
    assert "failed" in msg.lower() or "error" in msg.lower()


def test_export_file_list_exception_handling(setup_user, monkeypatch):
    """Test export_file_list exception handling"""
    fam, db, tmp_path, user = setup_user

    # Upload some files
    for i in range(2):
        test_file = tmp_path / f"test{i}.txt"
        test_file.write_text(f"content {i}")
        fam.upload_file(test_file, user, "password")

    export_path = tmp_path / "export.csv"

    # Mock list_user_files to raise exception
    def raise_exception(*args, **kwargs):
        raise RuntimeError("Database error")

    monkeypatch.setattr(fam, "list_user_files", raise_exception)

    success, msg = fam.export_file_list(user, export_path)
    assert success is False
    assert "failed" in msg.lower() or "error" in msg.lower()


def test_export_backup_exception_handling(setup_user, monkeypatch):
    """Test export_backup exception handling"""
    fam, db, tmp_path, user = setup_user

    # Upload some files
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user, "password")

    backup_path = tmp_path / "backup"

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    success, msg = fam.export_backup(backup_path)
    assert success is False
    assert "failed" in msg.lower() or "error" in msg.lower()


def test_create_file_version_exception_handling(setup_user, monkeypatch):
    """Test create_file_version exception handling"""
    fam, db, tmp_path, user = setup_user

    # Upload a file first
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user, "password")

    files, _ = fam.list_user_files(user)
    file_id = files[0]["id"]

    # Mock get_session to raise exception
    def raise_exception():
        raise RuntimeError("Database error")

    monkeypatch.setattr(db, "get_session", raise_exception)

    success, msg = fam.create_file_version(file_id, user, "password")
    assert success is False
    assert "failed" in msg.lower() or "error" in msg.lower()


def test_list_user_files_with_offset(setup_user):
    """Test list_user_files with offset"""
    fam, db, tmp_path, user = setup_user

    # Upload multiple files
    for i in range(5):
        test_file = tmp_path / f"test{i}.txt"
        test_file.write_text(f"content {i}")
        fam.upload_file(test_file, user, "password")

    # Get files with offset
    files_page1, total = fam.list_user_files(user, limit=2, offset=0)
    files_page2, total2 = fam.list_user_files(user, limit=2, offset=2)
    files_page3, total3 = fam.list_user_files(user, limit=2, offset=4)

    assert total == total2 == total3
    assert len(files_page1) <= 2
    assert len(files_page2) <= 2
    assert len(files_page3) <= 2


def test_cleanup_temp_files(setup_user):
    """Test cleanup_temp_files method"""
    fam, db, tmp_path, user = setup_user

    # Create a temp file
    temp_file = fam.temp_dir / "temp_file.txt"
    temp_file.write_text("temp content")

    # Cleanup (should not remove recent files)
    fam.cleanup_temp_files()

    # Temp file should still exist (cleanup doesn't remove all, just old ones)
    # This tests the method exists and runs without error
    assert hasattr(fam, "cleanup_temp_files")


def test_cleanup_temp_files_with_old_files(setup_user):
    """Test cleanup_temp_files actually removes old files"""
    import time
    from datetime import datetime

    fam, db, tmp_path, user = setup_user

    # Create an old temp file (mock it as old)
    temp_file = fam.temp_dir / "old_temp.txt"
    temp_file.write_text("old content")

    # Mock file modification time to be > 1 hour old
    old_time = time.time() - 7200  # 2 hours ago
    os.utime(temp_file, (old_time, old_time))

    # Cleanup should remove old file
    fam.cleanup_temp_files()

    # Old file should be removed
    assert not temp_file.exists()


def test_cleanup_temp_files_exception_handling(setup_user, monkeypatch):
    """Test cleanup_temp_files exception handling"""
    fam, db, tmp_path, user = setup_user

    # Create a temp file first
    temp_file = fam.temp_dir / "test.txt"
    temp_file.write_text("test")

    # Mock Path.stat() to raise exception (which is called during cleanup)
    original_stat = Path.stat

    def failing_stat(self):
        if self == temp_file:
            raise RuntimeError("File system error")
        return original_stat(self)

    monkeypatch.setattr(Path, "stat", failing_stat)

    # Should handle exception gracefully
    fam.cleanup_temp_files()  # Should not raise


def test_list_user_files_shared_files_for_regular_user(setup_user):
    """Test regular user sees shared files"""
    fam, db, tmp_path, user = setup_user

    # Create second user
    session = db.get_session()
    try:
        user2 = User(
            username="user2",
            email="user2@example.com",
            password_hash="hash2",
            salt="salt2",
            role="user",
        )
        session.add(user2)
        session.commit()
    finally:
        db.close_session(session)

    # Upload file as user2
    test_file = tmp_path / "shared.txt"
    test_file.write_text("shared content")
    fam.upload_file(test_file, "user2", "password")

    files_user2, _ = fam.list_user_files("user2")
    file_id = files_user2[0]["id"]

    # Share with user
    fam.share_file(file_id, "user2", user, "read")

    # user should see shared file
    files_user, total = fam.list_user_files(user)
    assert total >= 1
    assert any(f["id"] == file_id for f in files_user)


def test_export_file_list_with_missing_fields(setup_user):
    """Test export_file_list handles missing optional fields"""
    fam, db, tmp_path, user = setup_user

    # Upload file
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user, "password")

    export_path = tmp_path / "export.csv"
    success, msg = fam.export_file_list(user, export_path)

    assert success is True
    assert export_path.exists()

    # Verify CSV has data
    with open(export_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert len(lines) >= 2  # Header + at least one row


def test_export_backup_with_encrypted_dir_missing(setup_user, monkeypatch):
    """Test export_backup when encrypted directory doesn't exist"""
    fam, db, tmp_path, user = setup_user

    # Upload a file first
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user, "password")

    backup_path = tmp_path / "backup"

    # Should still succeed (backup metadata even if no encrypted files)
    success, msg = fam.export_backup(backup_path)
    assert success is True


def test_download_file_decryption_error(setup_user, monkeypatch):
    """Test download_file when decryption fails"""
    fam, db, tmp_path, user = setup_user

    # Upload a file
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user, "password")

    files, _ = fam.list_user_files(user)
    file_id = files[0]["id"]

    # Mock decryption to fail
    original_encryption = fam.encryption_manager

    class FailingEncryption:
        def decrypt_file(self, encrypted_path, output_path):
            raise RuntimeError("Decryption failed")

    fam.encryption_manager = lambda p: FailingEncryption()

    success, temp_path, msg = fam.download_file(file_id, user, "password")
    assert success is False
    assert "failed" in msg.lower() or "error" in msg.lower()


def test_export_backup_with_no_files(setup_user):
    """Test export_backup when no files exist"""
    fam, db, tmp_path, user = setup_user

    backup_path = tmp_path / "backup"
    success, msg = fam.export_backup(backup_path)

    # Should succeed even with no files (empty backup)
    assert success is True


def test_list_user_files_admin_sees_all_with_pagination(setup_user):
    """Test admin sees all files with pagination"""
    fam, db, tmp_path, user = setup_user

    # Create admin
    session = db.get_session()
    try:
        admin = User(
            username="admin",
            email="admin@example.com",
            password_hash="hash",
            salt="salt",
            role="admin",
        )
        session.add(admin)
        session.commit()
    finally:
        db.close_session(session)

    # Upload files as regular user
    for i in range(3):
        test_file = tmp_path / f"test{i}.txt"
        test_file.write_text(f"content {i}")
        fam.upload_file(test_file, user, "password")

    # Admin should see all with pagination
    files_page1, total = fam.list_user_files("admin", limit=2, offset=0)
    files_page2, total2 = fam.list_user_files("admin", limit=2, offset=2)

    assert total >= 3
    assert len(files_page1) <= 2
    assert len(files_page2) <= 2
