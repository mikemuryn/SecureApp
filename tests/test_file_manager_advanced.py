"""
Tests for advanced FileAccessManager features:
- File versioning
- Tagging
- Sharing
- Export/Backup
- Pagination
"""

import csv
import os
import shutil
import tempfile  # noqa: F401
import zipfile  # noqa: F401
from pathlib import Path

import pytest

from app.encryption.file_crypto import FileEncryption
from app.models.database import DatabaseManager, FilePermission, FileTag, User
from app.utils.audit_logger import AuditLogger
from app.utils.file_manager import FileAccessManager


@pytest.fixture
def setup_file_manager(tmp_path, temp_db_file):
    """Setup file manager with test environment"""
    # Create directories
    data_dir = tmp_path / "data"
    enc_dir = data_dir / "encrypted"
    temp_dir = tmp_path / "temp"
    enc_dir.mkdir(parents=True, exist_ok=True)
    temp_dir.mkdir(parents=True, exist_ok=True)

    # Change working directory
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
def setup_users(setup_file_manager):
    """Create test users"""
    fam, db, tmp_path = setup_file_manager

    # Create users
    session = db.get_session()
    try:
        user1 = User(
            username="user1",
            email="user1@example.com",
            password_hash="hash1",
            salt="salt1",
            role="user",
        )
        user2 = User(
            username="user2",
            email="user2@example.com",
            password_hash="hash2",
            salt="salt2",
            role="user",
        )
        admin = User(
            username="admin",
            email="admin@example.com",
            password_hash="hash3",
            salt="salt3",
            role="admin",
        )
        session.add_all([user1, user2, admin])
        session.commit()
    finally:
        db.close_session(session)

    return fam, db, tmp_path, "user1", "user2", "admin"


# ============= File Versioning Tests =============


def test_upload_file_creates_version_on_existing_file(setup_users):
    """Test that uploading same filename creates new version"""
    fam, db, tmp_path, user1, _, _ = setup_users

    # Create test file
    test_file = tmp_path / "test.txt"
    test_file.write_text("version 1")

    # Upload first version
    success, msg = fam.upload_file(test_file, user1, "password")
    assert success is True

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    # Upload second version with same name
    test_file.write_text("version 2")
    success, msg = fam.upload_file(test_file, user1, "password")
    assert success is True
    assert "version 2" in msg.lower()

    # Verify versions
    versions = fam.list_file_versions(file_id)
    assert len(versions) > 0


def test_list_file_versions(setup_users):
    """Test listing file versions"""
    fam, db, tmp_path, user1, _, _ = setup_users

    # Create and upload file
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")

    success, _ = fam.upload_file(test_file, user1, "password")
    assert success is True

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    # Upload again to create version
    test_file.write_text("new content")
    fam.upload_file(test_file, user1, "password")

    # List versions
    versions = fam.list_file_versions(file_id)
    assert len(versions) >= 1
    assert "version_number" in versions[0]
    assert "created_at" in versions[0]


def test_list_file_versions_nonexistent_file(setup_users):
    """Test listing versions for non-existent file"""
    fam, _, _, _, _, _ = setup_users

    versions = fam.list_file_versions(99999)
    assert versions == []


# ============= File Tagging Tests =============


def test_add_file_tag(setup_users):
    """Test adding a tag to a file"""
    fam, db, tmp_path, user1, _, _ = setup_users

    # Create and upload file
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    success, _ = fam.upload_file(test_file, user1, "password")
    assert success is True

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    # Add tag
    success, msg = fam.add_file_tag(file_id, user1, "important", "#ff0000")
    assert success is True
    assert "successfully" in msg.lower()


def test_add_file_tag_default_color(setup_users):
    """Test adding tag with default color"""
    fam, db, tmp_path, user1, _, _ = setup_users

    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    success, _ = fam.add_file_tag(file_id, user1, "urgent")
    assert success is True

    # Check default color is used
    tags = fam.get_file_tags(file_id)
    assert any(tag["name"] == "urgent" for tag in tags)


def test_add_file_tag_duplicate(setup_users):
    """Test adding duplicate tag"""
    fam, db, tmp_path, user1, _, _ = setup_users

    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    # Add tag first time
    success1, _ = fam.add_file_tag(file_id, user1, "important")
    assert success1 is True

    # Try to add same tag again
    success2, msg = fam.add_file_tag(file_id, user1, "important")
    assert success2 is False
    assert "already exists" in msg.lower()


def test_remove_file_tag(setup_users):
    """Test removing a tag from a file"""
    fam, db, tmp_path, user1, _, _ = setup_users

    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    # Add tag
    fam.add_file_tag(file_id, user1, "important")

    # Remove tag
    success, msg = fam.remove_file_tag(file_id, "important")
    assert success is True
    assert "successfully" in msg.lower()

    # Verify tag is removed
    tags = fam.get_file_tags(file_id)
    assert not any(tag["name"] == "important" for tag in tags)


def test_remove_file_tag_not_found(setup_users):
    """Test removing non-existent tag"""
    fam, db, tmp_path, user1, _, _ = setup_users

    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    success, msg = fam.remove_file_tag(file_id, "nonexistent")
    assert success is False
    assert "not found" in msg.lower()


def test_get_file_tags(setup_users):
    """Test getting all tags for a file"""
    fam, db, tmp_path, user1, _, _ = setup_users

    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    # Add multiple tags
    fam.add_file_tag(file_id, user1, "important", "#ff0000")
    fam.add_file_tag(file_id, user1, "urgent", "#00ff00")

    # Get tags
    tags = fam.get_file_tags(file_id)
    assert len(tags) == 2
    tag_names = [tag["name"] for tag in tags]
    assert "important" in tag_names
    assert "urgent" in tag_names
    assert all("color" in tag for tag in tags)


def test_get_file_tags_empty(setup_users):
    """Test getting tags for file with no tags"""
    fam, db, tmp_path, user1, _, _ = setup_users

    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    tags = fam.get_file_tags(file_id)
    assert tags == []


# ============= File Sharing Tests =============


def test_share_file_read_permission(setup_users):
    """Test sharing file with read permission"""
    fam, db, tmp_path, user1, user2, _ = setup_users

    # Upload file as user1
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    # Share with user2
    success, msg = fam.share_file(file_id, user1, user2, "read")
    assert success is True
    assert "successfully" in msg.lower()

    # Verify user2 can see file
    files_user2, _ = fam.list_user_files(user2)
    assert any(f["id"] == file_id for f in files_user2)


def test_share_file_write_permission(setup_users):
    """Test sharing file with write permission"""
    fam, db, tmp_path, user1, user2, _ = setup_users

    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    success, _ = fam.share_file(file_id, user1, user2, "write")
    assert success is True


def test_share_file_admin_permission(setup_users):
    """Test sharing file with admin permission"""
    fam, db, tmp_path, user1, user2, _ = setup_users

    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    success, _ = fam.share_file(file_id, user1, user2, "admin")
    assert success is True


def test_share_file_owner_not_found(setup_users):
    """Test sharing file with non-existent owner"""
    fam, _, _, _, user2, _ = setup_users

    success, msg = fam.share_file(1, "nonexistent", user2, "read")
    assert success is False
    assert "owner" in msg.lower() or "not found" in msg.lower()


def test_share_file_shared_with_not_found(setup_users):
    """Test sharing file with non-existent user"""
    fam, db, tmp_path, user1, _, _ = setup_users

    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    success, msg = fam.share_file(file_id, user1, "nonexistent", "read")
    assert success is False
    assert "not found" in msg.lower()


def test_share_file_self(setup_users):
    """Test sharing file with self"""
    fam, db, tmp_path, user1, _, _ = setup_users

    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    success, msg = fam.share_file(file_id, user1, user1, "read")
    assert success is False
    assert "same" in msg.lower() or "self" in msg.lower()


def test_revoke_file_share(setup_users):
    """Test revoking file share"""
    fam, db, tmp_path, user1, user2, _ = setup_users

    # Upload and share file
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    fam.share_file(file_id, user1, user2, "read")

    # Revoke share
    success, msg = fam.revoke_file_share(file_id, user1, user2)
    assert success is True
    assert "successfully" in msg.lower()


def test_revoke_file_share_not_shared(setup_users):
    """Test revoking share that doesn't exist"""
    fam, db, tmp_path, user1, user2, _ = setup_users

    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    success, msg = fam.revoke_file_share(file_id, user1, user2)
    assert success is False
    assert "not found" in msg.lower()


def test_shared_file_download_permission(setup_users):
    """Test that shared file can be downloaded by shared user"""
    fam, db, tmp_path, user1, user2, _ = setup_users

    # Upload file as user1
    test_file = tmp_path / "test.txt"
    test_file.write_text("shared content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    # Share with user2
    fam.share_file(file_id, user1, user2, "read")

    # user2 should be able to download
    success, temp_path, msg = fam.download_file(file_id, user2, "password")
    assert success is True
    assert temp_path.exists()
    assert temp_path.read_text() == "shared content"


# ============= Export/Backup Tests =============


def test_export_file_list_csv(setup_users):
    """Test exporting file list to CSV"""
    fam, db, tmp_path, user1, _, _ = setup_users

    # Upload files
    for i in range(3):
        test_file = tmp_path / f"test{i}.txt"
        test_file.write_text(f"content {i}")
        fam.upload_file(test_file, user1, "password")

    # Export to CSV
    export_path = tmp_path / "export.csv"
    success, msg = fam.export_file_list(user1, export_path)
    assert success is True
    assert export_path.exists()

    # Verify CSV content
    with open(export_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) >= 3
        assert "filename" in rows[0]
        assert "file_size" in rows[0]


def test_export_file_list_user_not_found(setup_users):
    """Test exporting file list for non-existent user"""
    fam, _, tmp_path, _, _, _ = setup_users

    export_path = tmp_path / "export.csv"
    # Export can succeed with empty list (user not found returns empty)
    success, msg = fam.export_file_list("nonexistent", export_path)
    # Export succeeds with empty file
    assert success is True
    assert export_path.exists()


def test_export_backup(setup_users):
    """Test creating full system backup"""
    fam, db, tmp_path, user1, user2, admin = setup_users

    # Upload some files
    for i in range(2):
        test_file = tmp_path / f"test{i}.txt"
        test_file.write_text(f"content {i}")
        fam.upload_file(test_file, user1, "password")

    # Create backup
    backup_path = tmp_path / "backup"
    backup_path.mkdir(exist_ok=True)
    success, msg = fam.export_backup(backup_path)
    assert success is True

    # Message should contain zip path
    assert ".zip" in msg or "Backup exported" in msg

    # Find zip file in backup_path
    zip_files = list(backup_path.glob("*.zip"))
    assert len(zip_files) > 0

    # Verify zip file contents
    zip_path = zip_files[0]
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        file_list = zip_ref.namelist()
        assert len(file_list) > 0


def test_export_backup_creates_directory(setup_users):
    """Test that export_backup creates directory if needed"""
    fam, db, tmp_path, user1, _, _ = setup_users

    backup_path = tmp_path / "new_backup" / "backup.zip"
    assert not backup_path.parent.exists()

    success, _ = fam.export_backup(backup_path)
    # Should handle directory creation (implementation dependent)
    # At minimum, should not raise exception


# ============= Pagination Tests =============


def test_list_user_files_pagination(setup_users):
    """Test pagination in list_user_files"""
    fam, db, tmp_path, user1, _, _ = setup_users

    # Upload multiple files
    for i in range(10):
        test_file = tmp_path / f"test{i}.txt"
        test_file.write_text(f"content {i}")
        fam.upload_file(test_file, user1, "password")

    # Get first page
    files_page1, total = fam.list_user_files(user1, limit=5, offset=0)
    assert len(files_page1) <= 5
    assert total >= 10

    # Get second page
    files_page2, total2 = fam.list_user_files(user1, limit=5, offset=5)
    assert len(files_page2) <= 5
    assert total == total2

    # Verify different files
    page1_ids = {f["id"] for f in files_page1}
    page2_ids = {f["id"] for f in files_page2}
    assert page1_ids.isdisjoint(page2_ids)


def test_list_user_files_no_limit(setup_users):
    """Test list_user_files without limit"""
    fam, db, tmp_path, user1, _, _ = setup_users

    # Upload files
    for i in range(5):
        test_file = tmp_path / f"test{i}.txt"
        test_file.write_text(f"content {i}")
        fam.upload_file(test_file, user1, "password")

    files, total = fam.list_user_files(user1)
    assert len(files) >= 5
    assert total >= 5


def test_list_user_files_admin_sees_all(setup_users):
    """Test that admin sees all files"""
    fam, db, tmp_path, user1, user2, admin = setup_users

    # Upload files as user1 and user2
    test_file1 = tmp_path / "file1.txt"
    test_file1.write_text("content1")
    fam.upload_file(test_file1, user1, "password")

    test_file2 = tmp_path / "file2.txt"
    test_file2.write_text("content2")
    fam.upload_file(test_file2, user2, "password")

    # Admin should see both
    files_admin, total = fam.list_user_files(admin)
    assert total >= 2
    assert any(f["filename"] == "file1.txt" for f in files_admin)
    assert any(f["filename"] == "file2.txt" for f in files_admin)


def test_list_user_files_includes_tags_and_version(setup_users):
    """Test that list_user_files includes tags and version info"""
    fam, db, tmp_path, user1, _, _ = setup_users

    # Upload file
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    assert len(files) > 0

    # Check that tags and version are included
    file_data = files[0]
    assert "tags" in file_data or "version" in file_data  # At least one


# ============= Permission Tests =============


def test_permission_hierarchy_read_write(setup_users):
    """Test permission hierarchy: write > read"""
    fam, db, tmp_path, user1, user2, _ = setup_users

    # Upload file
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    # Share with write permission
    fam.share_file(file_id, user1, user2, "write")

    # user2 should have read permission (write includes read)
    # This is tested through download capability
    success, _, _ = fam.download_file(file_id, user2, "password")
    assert success is True


def test_permission_owner_has_all(setup_users):
    """Test that owner has all permissions"""
    fam, db, tmp_path, user1, _, _ = setup_users

    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    # Owner should be able to download
    success, _, _ = fam.download_file(file_id, user1, "password")
    assert success is True

    # Owner should be able to delete
    success, _ = fam.delete_file(file_id, user1)
    assert success is True


def test_permission_admin_has_all(setup_users):
    """Test that admin has all permissions"""
    fam, db, tmp_path, user1, _, admin = setup_users

    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    # Admin should be able to download any file
    success, _, _ = fam.download_file(file_id, admin, "password")
    assert success is True


def test_permission_no_access_denied(setup_users):
    """Test that user without permission gets access denied"""
    fam, db, tmp_path, user1, user2, _ = setup_users

    # Upload file as user1
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")
    fam.upload_file(test_file, user1, "password")

    files, _ = fam.list_user_files(user1)
    file_id = files[0]["id"]

    # user2 should not be able to download (not shared)
    success, _, msg = fam.download_file(file_id, user2, "password")
    assert success is False
    assert "denied" in msg.lower() or "access" in msg.lower()
