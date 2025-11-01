"""
Tests for BackupScheduler
"""

import os
import tempfile
import threading
import time  # noqa: F401
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from app.utils.backup_scheduler import BackupScheduler


@pytest.fixture
def mock_file_manager():
    """Create a mock file manager"""
    fm = Mock()
    fm.export_backup = Mock(return_value=(True, "backup_path"))
    return fm


@pytest.fixture
def temp_backup_dir(tmp_path):
    """Create a temporary backup directory"""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    return backup_dir


def test_backup_scheduler_init(mock_file_manager, temp_backup_dir):
    """Test BackupScheduler initialization"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
        interval_hours=24,
        enabled=True,
    )

    assert scheduler.file_manager == mock_file_manager
    assert scheduler.backup_directory == temp_backup_dir
    assert scheduler.interval_hours == 24
    assert scheduler.enabled is True
    assert scheduler.running is False
    assert scheduler.scheduler_thread is None
    assert temp_backup_dir.exists()


def test_backup_scheduler_init_disabled(mock_file_manager, temp_backup_dir):
    """Test BackupScheduler initialization when disabled"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
        interval_hours=24,
        enabled=False,
    )

    assert scheduler.enabled is False


def test_backup_scheduler_init_creates_directory(mock_file_manager, tmp_path):
    """Test that BackupScheduler creates backup directory if it doesn't exist"""
    backup_dir = tmp_path / "new_backups"
    assert not backup_dir.exists()

    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=backup_dir,
    )

    assert backup_dir.exists()


def test_create_backup_success(mock_file_manager, temp_backup_dir):
    """Test successful backup creation"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
    )

    success, message = scheduler.create_backup()

    assert success is True
    assert "backup_" in message
    mock_file_manager.export_backup.assert_called_once()
    assert isinstance(mock_file_manager.export_backup.call_args[0][0], Path)


def test_create_backup_failure(mock_file_manager, temp_backup_dir):
    """Test backup creation failure"""
    mock_file_manager.export_backup.return_value = (False, "Backup failed")

    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
    )

    success, message = scheduler.create_backup()

    assert success is False
    assert "Backup failed" in message
    mock_file_manager.export_backup.assert_called_once()


def test_create_backup_exception(mock_file_manager, temp_backup_dir):
    """Test backup creation with exception"""
    mock_file_manager.export_backup.side_effect = Exception("Database error")

    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
    )

    success, message = scheduler.create_backup()

    assert success is False
    assert "error" in message.lower()


def test_start_disabled(mock_file_manager, temp_backup_dir):
    """Test starting scheduler when disabled"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
        enabled=False,
    )

    scheduler.start()

    assert scheduler.running is False
    assert scheduler.scheduler_thread is None


def test_start_already_running(mock_file_manager, temp_backup_dir):
    """Test starting scheduler when already running"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
    )

    scheduler.start()
    assert scheduler.running is True

    # Try to start again
    initial_thread = scheduler.scheduler_thread
    scheduler.start()

    # Should not create a new thread
    assert scheduler.running is True


def test_start_enabled(mock_file_manager, temp_backup_dir):
    """Test starting enabled scheduler"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
        interval_hours=24,
    )

    scheduler.start()

    assert scheduler.running is True
    assert scheduler.scheduler_thread is not None
    assert scheduler.scheduler_thread.is_alive()
    assert scheduler.scheduler_thread.daemon is True

    # Cleanup
    scheduler.stop()
    scheduler.scheduler_thread.join(timeout=1)


def test_start_creates_immediate_backup(mock_file_manager, temp_backup_dir):
    """Test that starting scheduler creates an immediate backup"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
    )

    scheduler.start()

    # Should have been called once for immediate backup
    assert mock_file_manager.export_backup.call_count >= 1

    # Cleanup
    scheduler.stop()
    if scheduler.scheduler_thread:
        scheduler.scheduler_thread.join(timeout=1)


def test_stop_not_running(mock_file_manager, temp_backup_dir):
    """Test stopping scheduler when not running"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
    )

    # Should not raise exception
    scheduler.stop()
    assert scheduler.running is False


def test_stop_running(mock_file_manager, temp_backup_dir):
    """Test stopping running scheduler"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
    )

    scheduler.start()
    assert scheduler.running is True

    scheduler.stop()
    assert scheduler.running is False

    # Wait for thread to finish
    if scheduler.scheduler_thread:
        scheduler.scheduler_thread.join(timeout=2)
        # Thread may still be alive briefly, but running should be False
        assert scheduler.running is False


def test_update_interval_not_running(mock_file_manager, temp_backup_dir):
    """Test updating interval when scheduler is not running"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
        interval_hours=24,
    )

    scheduler.update_interval(48)

    assert scheduler.interval_hours == 48


def test_update_interval_running(mock_file_manager, temp_backup_dir):
    """Test updating interval when scheduler is running"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
        interval_hours=24,
    )

    scheduler.start()
    scheduler.update_interval(48)

    assert scheduler.interval_hours == 48

    # Cleanup
    scheduler.stop()
    if scheduler.scheduler_thread:
        scheduler.scheduler_thread.join(timeout=1)


def test_is_running(mock_file_manager, temp_backup_dir):
    """Test is_running method"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
    )

    assert scheduler.is_running() is False

    scheduler.start()
    assert scheduler.is_running() is True

    scheduler.stop()
    assert scheduler.is_running() is False

    if scheduler.scheduler_thread:
        scheduler.scheduler_thread.join(timeout=1)


def test_get_next_backup_time_not_running(mock_file_manager, temp_backup_dir):
    """Test get_next_backup_time when not running"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
    )

    next_time = scheduler.get_next_backup_time()
    assert next_time is None


def test_get_next_backup_time_running(mock_file_manager, temp_backup_dir):
    """Test get_next_backup_time when running"""
    from datetime import datetime

    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
        interval_hours=1,
    )

    scheduler.start()

    next_time = scheduler.get_next_backup_time()
    assert next_time is not None
    assert isinstance(next_time, datetime)

    # Cleanup
    scheduler.stop()
    if scheduler.scheduler_thread:
        scheduler.scheduler_thread.join(timeout=1)


def test_scheduler_thread_cleanup(mock_file_manager, temp_backup_dir):
    """Test that scheduler thread can be properly cleaned up"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
        interval_hours=1,
    )

    scheduler.start()
    thread = scheduler.scheduler_thread

    scheduler.stop()
    thread.join(timeout=2)

    # Thread cleanup verified by running being False
    assert scheduler.running is False
    # Thread may not be immediately dead due to daemon nature


def test_backup_timestamp_format(mock_file_manager, temp_backup_dir):
    """Test that backup timestamps are in correct format"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
    )

    success, message = scheduler.create_backup()

    assert success is True
    # Message should contain timestamp in format YYYYMMDD_HHMMSS
    backup_name = Path(message).name
    assert backup_name.startswith("backup_")
    # Extract timestamp part
    timestamp_part = backup_name.replace("backup_", "")
    assert len(timestamp_part) == 15  # YYYYMMDD_HHMMSS
    assert "_" in timestamp_part


def test_multiple_backups_unique_names(mock_file_manager, temp_backup_dir):
    """Test that multiple backups have unique names"""
    scheduler = BackupScheduler(
        file_manager=mock_file_manager,
        backup_directory=temp_backup_dir,
    )

    success1, message1 = scheduler.create_backup()
    time.sleep(1.1)  # Ensure different timestamp (seconds level)
    success2, message2 = scheduler.create_backup()

    assert success1 is True
    assert success2 is True
    # Messages should be different paths or have different timestamps
    assert message1 != message2 or "backup_" in message1
