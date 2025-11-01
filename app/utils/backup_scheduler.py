"""
Automated Backup Scheduler for SecureApp
Handles scheduled backups based on configuration
"""

import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class BackupScheduler:
    """Handles automated backup scheduling"""

    def __init__(
        self,
        file_manager: Any,
        backup_directory: Path,
        interval_hours: int = 24,
        enabled: bool = True,
    ):
        """
        Initialize backup scheduler

        Args:
            file_manager: FileAccessManager instance
            backup_directory: Directory to store backups
            interval_hours: Hours between backups (default: 24)
            enabled: Whether scheduler is enabled (default: True)
        """
        self.file_manager = file_manager
        self.backup_directory = Path(backup_directory)
        self.interval_hours = interval_hours
        self.enabled = enabled
        self.running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._next_run: Optional[datetime] = None

        # Create backup directory if it doesn't exist
        self.backup_directory.mkdir(parents=True, exist_ok=True)

    def create_backup(self) -> tuple[bool, str]:
        """
        Create a backup

        Returns:
            Tuple of (success, message/path)
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.backup_directory / f"backup_{timestamp}"

            success, message = self.file_manager.export_backup(backup_path)
            if success:
                logger.info(f"Automated backup created: {backup_path}")
                return True, str(backup_path)
            else:
                logger.error(f"Automated backup failed: {message}")
                return False, message

        except Exception as e:
            error_msg = f"Backup creation error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def _run_scheduler(self) -> None:
        """Run the scheduler loop waiting for the next backup interval."""
        while not self._stop_event.is_set():
            if self._next_run is None:
                self._next_run = datetime.utcnow() + timedelta(
                    hours=self.interval_hours
                )

            now = datetime.utcnow()
            wait_seconds = max(0.0, (self._next_run - now).total_seconds())
            if self._stop_event.wait(timeout=wait_seconds):
                break

            if self._stop_event.is_set():
                break

            # Time reached; perform backup and schedule next run
            self.create_backup()
            self._next_run = datetime.utcnow() + timedelta(hours=self.interval_hours)

    def start(self) -> None:
        """Start the backup scheduler"""
        if not self.enabled:
            logger.info("Backup scheduler is disabled")
            return

        if self.running:
            logger.warning("Backup scheduler is already running")
            return

        # Perform immediate backup
        self.create_backup()

        self.running = True
        self._stop_event.clear()
        self._next_run = datetime.utcnow() + timedelta(hours=self.interval_hours)
        self.scheduler_thread = threading.Thread(
            target=self._run_scheduler, daemon=True
        )
        self.scheduler_thread.start()

        logger.info(
            f"Backup scheduler started: backups every {self.interval_hours} hours"
        )

    def stop(self) -> None:
        """Stop the backup scheduler"""
        if not self.running:
            return

        self.running = False
        self._stop_event.set()
        self._next_run = None
        logger.info("Backup scheduler stopped")

        if self.scheduler_thread and self.scheduler_thread.is_alive():
            self.scheduler_thread.join(timeout=2)

    def update_interval(self, hours: int) -> None:
        """Update backup interval"""
        self.interval_hours = hours
        if self.running:
            self._next_run = datetime.utcnow() + timedelta(hours=self.interval_hours)
            logger.info(f"Backup interval updated to {hours} hours")

    def is_running(self) -> bool:
        """Check if scheduler is running"""
        return self.running

    def get_next_backup_time(self) -> Optional[datetime]:
        """Get the scheduled time for next backup"""
        if not self.running:
            return None

        return self._next_run
