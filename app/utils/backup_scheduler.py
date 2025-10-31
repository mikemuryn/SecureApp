"""
Automated Backup Scheduler for SecureApp
Handles scheduled backups based on configuration
"""

import logging
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import schedule

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
        """Run the scheduler loop"""
        while self.running:
            schedule.run_pending()
            time.sleep(60)  # Check every minute

    def start(self) -> None:
        """Start the backup scheduler"""
        if not self.enabled:
            logger.info("Backup scheduler is disabled")
            return

        if self.running:
            logger.warning("Backup scheduler is already running")
            return

        # Schedule backup
        schedule.every(self.interval_hours).hours.do(self.create_backup)

        # Schedule first backup immediately
        self.create_backup()

        # Start scheduler thread
        self.running = True
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
        schedule.clear()
        logger.info("Backup scheduler stopped")

    def update_interval(self, hours: int) -> None:
        """Update backup interval"""
        self.interval_hours = hours
        if self.running:
            schedule.clear()
            schedule.every(self.interval_hours).hours.do(self.create_backup)
            logger.info(f"Backup interval updated to {hours} hours")

    def is_running(self) -> bool:
        """Check if scheduler is running"""
        return self.running

    def get_next_backup_time(self) -> Optional[datetime]:
        """Get the scheduled time for next backup"""
        if not self.running:
            return None

        jobs = schedule.get_jobs()
        if jobs:
            return jobs[0].next_run
        return None
