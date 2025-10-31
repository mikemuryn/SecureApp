"""
File Access Control Module
Handles secure file operations and permissions
"""

import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class FileAccessManager:
    """Manages secure file access and permissions"""

    def __init__(
        self,
        db_manager: Any,
        encryption_manager: Any,
        audit_logger: Any,
    ) -> None:
        self.db_manager = db_manager
        self.encryption_manager = encryption_manager
        self.audit_logger = audit_logger
        self.temp_dir = Path("temp")
        self.temp_dir.mkdir(exist_ok=True)

    def upload_file(
        self, file_path: Path, username: str, password: str
    ) -> tuple[bool, str]:
        """
        Upload and encrypt a file

        Args:
            file_path: Path to file to upload
            username: Username uploading the file
            password: User password for encryption

        Returns:
            (success, message)
        """
        try:
            # Validate file
            if not file_path.exists():
                return False, "File does not exist"

            if file_path.stat().st_size > 100 * 1024 * 1024:  # 100MB limit
                return False, "File too large (max 100MB)"

            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)

            # Check if file already exists
            session = self.db_manager.get_session()
            try:
                from ..models.database import SecureFile, User

                user = session.query(User).filter(User.username == username).first()
                if not user:
                    return False, "User not found"

                existing_file = (
                    session.query(SecureFile)
                    .filter(SecureFile.file_hash == file_hash)
                    .first()
                )

                if existing_file:
                    return False, "File already exists in system"

                # Encrypt file
                encrypted_path = Path("data/encrypted") / f"{file_path.name}.enc"
                encryption = self.encryption_manager(password)
                encryption.encrypt_file(file_path, encrypted_path)

                # Save file record
                secure_file = SecureFile(
                    filename=file_path.name,
                    original_path=str(file_path),
                    encrypted_path=str(encrypted_path),
                    file_hash=file_hash,
                    file_size=file_path.stat().st_size,
                    owner_id=user.id,
                    is_encrypted=True,
                )

                session.add(secure_file)
                session.commit()

                # Log the event
                self.audit_logger.log_file_access(
                    username, file_path.name, "upload", True
                )

                logger.info(
                    f"File uploaded successfully: {file_path.name} by {username}"
                )
                return True, "File uploaded and encrypted successfully"

            finally:
                self.db_manager.close_session(session)

        except Exception as e:
            logger.error(f"File upload failed: {e}")
            self.audit_logger.log_file_access(username, str(file_path), "upload", False)
            return False, f"Upload failed: {str(e)}"

    def download_file(
        self, file_id: int, username: str, password: str
    ) -> tuple[bool, Optional[Path], str]:
        """
        Download and decrypt a file

        Args:
            file_id: File ID to download
            username: Username downloading the file
            password: User password for decryption

        Returns:
            (success, temp_file_path, message)
        """
        try:
            session = self.db_manager.get_session()
            try:
                from ..models.database import SecureFile, User

                user = session.query(User).filter(User.username == username).first()
                if not user:
                    return False, None, "User not found"

                secure_file = (
                    session.query(SecureFile).filter(SecureFile.id == file_id).first()
                )

                if not secure_file:
                    return False, None, "File not found"

                # Check permissions
                if not self._has_file_permission(user, secure_file, "read"):
                    self.audit_logger.log_file_access(
                        username, secure_file.filename, "download", False
                    )
                    return False, None, "Access denied"

                # Decrypt file to temporary location
                encrypted_path = Path(secure_file.encrypted_path)
                temp_file_path = self.temp_dir / secure_file.filename

                encryption = self.encryption_manager(password)
                encryption.decrypt_file(encrypted_path, temp_file_path)

                # Update access statistics
                secure_file.last_accessed = datetime.utcnow()
                secure_file.access_count += 1
                session.commit()

                # Log the event
                self.audit_logger.log_file_access(
                    username, secure_file.filename, "download", True
                )

                logger.info(f"File downloaded: {secure_file.filename} by {username}")
                return True, temp_file_path, "File downloaded successfully"

            finally:
                self.db_manager.close_session(session)

        except Exception as e:
            logger.error(f"File download failed: {e}")
            self.audit_logger.log_file_access(
                username, f"file_id:{file_id}", "download", False
            )
            return False, None, f"Download failed: {str(e)}"

    def list_user_files(self, username: str) -> List[Dict]:
        """
        List files accessible to user

        Args:
            username: Username

        Returns:
            List of file information dictionaries
        """
        try:
            session = self.db_manager.get_session()
            try:
                from ..models.database import SecureFile, User

                user = session.query(User).filter(User.username == username).first()
                if not user:
                    return []

                # Admin users can see all files
                if user.role == "admin":
                    all_files = session.query(SecureFile).all()
                    files = []
                    for file in all_files:
                        files.append(
                            {
                                "id": file.id,
                                "filename": file.filename,
                                "size": file.file_size,
                                "created_at": file.created_at,
                                "last_accessed": file.last_accessed,
                                "access_count": file.access_count,
                                "owner": file.owner.username,
                            }
                        )
                    return files

                # Regular users see only their own files
                owned_files = (
                    session.query(SecureFile)
                    .filter(SecureFile.owner_id == user.id)
                    .all()
                )

                # Get files with permissions
                # TODO: Implement permission-based file access

                files = []
                for file in owned_files:
                    files.append(
                        {
                            "id": file.id,
                            "filename": file.filename,
                            "size": file.file_size,
                            "created_at": file.created_at,
                            "last_accessed": file.last_accessed,
                            "access_count": file.access_count,
                            "owner": file.owner.username,
                        }
                    )

                return files

            finally:
                self.db_manager.close_session(session)

        except Exception as e:
            logger.error(f"Failed to list files for {username}: {e}")
            return []

    def delete_file(self, file_id: int, username: str) -> tuple[bool, str]:
        """
        Delete a file

        Args:
            file_id: File ID to delete
            username: Username requesting deletion

        Returns:
            (success, message)
        """
        try:
            session = self.db_manager.get_session()
            try:
                from ..models.database import SecureFile, User

                user = session.query(User).filter(User.username == username).first()
                if not user:
                    return False, "User not found"

                secure_file = (
                    session.query(SecureFile).filter(SecureFile.id == file_id).first()
                )

                if not secure_file:
                    return False, "File not found"

                # Check permissions (only owner or admin can delete)
                if secure_file.owner_id != user.id and user.role != "admin":
                    self.audit_logger.log_file_access(
                        username, secure_file.filename, "delete", False
                    )
                    return False, "Access denied"

                # Delete encrypted file
                encrypted_path = Path(secure_file.encrypted_path)
                if encrypted_path.exists():
                    encrypted_path.unlink()

                # Remove from database
                session.delete(secure_file)
                session.commit()

                # Log the event
                self.audit_logger.log_file_access(
                    username, secure_file.filename, "delete", True
                )

                logger.info(f"File deleted: {secure_file.filename} by {username}")
                return True, "File deleted successfully"

            finally:
                self.db_manager.close_session(session)

        except Exception as e:
            logger.error(f"File deletion failed: {e}")
            self.audit_logger.log_file_access(
                username, f"file_id:{file_id}", "delete", False
            )
            return False, f"Deletion failed: {str(e)}"

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def _has_file_permission(self, user: Any, file: Any, permission_type: str) -> bool:
        """Check if user has permission for file"""
        # Owner always has all permissions
        if file.owner_id == user.id:
            return True

        # Admin has all permissions
        if user.role == "admin":
            return True

        # TODO: Implement role-based permissions
        return False

    def cleanup_temp_files(self) -> None:
        """Clean up temporary files older than 1 hour"""
        try:
            current_time = datetime.utcnow()
            for temp_file in self.temp_dir.iterdir():
                if temp_file.is_file():
                    file_age = current_time - datetime.fromtimestamp(
                        temp_file.stat().st_mtime
                    )
                    if file_age.total_seconds() > 3600:  # 1 hour
                        temp_file.unlink()
                        logger.info(f"Cleaned up temp file: {temp_file.name}")
        except Exception as e:
            logger.error(f"Failed to cleanup temp files: {e}")
