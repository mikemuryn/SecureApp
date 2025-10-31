"""
File Access Control Module
Handles secure file operations and permissions
"""

import csv
import hashlib
import json
import logging
import shutil
import zipfile
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

                # Check if file with same name exists (for versioning)
                existing_file = (
                    session.query(SecureFile)
                    .filter(
                        SecureFile.filename == file_path.name,
                        SecureFile.owner_id == user.id,
                        SecureFile.is_current_version == True,  # noqa: E712
                    )
                    .first()
                )

                # If same filename exists, create new version instead of error
                if existing_file:
                    # Mark old version as not current
                    existing_file.is_current_version = False
                    # Create version record
                    from ..models.database import FileVersion

                    # Get next version number
                    max_version = (
                        session.query(FileVersion)
                        .filter(FileVersion.file_id == existing_file.id)
                        .order_by(FileVersion.version_number.desc())
                        .first()
                    )
                    next_version = (
                        (max_version.version_number + 1) if max_version else 2
                    )

                    # Encrypt new version
                    encrypted_path = (
                        Path("data/encrypted") / f"{file_path.name}.v{next_version}.enc"
                    )
                    encryption = self.encryption_manager(password)
                    encryption.encrypt_file(file_path, encrypted_path)

                    # Create version record
                    file_version = FileVersion(
                        file_id=existing_file.id,
                        version_number=next_version,
                        encrypted_path=str(encrypted_path),
                        file_hash=file_hash,
                        file_size=file_path.stat().st_size,
                        created_by=user.id,
                    )
                    session.add(file_version)

                    # Update main file record
                    existing_file.encrypted_path = str(encrypted_path)
                    existing_file.file_hash = file_hash
                    existing_file.file_size = file_path.stat().st_size
                    existing_file.is_current_version = True
                    existing_file.last_accessed = None  # Reset access time

                    session.commit()

                    # Log the event
                    self.audit_logger.log_file_access(
                        username, file_path.name, "upload_version", True
                    )

                    logger.info(
                        f"File version {next_version} uploaded: "
                        f"{file_path.name} by {username}"
                    )
                    return True, f"File version {next_version} uploaded successfully"

                # Check for exact duplicate (same hash)
                duplicate_file = (
                    session.query(SecureFile)
                    .filter(SecureFile.file_hash == file_hash)
                    .first()
                )

                if duplicate_file:
                    return False, "Exact duplicate file already exists in system"

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
                if not self._has_file_permission(session, user, secure_file, "read"):
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

                # Admin users can see all files (current versions only)
                if user.role == "admin":
                    all_files = (
                        session.query(SecureFile)
                        .filter(SecureFile.is_current_version == True)  # noqa: E712
                        .all()
                    )
                    files = []
                    for file in all_files:
                        tags = [tag.tag_name for tag in file.tags]
                        files.append(
                            {
                                "id": file.id,
                                "filename": file.filename,
                                "size": file.file_size,
                                "created_at": file.created_at,
                                "last_accessed": file.last_accessed,
                                "access_count": file.access_count,
                                "owner": file.owner.username,
                                "tags": tags,
                                "version": file.version,
                            }
                        )
                    return files

                # Regular users see only their own files (current versions only)
                owned_files = (
                    session.query(SecureFile)
                    .filter(
                        SecureFile.owner_id == user.id,
                        SecureFile.is_current_version == True,  # noqa: E712
                    )
                    .all()
                )

                files = []
                for file in owned_files:
                    tags = [tag.tag_name for tag in file.tags]
                    files.append(
                        {
                            "id": file.id,
                            "filename": file.filename,
                            "size": file.file_size,
                            "created_at": file.created_at,
                            "last_accessed": file.last_accessed,
                            "access_count": file.access_count,
                            "owner": file.owner.username,
                            "tags": tags,
                            "version": file.version,
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

    def _has_file_permission(
        self, session: Any, user: Any, file: Any, permission_type: str
    ) -> bool:
        """Check if user has permission for file"""
        # Owner always has all permissions
        if file.owner_id == user.id:
            return True

        # Admin has all permissions
        if user.role == "admin":
            return True

        # Check FilePermission model for shared files
        from ..models.database import FilePermission

        permission = (
            session.query(FilePermission)
            .filter(
                FilePermission.file_id == file.id,
                FilePermission.user_id == user.id,
            )
            .first()
        )

        if permission:
            # Permission hierarchy: admin > write > read
            permission_hierarchy = {"read": 1, "write": 2, "admin": 3}
            user_permission_level = permission_hierarchy.get(
                permission.permission_type, 0
            )
            required_level = permission_hierarchy.get(permission_type, 0)
            if user_permission_level >= required_level:
                return True

        return False

    def create_file_version(
        self, file_id: int, username: str, password: str, notes: Optional[str] = None
    ) -> tuple[bool, str]:
        """Create a new version of an existing file"""
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

                # Create version record before uploading new version
                # This will be handled during upload_file when file already exists
                return True, "Version creation handled during upload"

            finally:
                self.db_manager.close_session(session)
        except Exception as e:
            logger.error(f"Version creation failed: {e}")
            return False, f"Version creation failed: {str(e)}"

    def list_file_versions(self, file_id: int) -> List[Dict]:
        """List all versions of a file"""
        try:
            session = self.db_manager.get_session()
            try:
                from ..models.database import FileVersion, SecureFile

                secure_file = (
                    session.query(SecureFile).filter(SecureFile.id == file_id).first()
                )
                if not secure_file:
                    return []

                # Get all versions
                versions = (
                    session.query(FileVersion)
                    .filter(FileVersion.file_id == file_id)
                    .order_by(FileVersion.version_number.desc())
                    .all()
                )

                result = []
                for version in versions:
                    result.append(
                        {
                            "id": version.id,
                            "version_number": version.version_number,
                            "created_at": version.created_at,
                            "file_size": version.file_size,
                            "notes": version.notes,
                            "created_by": (
                                version.creator.username
                                if version.creator
                                else "Unknown"
                            ),
                        }
                    )
                return result

            finally:
                self.db_manager.close_session(session)
        except Exception as e:
            logger.error(f"Failed to list versions: {e}")
            return []

    def add_file_tag(
        self,
        file_id: int,
        username: str,
        tag_name: str,
        tag_color: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Add a tag to a file"""
        try:
            session = self.db_manager.get_session()
            try:
                from ..models.database import FileTag, SecureFile, User

                user = session.query(User).filter(User.username == username).first()
                if not user:
                    return False, "User not found"

                secure_file = (
                    session.query(SecureFile).filter(SecureFile.id == file_id).first()
                )
                if not secure_file:
                    return False, "File not found"

                # Check if tag already exists
                existing_tag = (
                    session.query(FileTag)
                    .filter(
                        FileTag.file_id == file_id,
                        FileTag.tag_name == tag_name,
                    )
                    .first()
                )
                if existing_tag:
                    return False, "Tag already exists"

                # Create tag
                file_tag = FileTag(
                    file_id=file_id,
                    tag_name=tag_name,
                    tag_color=tag_color or "#3498db",
                    created_by=user.id,
                )
                session.add(file_tag)
                session.commit()

                logger.info(f"Tag '{tag_name}' added to file {file_id}")
                return True, "Tag added successfully"

            finally:
                self.db_manager.close_session(session)
        except Exception as e:
            logger.error(f"Failed to add tag: {e}")
            return False, f"Failed to add tag: {str(e)}"

    def remove_file_tag(self, file_id: int, tag_name: str) -> tuple[bool, str]:
        """Remove a tag from a file"""
        try:
            session = self.db_manager.get_session()
            try:
                from ..models.database import FileTag

                tag = (
                    session.query(FileTag)
                    .filter(FileTag.file_id == file_id, FileTag.tag_name == tag_name)
                    .first()
                )
                if not tag:
                    return False, "Tag not found"

                session.delete(tag)
                session.commit()

                logger.info(f"Tag '{tag_name}' removed from file {file_id}")
                return True, "Tag removed successfully"

            finally:
                self.db_manager.close_session(session)
        except Exception as e:
            logger.error(f"Failed to remove tag: {e}")
            return False, f"Failed to remove tag: {str(e)}"

    def get_file_tags(self, file_id: int) -> List[Dict]:
        """Get all tags for a file"""
        try:
            session = self.db_manager.get_session()
            try:
                from ..models.database import FileTag

                tags = session.query(FileTag).filter(FileTag.file_id == file_id).all()

                return [
                    {"name": tag.tag_name, "color": tag.tag_color or "#3498db"}
                    for tag in tags
                ]

            finally:
                self.db_manager.close_session(session)
        except Exception as e:
            logger.error(f"Failed to get tags: {e}")
            return []

    def share_file(
        self,
        file_id: int,
        owner_username: str,
        shared_with_username: str,
        permission_type: str = "read",
    ) -> tuple[bool, str]:
        """Share a file with another user"""
        try:
            session = self.db_manager.get_session()
            try:
                from ..models.database import FilePermission, SecureFile, User

                owner = (
                    session.query(User).filter(User.username == owner_username).first()
                )
                if not owner:
                    return False, "Owner not found"

                shared_with = (
                    session.query(User)
                    .filter(User.username == shared_with_username)
                    .first()
                )
                if not shared_with:
                    return False, "User to share with not found"

                secure_file = (
                    session.query(SecureFile).filter(SecureFile.id == file_id).first()
                )
                if not secure_file:
                    return False, "File not found"

                if secure_file.owner_id != owner.id:
                    return False, "Only file owner can share files"

                # Check if permission already exists
                existing = (
                    session.query(FilePermission)
                    .filter(
                        FilePermission.file_id == file_id,
                        FilePermission.user_id == shared_with.id,
                    )
                    .first()
                )
                if existing:
                    existing.permission_type = permission_type
                    session.commit()
                    return True, "Share permission updated"

                # Create permission
                permission = FilePermission(
                    file_id=file_id,
                    user_id=shared_with.id,
                    permission_type=permission_type,
                    granted_by=owner.id,
                )
                session.add(permission)
                session.commit()

                logger.info(
                    f"File {file_id} shared with {shared_with_username} "
                    f"by {owner_username}"
                )
                return True, "File shared successfully"

            finally:
                self.db_manager.close_session(session)
        except Exception as e:
            logger.error(f"Failed to share file: {e}")
            return False, f"Failed to share file: {str(e)}"

    def revoke_file_share(
        self, file_id: int, owner_username: str, shared_with_username: str
    ) -> tuple[bool, str]:
        """Revoke file sharing with a user"""
        try:
            session = self.db_manager.get_session()
            try:
                from ..models.database import FilePermission, SecureFile, User

                owner = (
                    session.query(User).filter(User.username == owner_username).first()
                )
                shared_with = (
                    session.query(User)
                    .filter(User.username == shared_with_username)
                    .first()
                )
                secure_file = (
                    session.query(SecureFile).filter(SecureFile.id == file_id).first()
                )

                if not owner or not shared_with or not secure_file:
                    return False, "User or file not found"

                permission = (
                    session.query(FilePermission)
                    .filter(
                        FilePermission.file_id == file_id,
                        FilePermission.user_id == shared_with.id,
                    )
                    .first()
                )
                if permission:
                    session.delete(permission)
                    session.commit()
                    return True, "Share revoked successfully"

                return False, "Share not found"

            finally:
                self.db_manager.close_session(session)
        except Exception as e:
            logger.error(f"Failed to revoke share: {e}")
            return False, f"Failed to revoke share: {str(e)}"

    def export_file_list(self, username: str, export_path: Path) -> tuple[bool, str]:
        """Export file list to CSV"""
        try:
            files = self.list_user_files(username)
            with open(export_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "id",
                        "filename",
                        "owner",
                        "size",
                        "created_at",
                        "last_accessed",
                        "access_count",
                    ],
                )
                writer.writeheader()
                for file_info in files:
                    writer.writerow(
                        {
                            "id": file_info["id"],
                            "filename": file_info["filename"],
                            "owner": file_info.get("owner", username),
                            "size": file_info["size"],
                            "created_at": (
                                file_info["created_at"].isoformat()
                                if file_info["created_at"]
                                else ""
                            ),
                            "last_accessed": (
                                file_info["last_accessed"].isoformat()
                                if file_info.get("last_accessed")
                                else ""
                            ),
                            "access_count": file_info.get("access_count", 0),
                        }
                    )
            return True, f"File list exported to {export_path}"

        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False, f"Export failed: {str(e)}"

    def export_backup(self, backup_path: Path) -> tuple[bool, str]:
        """Export complete backup (database + encrypted files)"""
        try:
            session = self.db_manager.get_session()
            try:
                from ..models.database import SecureFile, User

                # Create backup directory
                backup_dir = (
                    backup_path
                    / f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
                )
                backup_dir.mkdir(parents=True, exist_ok=True)

                # Export database info
                db_info: Dict[str, Any] = {
                    "users": [],
                    "files": [],
                    "backup_date": datetime.utcnow().isoformat(),
                }

                users = session.query(User).all()
                for user in users:
                    db_info["users"].append(
                        {
                            "id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "role": user.role,
                            "created_at": (
                                user.created_at.isoformat() if user.created_at else None
                            ),
                        }
                    )

                files = session.query(SecureFile).all()
                for file in files:
                    db_info["files"].append(
                        {
                            "id": file.id,
                            "filename": file.filename,
                            "owner_id": file.owner_id,
                            "file_size": file.file_size,
                            "created_at": (
                                file.created_at.isoformat() if file.created_at else None
                            ),
                        }
                    )

                # Save metadata
                with open(backup_dir / "metadata.json", "w") as f:
                    json.dump(db_info, f, indent=2)

                # Copy encrypted files
                encrypted_backup_dir = backup_dir / "encrypted"
                encrypted_backup_dir.mkdir(exist_ok=True)

                encrypted_dir = Path("data/encrypted")
                if encrypted_dir.exists():
                    for enc_file in encrypted_dir.iterdir():
                        if enc_file.is_file():
                            shutil.copy2(enc_file, encrypted_backup_dir / enc_file.name)

                # Create zip archive
                zip_path = backup_path / f"{backup_dir.name}.zip"
                with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                    for file_path in backup_dir.rglob("*"):
                        if file_path.is_file():
                            zipf.write(
                                file_path, file_path.relative_to(backup_dir.parent)
                            )

                # Cleanup temp directory
                shutil.rmtree(backup_dir)

                return True, f"Backup exported to {zip_path}"

            finally:
                self.db_manager.close_session(session)
        except Exception as e:
            logger.error(f"Backup export failed: {e}")
            return False, f"Backup export failed: {str(e)}"

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
