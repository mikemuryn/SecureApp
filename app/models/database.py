"""
Database Models for SecureApp
"""

import logging
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

logger = logging.getLogger(__name__)

Base = declarative_base()


class User(Base):  # type: ignore[valid-type,misc]
    """User model for authentication and authorization"""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    salt = Column(String(255), nullable=False)
    role = Column(String(20), default="user")  # admin, user, readonly
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)

    # Relationships
    files = relationship("SecureFile", back_populates="owner")
    audit_logs = relationship("AuditLog", back_populates="user")


class SecureFile(Base):  # type: ignore[valid-type,misc]
    """Model for encrypted files"""

    __tablename__ = "secure_files"

    id = Column(Integer, primary_key=True)
    filename = Column(String(255), nullable=False)
    original_path = Column(String(500), nullable=False)
    encrypted_path = Column(String(500), nullable=False)
    file_hash = Column(String(64), nullable=False)  # SHA-256 hash
    file_size = Column(Integer, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_accessed = Column(DateTime)
    access_count = Column(Integer, default=0)
    is_encrypted = Column(Boolean, default=True)

    # Relationships
    owner = relationship("User", back_populates="files")
    permissions = relationship("FilePermission", back_populates="file")


class FilePermission(Base):  # type: ignore[valid-type,misc]
    """Model for file access permissions"""

    __tablename__ = "file_permissions"

    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey("secure_files.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    permission_type = Column(String(20), nullable=False)  # read, write, admin
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    granted_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)

    # Relationships
    file = relationship("SecureFile", back_populates="permissions")
    user = relationship("User", foreign_keys=[user_id])
    granter = relationship("User", foreign_keys=[granted_by])


class AuditLog(Base):  # type: ignore[valid-type,misc]
    """Model for security audit logging"""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(50), nullable=False)  # login, logout, file_access, etc.
    resource = Column(String(255), nullable=True)  # filename, endpoint, etc.
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    success = Column(Boolean, nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="audit_logs")


class DatabaseManager:
    """Database connection and session management"""

    def __init__(self, database_url: str):
        self.engine = create_engine(database_url)
        self.SessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )

    def create_tables(self) -> None:
        """Create all database tables"""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create database tables: {e}")
            raise

    def get_session(self):  # type: ignore[no-untyped-def]
        """Get database session"""
        return self.SessionLocal()

    def close_session(self, session) -> None:  # type: ignore[no-untyped-def]
        """Close database session"""
        session.close()
