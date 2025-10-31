"""
Authentication Module
Handles user authentication, password management, and session control
"""

import logging
import secrets
from datetime import datetime, timedelta

from passlib.context import CryptContext

logger = logging.getLogger(__name__)


class AuthenticationManager:
    """Handles user authentication and password management"""

    def __init__(self, db_manager) -> None:
        self.db_manager = db_manager
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.max_login_attempts = 5
        self.lockout_duration = timedelta(minutes=15)

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        result: str = self.pwd_context.hash(password)
        return result

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        result: bool = self.pwd_context.verify(plain_password, hashed_password)
        return result

    def validate_password_strength(self, password: str) -> tuple[bool, list[str]]:
        """
        Validate password strength

        Returns:
            (is_valid, list_of_errors)
        """
        errors = []

        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")

        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")

        if not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")

        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one number")

        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one special character")

        return len(errors) == 0, errors

    def create_user(
        self, username: str, email: str, password: str, role: str = "user"
    ) -> bool:
        """
        Create a new user

        Args:
            username: Username
            email: Email address
            password: Plain text password
            role: User role (admin, user, readonly)

        Returns:
            True if user created successfully
        """
        session = None
        try:
            session = self.db_manager.get_session()
            from ..models.database import User

            # Check if user already exists
            existing_user = (
                session.query(User)
                .filter((User.username == username) | (User.email == email))
                .first()
            )

            if existing_user:
                logger.warning(f"User creation failed: {username} already exists")
                return False

            # Validate password strength
            is_valid, errors = self.validate_password_strength(password)
            if not is_valid:
                logger.warning(f"Password validation failed for {username}: {errors}")
                return False

            # Hash password
            password_hash = self.hash_password(password)

            # Create user
            user = User(
                username=username,
                email=email,
                password_hash=password_hash,
                salt=secrets.token_hex(16),
                role=role,
                is_active=True,
            )

            session.add(user)
            session.commit()

            logger.info(f"User created successfully: {username}")
            return True

        except Exception as e:
            if session is not None:
                session.rollback()
            logger.error(f"Failed to create user {username}: {e}")
            return False
        finally:
            if session is not None:
                self.db_manager.close_session(session)

    def authenticate_user(self, username: str, password: str) -> tuple[bool, str]:
        """
        Authenticate user login

        Args:
            username: Username
            password: Plain text password

        Returns:
            (success, message)
        """
        session = None
        try:
            session = self.db_manager.get_session()
            from ..models.database import User

            user = session.query(User).filter(User.username == username).first()

            if not user:
                logger.warning(f"Login attempt with unknown username: {username}")
                return False, "Invalid username or password"

            if not user.is_active:
                logger.warning(f"Login attempt with inactive account: {username}")
                return False, "Account is disabled"

            # Check if account is locked
            if user.locked_until and user.locked_until > datetime.utcnow():
                logger.warning(f"Login attempt with locked account: {username}")
                return False, f"Account locked until {user.locked_until}"

            # Verify password
            if not self.verify_password(password, user.password_hash):
                # Increment failed attempts
                user.failed_attempts += 1

                if user.failed_attempts >= self.max_login_attempts:
                    user.locked_until = datetime.utcnow() + self.lockout_duration
                    logger.warning(f"Account locked due to failed attempts: {username}")

                session.commit()
                logger.warning(f"Failed login attempt for: {username}")
                return False, "Invalid username or password"

            # Reset failed attempts on successful login
            user.failed_attempts = 0
            user.locked_until = None
            user.last_login = datetime.utcnow()
            session.commit()

            logger.info(f"Successful login: {username}")
            return True, "Login successful"

        except Exception as e:
            logger.error(f"Authentication error for {username}: {e}")
            return False, "Authentication error"
        finally:
            if session is not None:
                self.db_manager.close_session(session)

    def change_password(
        self, username: str, old_password: str, new_password: str
    ) -> tuple[bool, str]:
        """
        Change user password

        Args:
            username: Username
            old_password: Current password
            new_password: New password

        Returns:
            (success, message)
        """
        session = None
        try:
            session = self.db_manager.get_session()
            from ..models.database import User

            user = session.query(User).filter(User.username == username).first()

            if not user:
                return False, "User not found"

            # Verify old password
            if not self.verify_password(old_password, user.password_hash):
                return False, "Current password is incorrect"

            # Validate new password strength
            is_valid, errors = self.validate_password_strength(new_password)
            if not is_valid:
                return False, f"Password validation failed: {', '.join(errors)}"

            # Update password
            user.password_hash = self.hash_password(new_password)
            session.commit()

            logger.info(f"Password changed successfully for: {username}")
            return True, "Password changed successfully"

        except Exception as e:
            if session is not None:
                session.rollback()
            logger.error(f"Failed to change password for {username}: {e}")
            return False, "Failed to change password"
        finally:
            if session is not None:
                self.db_manager.close_session(session)

    def get_user_by_username(self, username: str):
        """Get user by username"""
        session = None
        try:
            session = self.db_manager.get_session()
            from ..models.database import User

            return session.query(User).filter(User.username == username).first()
        finally:
            if session is not None:
                self.db_manager.close_session(session)

    def set_recovery_question(
        self, username: str, question: str, answer: str
    ) -> tuple[bool, str]:
        """
        Set password recovery question and answer

        Args:
            username: Username
            question: Security question
            answer: Answer to security question

        Returns:
            (success, message)
        """
        session = None
        try:
            session = self.db_manager.get_session()
            from ..models.database import User

            user = session.query(User).filter(User.username == username).first()
            if not user:
                return False, "User not found"

            # Hash the answer
            answer_hash = self.hash_password(answer.lower().strip())

            user.recovery_question = question
            user.recovery_answer_hash = answer_hash
            session.commit()

            logger.info(f"Recovery question set for: {username}")
            return True, "Recovery question set successfully"

        except Exception as e:
            if session is not None:
                session.rollback()
            logger.error(f"Failed to set recovery question for {username}: {e}")
            return False, "Failed to set recovery question"
        finally:
            if session is not None:
                self.db_manager.close_session(session)

    def request_password_reset(
        self, username: str, recovery_answer: str
    ) -> tuple[bool, str, str]:
        """
        Request password reset using recovery answer

        Args:
            username: Username
            recovery_answer: Answer to security question

        Returns:
            (success, message, reset_token)
        """
        session = None
        try:
            session = self.db_manager.get_session()
            from ..models.database import User

            user = session.query(User).filter(User.username == username).first()
            if not user:
                return False, "User not found", ""

            if not user.recovery_question or not user.recovery_answer_hash:
                return False, "Recovery question not set", ""

            # Verify recovery answer
            if not self.verify_password(
                recovery_answer.lower().strip(), user.recovery_answer_hash
            ):
                logger.warning(f"Invalid recovery answer for: {username}")
                return False, "Incorrect recovery answer", ""

            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            user.password_reset_token = reset_token
            user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
            session.commit()

            logger.info(f"Password reset token generated for: {username}")
            return True, "Reset token generated", reset_token

        except Exception as e:
            if session is not None:
                session.rollback()
            logger.error(f"Failed to request password reset for {username}: {e}")
            return False, "Failed to request password reset", ""
        finally:
            if session is not None:
                self.db_manager.close_session(session)

    def reset_password(
        self, username: str, reset_token: str, new_password: str
    ) -> tuple[bool, str]:
        """
        Reset password using reset token

        Args:
            username: Username
            reset_token: Password reset token
            new_password: New password

        Returns:
            (success, message)
        """
        session = None
        try:
            session = self.db_manager.get_session()
            from ..models.database import User

            user = session.query(User).filter(User.username == username).first()
            if not user:
                return False, "User not found"

            # Verify token
            if (
                not user.password_reset_token
                or user.password_reset_token != reset_token
            ):
                return False, "Invalid reset token"

            # Check token expiration
            if (
                not user.password_reset_expires
                or user.password_reset_expires < datetime.utcnow()
            ):
                return False, "Reset token has expired"

            # Validate new password strength
            is_valid, errors = self.validate_password_strength(new_password)
            if not is_valid:
                return False, f"Password validation failed: {', '.join(errors)}"

            # Update password
            user.password_hash = self.hash_password(new_password)
            user.password_reset_token = None
            user.password_reset_expires = None
            user.failed_attempts = 0
            user.locked_until = None
            session.commit()

            logger.info(f"Password reset successfully for: {username}")
            return True, "Password reset successfully"

        except Exception as e:
            if session is not None:
                session.rollback()
            logger.error(f"Failed to reset password for {username}: {e}")
            return False, "Failed to reset password"
        finally:
            if session is not None:
                self.db_manager.close_session(session)

    def admin_reset_password(
        self, admin_username: str, target_username: str, new_password: str
    ) -> tuple[bool, str]:
        """
        Admin-initiated password reset

        Args:
            admin_username: Admin username
            target_username: Username to reset password for
            new_password: New password

        Returns:
            (success, message)
        """
        session = None
        try:
            session = self.db_manager.get_session()
            from ..models.database import User

            admin = session.query(User).filter(User.username == admin_username).first()
            if not admin or admin.role != "admin":
                return False, "Admin access required"

            user = session.query(User).filter(User.username == target_username).first()
            if not user:
                return False, "User not found"

            # Validate new password strength
            is_valid, errors = self.validate_password_strength(new_password)
            if not is_valid:
                return False, f"Password validation failed: {', '.join(errors)}"

            # Update password
            user.password_hash = self.hash_password(new_password)
            user.failed_attempts = 0
            user.locked_until = None
            session.commit()

            logger.info(
                f"Password reset by admin {admin_username} for user: {target_username}"
            )
            return True, "Password reset successfully"

        except Exception as e:
            if session is not None:
                session.rollback()
            logger.error(
                f"Failed to reset password by admin {admin_username} "
                f"for {target_username}: {e}"
            )
            return False, "Failed to reset password"
        finally:
            if session is not None:
                self.db_manager.close_session(session)
