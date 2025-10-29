"""
Authentication Module
Handles user authentication, password management, and session control
"""
import hashlib
import secrets
from datetime import datetime, timedelta
from passlib.context import CryptContext
from passlib.hash import bcrypt
import logging

logger = logging.getLogger(__name__)

class AuthenticationManager:
    """Handles user authentication and password management"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.max_login_attempts = 5
        self.lockout_duration = timedelta(minutes=15)
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return self.pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return self.pwd_context.verify(plain_password, hashed_password)
    
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
    
    def create_user(self, username: str, email: str, password: str, role: str = "user") -> bool:
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
        session = self.db_manager.get_session()
        try:
            from ..models.database import User
            
            # Check if user already exists
            existing_user = session.query(User).filter(
                (User.username == username) | (User.email == email)
            ).first()
            
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
                is_active=True
            )
            
            session.add(user)
            session.commit()
            
            logger.info(f"User created successfully: {username}")
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to create user {username}: {e}")
            return False
        finally:
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
        session = self.db_manager.get_session()
        try:
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
            self.db_manager.close_session(session)
    
    def change_password(self, username: str, old_password: str, new_password: str) -> tuple[bool, str]:
        """
        Change user password
        
        Args:
            username: Username
            old_password: Current password
            new_password: New password
            
        Returns:
            (success, message)
        """
        session = self.db_manager.get_session()
        try:
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
            session.rollback()
            logger.error(f"Failed to change password for {username}: {e}")
            return False, "Failed to change password"
        finally:
            self.db_manager.close_session(session)
    
    def get_user_by_username(self, username: str):
        """Get user by username"""
        session = self.db_manager.get_session()
        try:
            from ..models.database import User
            return session.query(User).filter(User.username == username).first()
        finally:
            self.db_manager.close_session(session)
