"""
Session Management Module
Handles user sessions, timeouts, and security
"""

import logging
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class SessionManager:
    """Manages user sessions and security"""

    def __init__(self, session_timeout: int = 1800):  # 30 minutes default
        self.sessions: Dict[str, dict] = {}
        self.session_timeout = session_timeout
        self.max_sessions_per_user = 3

    def create_session(self, username: str, user_role: str) -> str:
        """
        Create a new session for user

        Args:
            username: Username
            user_role: User role

        Returns:
            Session token
        """
        # Clean up expired sessions for this user
        self._cleanup_user_sessions(username)

        # Check session limit
        user_sessions = [s for s in self.sessions.values() if s["username"] == username]
        if len(user_sessions) >= self.max_sessions_per_user:
            # Remove oldest session
            oldest_session = min(user_sessions, key=lambda x: x["created_at"])
            self.sessions.pop(oldest_session["token"])

        # Create new session
        session_token = secrets.token_urlsafe(32)
        session_data = {
            "username": username,
            "role": user_role,
            "created_at": datetime.utcnow(),
            "last_activity": datetime.utcnow(),
            "token": session_token,
        }

        self.sessions[session_token] = session_data

        logger.info(f"Session created for user: {username}")
        return session_token

    def validate_session(self, session_token: str) -> tuple[bool, Optional[dict]]:
        """
        Validate session token

        Args:
            session_token: Session token to validate

        Returns:
            (is_valid, session_data)
        """
        if session_token not in self.sessions:
            return False, None

        session_data = self.sessions[session_token]

        # Check if session has expired
        if self._is_session_expired(session_data):
            self.sessions.pop(session_token)
            logger.info(f"Session expired for user: {session_data['username']}")
            return False, None

        # Update last activity
        session_data["last_activity"] = datetime.utcnow()

        return True, session_data

    def refresh_session(self, session_token: str) -> bool:
        """
        Refresh session activity

        Args:
            session_token: Session token

        Returns:
            True if session was refreshed
        """
        if session_token not in self.sessions:
            return False

        self.sessions[session_token]["last_activity"] = datetime.utcnow()
        return True

    def destroy_session(self, session_token: str) -> bool:
        """
        Destroy session

        Args:
            session_token: Session token to destroy

        Returns:
            True if session was destroyed
        """
        if session_token in self.sessions:
            username = self.sessions[session_token]["username"]
            self.sessions.pop(session_token)
            logger.info(f"Session destroyed for user: {username}")
            return True
        return False

    def destroy_user_sessions(self, username: str) -> int:
        """
        Destroy all sessions for a user

        Args:
            username: Username

        Returns:
            Number of sessions destroyed
        """
        sessions_to_remove = []
        for token, session_data in self.sessions.items():
            if session_data["username"] == username:
                sessions_to_remove.append(token)

        for token in sessions_to_remove:
            self.sessions.pop(token)

        logger.info(
            f"Destroyed {len(sessions_to_remove)} sessions for user: {username}"
        )
        return len(sessions_to_remove)

    def _is_session_expired(self, session_data: dict) -> bool:
        """Check if session has expired"""
        last_activity = session_data["last_activity"]
        timeout_threshold = datetime.utcnow() - timedelta(seconds=self.session_timeout)
        result: bool = last_activity < timeout_threshold
        return result

    def _cleanup_user_sessions(self, username: str) -> None:
        """Clean up expired sessions for a specific user"""
        sessions_to_remove = []
        for token, session_data in self.sessions.items():
            if session_data["username"] == username and self._is_session_expired(
                session_data
            ):
                sessions_to_remove.append(token)

        for token in sessions_to_remove:
            self.sessions.pop(token)

    def cleanup_expired_sessions(self) -> None:
        """Clean up all expired sessions"""
        sessions_to_remove = []
        for token, session_data in self.sessions.items():
            if self._is_session_expired(session_data):
                sessions_to_remove.append(token)

        for token in sessions_to_remove:
            self.sessions.pop(token)

        if sessions_to_remove:
            logger.info(f"Cleaned up {len(sessions_to_remove)} expired sessions")

    def get_active_sessions(self) -> Dict[str, dict]:
        """Get all active sessions"""
        self.cleanup_expired_sessions()
        return self.sessions.copy()

    def get_user_sessions(self, username: str) -> list:
        """Get all active sessions for a user"""
        return [
            session
            for session in self.sessions.values()
            if session["username"] == username and not self._is_session_expired(session)
        ]
