"""
Audit Logging Module
Handles security audit logging and monitoring
"""
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
import json

logger = logging.getLogger(__name__)

class AuditLogger:
    """Handles security audit logging"""
    
    def __init__(self, log_file: Path, db_manager=None):
        self.log_file = log_file
        self.db_manager = db_manager
        
        # Ensure log directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Setup file logging
        self._setup_file_logging()
    
    def _setup_file_logging(self):
        """Setup file logging for audit events"""
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        audit_logger = logging.getLogger('audit')
        audit_logger.addHandler(file_handler)
        audit_logger.setLevel(logging.INFO)
    
    def log_event(self, 
                  user_id: Optional[int] = None,
                  username: Optional[str] = None,
                  action: str = "",
                  resource: Optional[str] = None,
                  ip_address: Optional[str] = None,
                  user_agent: Optional[str] = None,
                  success: bool = True,
                  details: Optional[str] = None):
        """
        Log an audit event
        
        Args:
            user_id: User ID (if available)
            username: Username
            action: Action performed
            resource: Resource accessed (filename, endpoint, etc.)
            ip_address: Client IP address
            user_agent: Client user agent
            success: Whether action was successful
            details: Additional details
        """
        event_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'username': username,
            'action': action,
            'resource': resource,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'success': success,
            'details': details
        }
        
        # Log to file
        audit_logger = logging.getLogger('audit')
        log_message = f"USER:{username or 'ANONYMOUS'} ACTION:{action} RESOURCE:{resource or 'N/A'} SUCCESS:{success}"
        if details:
            log_message += f" DETAILS:{details}"
        
        if success:
            audit_logger.info(log_message)
        else:
            audit_logger.warning(log_message)
        
        # Log to database if available
        if self.db_manager:
            self._log_to_database(event_data)
    
    def _log_to_database(self, event_data: dict):
        """Log event to database"""
        try:
            from .models.database import AuditLog
            
            session = self.db_manager.get_session()
            try:
                audit_log = AuditLog(
                    user_id=event_data['user_id'],
                    action=event_data['action'],
                    resource=event_data['resource'],
                    ip_address=event_data['ip_address'],
                    user_agent=event_data['user_agent'],
                    success=event_data['success'],
                    details=event_data['details']
                )
                
                session.add(audit_log)
                session.commit()
                
            except Exception as e:
                session.rollback()
                logger.error(f"Failed to log to database: {e}")
            finally:
                self.db_manager.close_session(session)
                
        except ImportError:
            logger.warning("Database logging not available")
    
    def log_login_attempt(self, username: str, success: bool, ip_address: str = None):
        """Log login attempt"""
        self.log_event(
            username=username,
            action="login_attempt",
            success=success,
            ip_address=ip_address,
            details="Login attempt"
        )
    
    def log_logout(self, username: str, ip_address: str = None):
        """Log user logout"""
        self.log_event(
            username=username,
            action="logout",
            success=True,
            ip_address=ip_address,
            details="User logout"
        )
    
    def log_file_access(self, username: str, filename: str, action: str, success: bool = True):
        """Log file access event"""
        self.log_event(
            username=username,
            action=f"file_{action}",
            resource=filename,
            success=success,
            details=f"File {action} operation"
        )
    
    def log_password_change(self, username: str, success: bool):
        """Log password change attempt"""
        self.log_event(
            username=username,
            action="password_change",
            success=success,
            details="Password change attempt"
        )
    
    def log_user_creation(self, username: str, created_by: str, success: bool):
        """Log user creation"""
        self.log_event(
            username=created_by,
            action="user_creation",
            resource=username,
            success=success,
            details=f"User creation: {username}"
        )
    
    def log_security_event(self, username: str, event: str, details: str):
        """Log security-related event"""
        self.log_event(
            username=username,
            action="security_event",
            success=False,
            details=f"{event}: {details}"
        )
    
    def get_recent_events(self, hours: int = 24) -> list:
        """Get recent audit events from database"""
        if not self.db_manager:
            return []
        
        try:
            from .models.database import AuditLog
            from datetime import timedelta
            
            session = self.db_manager.get_session()
            try:
                cutoff_time = datetime.utcnow() - timedelta(hours=hours)
                
                events = session.query(AuditLog).filter(
                    AuditLog.timestamp >= cutoff_time
                ).order_by(AuditLog.timestamp.desc()).limit(100).all()
                
                return [{
                    'timestamp': event.timestamp,
                    'username': event.user.username if event.user else 'ANONYMOUS',
                    'action': event.action,
                    'resource': event.resource,
                    'success': event.success,
                    'details': event.details
                } for event in events]
                
            finally:
                self.db_manager.close_session(session)
                
        except Exception as e:
            logger.error(f"Failed to get recent events: {e}")
            return []
