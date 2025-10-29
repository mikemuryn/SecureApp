"""
Debug utilities for admin permissions
"""
import logging
from app.models.database import User, SecureFile

logger = logging.getLogger(__name__)

def debug_admin_permissions(db_manager, username: str):
    """Debug admin user permissions"""
    session = db_manager.get_session()
    try:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            print(f"❌ User '{username}' not found")
            return
        
        print(f"👤 User: {user.username}")
        print(f"🔑 Role: {user.role}")
        print(f"✅ Active: {user.is_active}")
        print(f"🔒 Locked: {user.locked_until}")
        print(f"❌ Failed attempts: {user.failed_attempts}")
        
        # Check if user is admin
        is_admin = user.role == "admin"
        print(f"👑 Is Admin: {is_admin}")
        
        # List all files
        all_files = session.query(SecureFile).all()
        print(f"📁 Total files in system: {len(all_files)}")
        
        # List files owned by user
        owned_files = session.query(SecureFile).filter(SecureFile.owner_id == user.id).all()
        print(f"📁 Files owned by {username}: {len(owned_files)}")
        
        # List all users
        all_users = session.query(User).all()
        print(f"👥 Total users: {len(all_users)}")
        
        for file in all_files:
            print(f"  📄 {file.filename} (Owner: {file.owner.username}, ID: {file.id})")
            
    except Exception as e:
        print(f"❌ Debug error: {e}")
    finally:
        db_manager.close_session(session)

def test_admin_access(db_manager, username: str):
    """Test admin access to files"""
    session = db_manager.get_session()
    try:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            print(f"❌ User '{username}' not found")
            return
        
        if user.role != "admin":
            print(f"❌ User '{username}' is not an admin (role: {user.role})")
            return
        
        # Test file listing
        all_files = session.query(SecureFile).all()
        print(f"✅ Admin can see {len(all_files)} files")
        
        for file in all_files:
            print(f"  📄 {file.filename} - Owner: {file.owner.username}")
            
    except Exception as e:
        print(f"❌ Test error: {e}")
    finally:
        db_manager.close_session(session)
