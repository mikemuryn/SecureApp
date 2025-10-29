"""
Debug authentication issues
"""
import logging
from app.models.database import DatabaseManager, User
from app.auth.authentication import AuthenticationManager

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def debug_authentication():
    """Debug authentication system"""
    try:
        # Initialize components
        db_manager = DatabaseManager("sqlite:///data/database/SecureApp.db")
        auth_manager = AuthenticationManager(db_manager)
        
        print("🔍 Debugging Authentication System")
        print("=" * 40)
        
        # Check database connection
        session = db_manager.get_session()
        try:
            # Check if admin user exists
            admin_user = session.query(User).filter(User.username == "admin").first()
            
            if admin_user:
                print(f"✅ Admin user found:")
                print(f"   Username: {admin_user.username}")
                print(f"   Email: {admin_user.email}")
                print(f"   Role: {admin_user.role}")
                print(f"   Active: {admin_user.is_active}")
                print(f"   Locked: {admin_user.locked_until}")
                print(f"   Failed attempts: {admin_user.failed_attempts}")
                print(f"   Password hash: {admin_user.password_hash[:20]}...")
            else:
                print("❌ Admin user not found!")
                
                # Try to create admin user
                print("🔄 Attempting to create admin user...")
                success = auth_manager.create_user(
                    "admin", "admin@secure-trading.com", "Admin123!", "admin"
                )
                if success:
                    print("✅ Admin user created successfully!")
                else:
                    print("❌ Failed to create admin user!")
            
            # Test authentication
            print("\n🧪 Testing authentication...")
            success, message = auth_manager.authenticate_user("admin", "Admin123!")
            print(f"Authentication result: {success}")
            print(f"Message: {message}")
            
            if not success:
                print("\n🔍 Debugging password verification...")
                admin_user = session.query(User).filter(User.username == "admin").first()
                if admin_user:
                    # Test password verification directly
                    is_valid = auth_manager.verify_password("Admin123!", admin_user.password_hash)
                    print(f"Password verification: {is_valid}")
                    
                    # Test password strength validation
                    is_strong, errors = auth_manager.validate_password_strength("Admin123!")
                    print(f"Password strength: {is_strong}")
                    if errors:
                        print(f"Password errors: {errors}")
            
        finally:
            db_manager.close_session(session)
            
    except Exception as e:
        print(f"❌ Debug error: {e}")
        logger.exception("Authentication debug failed")

if __name__ == "__main__":
    debug_authentication()
