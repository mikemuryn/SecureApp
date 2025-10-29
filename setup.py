#!/usr/bin/env python3
"""
Setup script for SecureApp
"""
import os
import sys
import subprocess
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    return True

def install_requirements():
    """Install required packages"""
    print("Installing required packages...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✓ Requirements installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to install requirements: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    print("Creating application directories...")
    directories = [
        "data",
        "data/encrypted", 
        "data/database",
        "logs",
        "temp"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✓ Created directory: {directory}")

def setup_logging():
    """Setup logging configuration"""
    print("Setting up logging...")
    log_file = Path("logs/setup.log")
    log_file.parent.mkdir(exist_ok=True)
    
    with open(log_file, "w") as f:
        f.write("SecureApp Setup Log\n")
        f.write("=" * 40 + "\n")
        f.write(f"Setup completed at: {os.popen('date').read().strip()}\n")
        f.write(f"Python version: {sys.version}\n")
    
    print("✓ Logging configured")

def verify_installation():
    """Verify the installation"""
    print("Verifying installation...")
    
    try:
        # Test imports
        import tkinter
        import customtkinter
        import cryptography
        import bcrypt
        import sqlalchemy
        print("✓ All required modules imported successfully")
        
        # Test database creation
        from app.models.database import DatabaseManager
        db_manager = DatabaseManager("sqlite:///data/database/test.db")
        db_manager.create_tables()
        print("✓ Database tables created successfully")
        
        return True
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"✗ Verification error: {e}")
        return False

def main():
    """Main setup function"""
    print("SecureApp Setup")
    print("=" * 40)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install requirements
    if not install_requirements():
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Setup logging
    setup_logging()
    
    # Verify installation
    if not verify_installation():
        print("✗ Installation verification failed")
        sys.exit(1)
    
    print("\n" + "=" * 40)
    print("✓ Setup completed successfully!")
    print("\nTo run the application:")
    print("  python main.py")
    print("\nDefault admin login:")
    print("  Username: admin")
    print("  Password: Admin123!")
    print("\n⚠️  Remember to change the default password!")

if __name__ == "__main__":
    main()
