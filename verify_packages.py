#!/usr/bin/env python3
"""
Package Verification Script for SecureApp
"""
import sys
import importlib

def check_package(package_name, import_name=None):
    """Check if a package is installed and importable"""
    if import_name is None:
        import_name = package_name
    
    try:
        module = importlib.import_module(import_name)
        version = getattr(module, '__version__', 'Unknown')
        print(f"✅ {package_name}: {version}")
        return True
    except ImportError as e:
        print(f"❌ {package_name}: Not installed ({e})")
        return False
    except Exception as e:
        print(f"⚠️  {package_name}: Installed but error ({e})")
        return False

def main():
    """Check all required packages"""
    print("🔍 Verifying SecureApp Dependencies")
    print("=" * 60)
    
    # Required packages
    packages = [
        ("cryptography", "cryptography"),
        ("bcrypt", "bcrypt"),
        ("sqlalchemy", "sqlalchemy"),
        ("customtkinter", "customtkinter"),
        ("passlib", "passlib"),
        ("python-dotenv", "dotenv"),
        ("argon2-cffi", "argon2"),
    ]
    
    # Optional development packages
    dev_packages = [
        ("pytest", "pytest"),
        ("black", "black"),
        ("flake8", "flake8"),
    ]
    
    print("📦 Core Dependencies:")
    core_success = 0
    for package, import_name in packages:
        if check_package(package, import_name):
            core_success += 1
    
    print(f"\n📦 Development Dependencies (Optional):")
    dev_success = 0
    for package, import_name in dev_packages:
        if check_package(package, import_name):
            dev_success += 1
    
    print("\n" + "=" * 60)
    print(f"📊 Summary:")
    print(f"   Core packages: {core_success}/{len(packages)}")
    print(f"   Dev packages: {dev_success}/{len(dev_packages)}")
    
    if core_success == len(packages):
        print("✅ All core dependencies are installed!")
        print("🚀 You can run the application with: python main.py")
    else:
        print("❌ Some core dependencies are missing!")
        print("📥 Install missing packages with:")
        print("   pip install -r requirements.txt")
        print("   or")
        print("   pip install -r requirements-minimal.txt")
    
    # Test basic functionality
    print(f"\n🧪 Testing Basic Functionality:")
    try:
        import tkinter
        print("✅ tkinter: Available (built-in)")
    except ImportError:
        print("❌ tkinter: Not available")
    
    try:
        import sqlite3
        print("✅ sqlite3: Available (built-in)")
    except ImportError:
        print("❌ sqlite3: Not available")

if __name__ == "__main__":
    main()
