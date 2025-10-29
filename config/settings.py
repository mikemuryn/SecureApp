"""
SecureApp - Configuration Settings
"""
import os
from pathlib import Path

# Application paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
ENCRYPTED_DIR = DATA_DIR / "encrypted"
DATABASE_DIR = DATA_DIR / "database"
LOGS_DIR = BASE_DIR / "logs"

# Security settings
ENCRYPTION_KEY_SIZE = 32  # 256 bits
SALT_SIZE = 16  # 128 bits
ITERATIONS = 100000  # PBKDF2 iterations

# Session settings
SESSION_TIMEOUT = 1800  # 30 minutes in seconds
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes

# Password requirements
MIN_PASSWORD_LENGTH = 8
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_NUMBERS = True
REQUIRE_SPECIAL_CHARS = True

# File settings
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {'.py', '.txt', '.md', '.json', '.csv', '.xlsx', '.pdf'}

# Database settings
DATABASE_URL = f"sqlite:///{DATABASE_DIR}/SecureApp.db"

# Logging settings
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_FILE = LOGS_DIR / "SecureApp.log"

# Create directories if they don't exist
for directory in [DATA_DIR, ENCRYPTED_DIR, DATABASE_DIR, LOGS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)
