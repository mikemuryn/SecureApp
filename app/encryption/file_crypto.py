"""
Encryption and Decryption Module
Handles secure file encryption/decryption using AES-256
"""

import base64
import logging
import os
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


class FileEncryption:
    """Handles encryption and decryption of files"""

    def __init__(self, password: str, salt: Optional[bytes] = None):
        """
        Initialize encryption with password and optional salt

        Args:
            password: User password for key derivation
            salt: Optional salt (generated if not provided)
        """
        self.password = password.encode()
        self.salt = salt or os.urandom(16)
        self._key = self._derive_key()
        self._fernet = Fernet(self._key)

    def _derive_key(self) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return key

    def encrypt_file(
        self, file_path: Path, encrypted_path: Optional[Path] = None
    ) -> Path:
        """
        Encrypt a file and save to encrypted location

        Args:
            file_path: Path to file to encrypt
            encrypted_path: Path to save encrypted file (auto-generated if None)

        Returns:
            Path to encrypted file
        """
        if encrypted_path is None:
            encrypted_path = Path("encrypted") / f"{file_path.name}.enc"

        try:
            # Ensure output directory exists
            encrypted_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, "rb") as file:
                file_data = file.read()

            encrypted_data = self._fernet.encrypt(file_data)

            # Save salt + encrypted data
            with open(encrypted_path, "wb") as file:
                file.write(self.salt + encrypted_data)

            logger.info(f"File encrypted: {file_path} -> {encrypted_path}")
            return encrypted_path

        except Exception as e:
            logger.error(f"Encryption failed for {file_path}: {e}")
            raise

    def decrypt_file(
        self, encrypted_path: Path, output_path: Optional[Path] = None
    ) -> Path:
        """
        Decrypt a file and save to output location

        Args:
            encrypted_path: Path to encrypted file
            output_path: Path to save decrypted file (auto-generated if None)

        Returns:
            Path to decrypted file
        """
        if output_path is None:
            output_path = Path("temp") / encrypted_path.stem

        try:
            with open(encrypted_path, "rb") as file:
                encrypted_data = file.read()

            # Extract salt and encrypted data
            salt = encrypted_data[:16]
            encrypted_content = encrypted_data[16:]

            # Recreate encryption object with extracted salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.password))
            fernet = Fernet(key)

            decrypted_data = fernet.decrypt(encrypted_content)

            # Ensure output directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "wb") as file:
                file.write(decrypted_data)

            logger.info(f"File decrypted: {encrypted_path} -> {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Decryption failed for {encrypted_path}: {e}")
            raise

    def encrypt_string(self, text: str) -> str:
        """Encrypt a string and return base64 encoded result"""
        encrypted_data = self._fernet.encrypt(text.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()

    def decrypt_string(self, encrypted_text: str) -> str:
        """Decrypt a base64 encoded string"""
        encrypted_data = base64.urlsafe_b64decode(encrypted_text.encode())
        decrypted_data = self._fernet.decrypt(encrypted_data)
        result: str = decrypted_data.decode(encoding="utf-8")
        return result

    def get_salt(self) -> bytes:
        """Get the salt used for key derivation"""
        return self.salt
