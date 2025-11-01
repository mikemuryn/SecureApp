"""
Encryption and Decryption Module
Handles secure file encryption/decryption using AES-256
"""

import base64
import logging
import os
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

NONCE_SIZE = 12
TAG_SIZE = 16


class FileEncryption:
    """Handles encryption and decryption of files."""

    def __init__(self, password: str, salt: Optional[bytes] = None):
        """
        Initialize encryption with password and optional salt.

        Args:
            password: Secret used for key derivation.
            salt: Optional salt (generated if not provided).
        """
        self.password = password.encode()
        self.salt = bytes(salt) if salt is not None else os.urandom(16)
        self._refresh_derived_materials()

    def _refresh_derived_materials(self) -> None:
        """Derive cryptographic material from the current password and salt."""
        self._key = self._derive_key()
        fernet_key = base64.urlsafe_b64encode(self._key)
        self._fernet = Fernet(fernet_key)
        self._aesgcm = AESGCM(self._key)

    def set_salt(self, salt: bytes) -> None:
        """Update the salt and recompute derived keys."""
        self.salt = bytes(salt)
        self._refresh_derived_materials()

    def _derive_key(self) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        return kdf.derive(self.password)

    def _decrypt_with_metadata(self, encrypted_data: bytes) -> bytes:
        """Decrypt payload written with the current metadata-prefixed format."""
        min_length = 1 + NONCE_SIZE + TAG_SIZE
        if len(encrypted_data) < min_length:
            raise ValueError("Encrypted payload is too small to contain metadata")

        salt_len = encrypted_data[0]
        if salt_len <= 0:
            raise ValueError("Invalid salt length in encrypted payload")

        header_end = 1 + salt_len + NONCE_SIZE
        if len(encrypted_data) <= header_end:
            raise ValueError("Encrypted payload missing ciphertext data")

        stored_salt = encrypted_data[1 : 1 + salt_len]
        nonce = encrypted_data[1 + salt_len : header_end]
        ciphertext = encrypted_data[header_end:]

        if stored_salt != self.salt:
            self.set_salt(stored_salt)

        try:
            return self._aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise ValueError(
                "Failed to decrypt file; the password or data may be incorrect."
            ) from exc

    def _decrypt_legacy_format(
        self, encrypted_data: bytes, original_error: ValueError
    ) -> bytes:
        """
        Support decrypting files produced by earlier versions that omitted metadata.

        Legacy files always used a 16-byte salt followed by a 12-byte nonce.
        """
        legacy_header = 16 + NONCE_SIZE
        if len(encrypted_data) < legacy_header + TAG_SIZE:
            raise original_error

        stored_salt = encrypted_data[:16]
        nonce = encrypted_data[16 : 16 + NONCE_SIZE]
        ciphertext = encrypted_data[legacy_header:]

        original_salt = self.salt
        try:
            if stored_salt != self.salt:
                self.set_salt(stored_salt)
            return self._aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            if stored_salt != original_salt:
                self.set_salt(original_salt)
            raise ValueError(
                "Failed to decrypt file; the password or data may be incorrect."
            ) from exc

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
        file_path = Path(file_path)
        if encrypted_path is None:
            encrypted_path = Path("encrypted") / f"{file_path.name}.enc"
        encrypted_path = Path(encrypted_path)

        try:
            encrypted_path.parent.mkdir(parents=True, exist_ok=True)
            file_data = file_path.read_bytes()

            salt_len = len(self.salt)
            if not 1 <= salt_len <= 255:
                raise ValueError("Salt must be between 1 and 255 bytes")

            nonce = os.urandom(NONCE_SIZE)
            ciphertext = self._aesgcm.encrypt(nonce, file_data, None)

            with open(encrypted_path, "wb") as file:
                file.write(bytes([salt_len]) + self.salt + nonce + ciphertext)

            logger.info("File encrypted: %s -> %s", file_path, encrypted_path)
            return encrypted_path

        except Exception as e:
            logger.error("Encryption failed for %s: %s", file_path, e)
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
        encrypted_path = Path(encrypted_path)
        if output_path is None:
            default_name = f"{encrypted_path.stem}.dec"
            output_path = Path("temp") / default_name
        output_path = Path(output_path)

        try:
            encrypted_data = encrypted_path.read_bytes()
            try:
                plaintext = self._decrypt_with_metadata(encrypted_data)
            except ValueError as metadata_error:
                plaintext = self._decrypt_legacy_format(encrypted_data, metadata_error)

            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(plaintext)

            logger.info("File decrypted: %s -> %s", encrypted_path, output_path)
            return output_path

        except Exception as e:
            logger.error("Decryption failed for %s: %s", encrypted_path, e)
            raise

    def encrypt_string(self, text: str) -> str:
        """Encrypt a string and return base64 encoded result."""
        encrypted_data = self._fernet.encrypt(text.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()

    def decrypt_string(self, encrypted_text: str) -> str:
        """Decrypt a base64 encoded string."""
        encrypted_data = base64.urlsafe_b64decode(encrypted_text.encode())
        decrypted_data = self._fernet.decrypt(encrypted_data)
        return decrypted_data.decode("utf-8")

    def get_salt(self) -> bytes:
        """Get the salt used for key derivation."""
        return self.salt
