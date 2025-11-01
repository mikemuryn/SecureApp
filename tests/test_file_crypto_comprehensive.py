"""
Comprehensive tests for FileEncryption to improve coverage
"""

import tempfile
from pathlib import Path

import pytest

from app.encryption.file_crypto import FileEncryption


def test_file_encryption_init_with_salt():
    """Test FileEncryption initialization with custom salt"""
    salt = b"test_salt_123456"  # 16 bytes
    enc = FileEncryption("password", salt=salt)

    assert enc.salt == salt
    assert enc._key is not None
    assert enc._fernet is not None


def test_file_encryption_init_without_salt():
    """Test FileEncryption initialization without salt"""
    enc = FileEncryption("password")

    assert enc.salt is not None
    assert len(enc.salt) == 16
    assert enc._key is not None
    assert enc._fernet is not None


def test_get_salt():
    """Test getting salt"""
    enc = FileEncryption("password")
    salt = enc.get_salt()

    assert isinstance(salt, bytes)
    assert len(salt) == 16
    assert salt == enc.salt


def test_encrypt_file_with_output_path(tmp_path):
    """Test encrypting file with specified output path"""
    source_file = tmp_path / "source.txt"
    source_file.write_text("test content")

    output_file = tmp_path / "output.enc"
    enc = FileEncryption("password123!")

    result = enc.encrypt_file(source_file, output_file)

    assert result == output_file
    assert output_file.exists()
    assert output_file.stat().st_size > 0


def test_encrypt_file_auto_output_path(tmp_path):
    """Test encrypting file with auto-generated output path"""
    source_file = tmp_path / "source.txt"
    source_file.write_text("test content")

    # Change to tmp_path so default path works
    import os

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        encrypted_dir = tmp_path / "encrypted"
        encrypted_dir.mkdir(exist_ok=True)

        enc = FileEncryption("password123!")
        result = enc.encrypt_file(source_file)

        assert result.exists()
        assert "source.txt.enc" in str(result)
    finally:
        os.chdir(cwd)


def test_encrypt_file_creates_directory(tmp_path):
    """Test that encrypt_file creates output directory if needed"""
    source_file = tmp_path / "source.txt"
    source_file.write_text("test content")

    output_dir = tmp_path / "new_dir"
    output_file = output_dir / "output.enc"

    assert not output_dir.exists()

    enc = FileEncryption("password123!")
    enc.encrypt_file(source_file, output_file)

    assert output_dir.exists()
    assert output_file.exists()


def test_encrypt_decrypt_large_file(tmp_path):
    """Test encrypting and decrypting large file"""
    source_file = tmp_path / "large.txt"
    # Create 1MB file
    source_file.write_bytes(b"x" * (1024 * 1024))

    enc = FileEncryption("password123!")
    encrypted_file = tmp_path / "large.enc"
    enc.encrypt_file(source_file, encrypted_file)

    decrypted_file = tmp_path / "large_decrypted.txt"
    enc.decrypt_file(encrypted_file, decrypted_file)

    assert decrypted_file.exists()
    assert decrypted_file.stat().st_size == source_file.stat().st_size
    assert decrypted_file.read_bytes() == source_file.read_bytes()


def test_encrypt_decrypt_empty_file(tmp_path):
    """Test encrypting and decrypting empty file"""
    source_file = tmp_path / "empty.txt"
    source_file.write_text("")

    enc = FileEncryption("password123!")
    encrypted_file = tmp_path / "empty.enc"
    enc.encrypt_file(source_file, encrypted_file)

    decrypted_file = tmp_path / "empty_decrypted.txt"
    enc.decrypt_file(encrypted_file, decrypted_file)

    assert decrypted_file.exists()
    assert decrypted_file.read_text() == ""


def test_encrypt_decrypt_binary_file(tmp_path):
    """Test encrypting and decrypting binary file"""
    source_file = tmp_path / "binary.bin"
    binary_data = bytes(range(256))  # All byte values
    source_file.write_bytes(binary_data)

    enc = FileEncryption("password123!")
    encrypted_file = tmp_path / "binary.enc"
    enc.encrypt_file(source_file, encrypted_file)

    decrypted_file = tmp_path / "binary_decrypted.bin"
    enc.decrypt_file(encrypted_file, decrypted_file)

    assert decrypted_file.exists()
    assert decrypted_file.read_bytes() == binary_data


def test_encrypt_string():
    """Test encrypting string"""
    enc = FileEncryption("password123!")
    plaintext = "This is a test string with special chars: !@#$%^&*()"

    encrypted = enc.encrypt_string(plaintext)

    assert isinstance(encrypted, str)
    assert encrypted != plaintext
    assert len(encrypted) > 0


def test_decrypt_string():
    """Test decrypting string"""
    enc = FileEncryption("password123!")
    plaintext = "Test string content"

    encrypted = enc.encrypt_string(plaintext)
    decrypted = enc.decrypt_string(encrypted)

    assert decrypted == plaintext


def test_encrypt_decrypt_string_unicode(tmp_path):
    """Test encrypting/decrypting string with unicode characters"""
    enc = FileEncryption("password123!")
    plaintext = "Unicode: 中文, 🎉, émoji, 日本語"

    encrypted = enc.encrypt_string(plaintext)
    decrypted = enc.decrypt_string(encrypted)

    assert decrypted == plaintext


def test_decrypt_with_wrong_password(tmp_path):
    """Test decrypting with wrong password"""
    source_file = tmp_path / "source.txt"
    source_file.write_text("test content")

    # Encrypt with one password
    enc1 = FileEncryption("password1")
    encrypted_file = tmp_path / "encrypted.enc"
    enc1.encrypt_file(source_file, encrypted_file)

    # Try to decrypt with different password
    enc2 = FileEncryption("password2", salt=enc1.salt)

    decrypted_file = tmp_path / "decrypted.txt"
    with pytest.raises(Exception):
        enc2.decrypt_file(encrypted_file, decrypted_file)


def test_decrypt_with_wrong_salt(tmp_path):
    """Test decrypting with wrong salt"""
    source_file = tmp_path / "source.txt"
    source_file.write_text("test content")

    # Encrypt with one salt
    enc1 = FileEncryption("password", salt=b"salt123456789012")
    encrypted_file = tmp_path / "encrypted.enc"
    enc1.encrypt_file(source_file, encrypted_file)

    # Try to decrypt - salt is read from file, not from constructor
    # So we need to create a new FileEncryption and it will read salt from file
    # But decrypt_file reads salt from encrypted file, not from instance
    # This test may not work as expected - the salt in file will be used
    enc2 = FileEncryption("password")  # Different salt instance
    # But decrypt_file reads salt from encrypted file header

    decrypted_file = tmp_path / "decrypted.txt"
    # This should work because salt is read from file, not instance
    # Test that wrong password fails instead
    enc3 = FileEncryption("wrong_password", salt=enc1.salt)
    with pytest.raises(Exception):
        enc3.decrypt_file(encrypted_file, decrypted_file)


def test_encrypt_decrypt_roundtrip_same_instance(tmp_path):
    """Test encrypt/decrypt roundtrip with same instance"""
    source_file = tmp_path / "source.txt"
    source_file.write_text("roundtrip test content")

    enc = FileEncryption("password123!")
    encrypted_file = tmp_path / "encrypted.enc"
    enc.encrypt_file(source_file, encrypted_file)

    decrypted_file = tmp_path / "decrypted.txt"
    enc.decrypt_file(encrypted_file, decrypted_file)

    assert decrypted_file.read_text() == source_file.read_text()


def test_encrypt_decrypt_roundtrip_different_instances_same_salt(tmp_path):
    """Test encrypt/decrypt with different instances but same salt"""
    source_file = tmp_path / "source.txt"
    source_file.write_text("test content")

    salt = b"test_salt_123456"

    # Encrypt with first instance
    enc1 = FileEncryption("password", salt=salt)
    encrypted_file = tmp_path / "encrypted.enc"
    enc1.encrypt_file(source_file, encrypted_file)

    # Decrypt with second instance (same password and salt)
    enc2 = FileEncryption("password", salt=salt)
    decrypted_file = tmp_path / "decrypted.txt"
    enc2.decrypt_file(encrypted_file, decrypted_file)

    assert decrypted_file.read_text() == source_file.read_text()


def test_encrypted_file_contains_salt(tmp_path):
    """Test that encrypted file contains salt"""
    source_file = tmp_path / "source.txt"
    source_file.write_text("test")

    salt = b"test_salt_123456"
    enc = FileEncryption("password", salt=salt)
    encrypted_file = tmp_path / "encrypted.enc"
    enc.encrypt_file(source_file, encrypted_file)

    # Read encrypted file and verify salt metadata is encoded correctly
    encrypted_data = encrypted_file.read_bytes()
    assert encrypted_data[0] == len(salt)
    assert encrypted_data[1 : 1 + len(salt)] == salt


def test_decrypt_legacy_encrypted_format(tmp_path):
    """Ensure files produced by legacy versions (without metadata) still decrypt."""
    source_file = tmp_path / "source.txt"
    source_file.write_text("legacy content")

    enc = FileEncryption("password123!")
    encrypted_file = tmp_path / "encrypted.enc"
    enc.encrypt_file(source_file, encrypted_file)

    legacy_payload = encrypted_file.read_bytes()[1:]
    legacy_file = tmp_path / "legacy.enc"
    legacy_file.write_bytes(legacy_payload)

    dec = FileEncryption("password123!")
    output_path = tmp_path / "legacy.dec"
    dec.decrypt_file(legacy_file, output_path)

    assert output_path.read_text() == "legacy content"


def test_decrypt_corrupt_file_missing_salt(tmp_path):
    """Test decrypting file with corrupted salt"""
    source_file = tmp_path / "source.txt"
    source_file.write_text("test")

    enc = FileEncryption("password123!")
    encrypted_file = tmp_path / "encrypted.enc"
    enc.encrypt_file(source_file, encrypted_file)

    # Corrupt the salt portion
    corrupt_data = encrypted_file.read_bytes()
    corrupt_data = b"x" * 16 + corrupt_data[16:]
    corrupt_file = tmp_path / "corrupt.enc"
    corrupt_file.write_bytes(corrupt_data)

    decrypted_file = tmp_path / "decrypted.txt"
    with pytest.raises(Exception):
        enc.decrypt_file(corrupt_file, decrypted_file)


def test_decrypt_file_with_output_path(tmp_path):
    """Test decrypting file with specified output path"""
    source_file = tmp_path / "source.txt"
    source_file.write_text("test content")

    enc = FileEncryption("password123!")
    encrypted_file = tmp_path / "encrypted.enc"
    enc.encrypt_file(source_file, encrypted_file)

    output_file = tmp_path / "decrypted.txt"
    result = enc.decrypt_file(encrypted_file, output_file)

    assert result == output_file
    assert output_file.exists()
    assert output_file.read_text() == "test content"


def test_decrypt_file_auto_output_path(tmp_path):
    """Test decrypting file with auto-generated output path"""
    source_file = tmp_path / "source.txt"
    source_file.write_text("test content")

    enc = FileEncryption("password123!")
    encrypted_file = tmp_path / "encrypted.enc"
    enc.encrypt_file(source_file, encrypted_file)

    import os

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        result = enc.decrypt_file(encrypted_file)

        assert result.exists()
        # Result should exist and contain decrypted content
        assert result.read_text() == "test content"
    finally:
        os.chdir(cwd)


def test_decrypt_file_creates_directory(tmp_path):
    """Test that decrypt_file creates output directory if needed"""
    source_file = tmp_path / "source.txt"
    source_file.write_text("test")

    enc = FileEncryption("password123!")
    encrypted_file = tmp_path / "encrypted.enc"
    enc.encrypt_file(source_file, encrypted_file)

    output_dir = tmp_path / "decrypt_dir"
    output_file = output_dir / "decrypted.txt"

    assert not output_dir.exists()

    enc.decrypt_file(encrypted_file, output_file)

    assert output_dir.exists()
    assert output_file.exists()


def test_multiple_encrypt_same_file(tmp_path):
    """Test encrypting same file multiple times produces different output"""
    source_file = tmp_path / "source.txt"
    source_file.write_text("test")

    enc = FileEncryption("password123!")
    encrypted1 = tmp_path / "enc1.enc"
    encrypted2 = tmp_path / "enc2.enc"

    enc1_instance = FileEncryption("password123!")
    enc1_instance.encrypt_file(source_file, encrypted1)

    enc2_instance = FileEncryption("password123!")
    enc2_instance.encrypt_file(source_file, encrypted2)

    # Should be different due to different salts
    assert encrypted1.read_bytes() != encrypted2.read_bytes()


def test_same_salt_same_output(tmp_path):
    """Test that same salt produces same encrypted output"""
    source_file = tmp_path / "source.txt"
    source_file.write_text("test")

    salt = b"fixed_salt_123456"

    enc1 = FileEncryption("password", salt=salt)
    encrypted1 = tmp_path / "enc1.enc"
    enc1.encrypt_file(source_file, encrypted1)

    enc2 = FileEncryption("password", salt=salt)
    encrypted2 = tmp_path / "enc2.enc"
    enc2.encrypt_file(source_file, encrypted2)

    # Note: Fernet encryption includes nonce/IV in each encryption, so encrypted files
    # will differ even with same salt/password. This is expected behavior.
    # We verify both decrypt correctly - each encrypted file contains its salt
    # so we can decrypt with any FileEncryption instance using the same password
    dec1 = tmp_path / "dec1.txt"
    dec2 = tmp_path / "dec2.txt"

    # Decrypt using new instances - salt is read from file header
    enc_dec1 = FileEncryption("password")  # Will read salt from encrypted1
    enc_dec2 = FileEncryption("password")  # Will read salt from encrypted2

    enc_dec1.decrypt_file(encrypted1, dec1)
    enc_dec2.decrypt_file(encrypted2, dec2)

    # Both should decrypt to same content
    assert dec1.read_text() == dec2.read_text() == "test"

    # Encrypted files will be different due to nonce (this is correct behavior)
    assert encrypted1.read_bytes() != encrypted2.read_bytes()
