from pathlib import Path

import pytest

from app.encryption.file_crypto import FileEncryption


def test_encrypt_raises_on_missing_file(tmp_path):
    enc = FileEncryption("StrongPassword123!")
    with pytest.raises(Exception):
        enc.encrypt_file(tmp_path / "no-such.txt")


def test_decrypt_raises_on_corrupt_file(tmp_path):
    # write a bogus encrypted file
    corrupt = tmp_path / "bad.enc"
    corrupt.write_bytes(b"not a valid payload")
    enc = FileEncryption("StrongPassword123!")
    with pytest.raises(Exception):
        enc.decrypt_file(corrupt)
