import tempfile
from pathlib import Path

from app.encryption.file_crypto import FileEncryption


def test_encrypt_decrypt_roundtrip(tmp_path):
    content = b"hello secret world"
    src = tmp_path / "sample.txt"
    src.write_bytes(content)

    enc = FileEncryption(password="TestEncryptionPassword123!")
    enc_path = tmp_path / "sample.txt.enc"
    out = enc.encrypt_file(src, enc_path)
    assert out.exists()

    # decrypt
    dec_out = tmp_path / "sample.txt.dec"
    dec_path = enc.decrypt_file(enc_path, dec_out)
    assert dec_path.read_bytes() == content


def test_string_encrypt_decrypt():
    enc = FileEncryption(password="AnotherStrongPass!123")
    text = "S3cret Text"
    cipher = enc.encrypt_string(text)
    plain = enc.decrypt_string(cipher)
    assert plain == text
