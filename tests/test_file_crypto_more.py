from app.encryption.file_crypto import FileEncryption


def test_get_salt_present():
    enc = FileEncryption("pw")
    s = enc.get_salt()
    assert isinstance(s, (bytes, bytearray)) and len(s) == 16
