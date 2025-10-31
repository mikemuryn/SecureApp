from pathlib import Path

from app.encryption.file_crypto import FileEncryption


def test_encrypt_default_path_creates_dir(tmp_path, monkeypatch):
    # run in tmp so default 'encrypted' lives under tmp
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "x.txt"
    src.write_text("data")
    enc = FileEncryption("StrongPassword123!")
    out = enc.encrypt_file(src)
    assert out.exists()
    assert out.parent.name == "encrypted"


def test_decrypt_default_output(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "y.txt"
    src.write_text("data2")
    enc = FileEncryption("StrongPassword123!")
    enc_path = enc.encrypt_file(src)
    # use default output path (temp/<name>)
    dec = enc.decrypt_file(enc_path)
    assert dec.exists() and dec.read_text() == "data2"
