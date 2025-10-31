# Architecture Overview

SecureApp is a desktop GUI application with the following layers:

- UI: tkinter/customtkinter in `main.py`
- Auth: `app/auth/*`
- Crypto: `app/encryption/file_crypto.py`
- Storage: `app/models/database.py` (SQLite)
- Utilities: `app/utils/*`
- Config: `config/settings.py`

High-level flow: user authentication → session creation → file operations (encrypt/decrypt) → audit logging.
