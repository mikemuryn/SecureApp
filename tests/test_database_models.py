from app.models.database import AuditLog, DatabaseManager, SecureFile, User


def test_database_crud(temp_db_file):
    db = DatabaseManager(temp_db_file)
    db.create_tables()
    session = db.get_session()
    try:
        u = User(
            username="dave",
            email="dave@example.com",
            password_hash="x",
            salt="y",
            role="user",
        )
        session.add(u)
        session.commit()
        assert u.id is not None

        f = SecureFile(
            filename="a.txt",
            original_path="/tmp/a.txt",
            encrypted_path="/tmp/a.txt.enc",
            file_hash="h",
            file_size=1,
            owner_id=u.id,
        )
        session.add(f)
        session.commit()
        assert f.id is not None

        a = AuditLog(user_id=u.id, action="login", success=True)
        session.add(a)
        session.commit()
        assert a.id is not None
    finally:
        db.close_session(session)
