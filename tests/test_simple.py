def test_simple():
    """Simple test to verify pytest is working"""
    assert 1 + 1 == 2


def test_imports():
    """Test that we can import our modules"""
    try:
        from app.auth.authentication import AuthenticationManager
        from app.models.database import DatabaseManager

        assert True
    except ImportError as e:
        assert False, f"Import failed: {e}"
