"""Basic test to verify testing infrastructure works."""

def test_imports():
    """Test that basic imports work."""
    try:
        import sys
        import os
        assert True
    except ImportError:
        assert False, "Basic imports failed"

def test_python_version():
    """Test Python version is 3.10+."""
    import sys
    assert sys.version_info >= (3, 10), "Python 3.10+ required"

def test_placeholder():
    """Placeholder test that always passes."""
    assert 1 + 1 == 2