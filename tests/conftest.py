import os
from pathlib import Path
import tempfile

_TEST_DATABASE_DIR = tempfile.TemporaryDirectory(prefix="aegisai-pytest-")
os.environ["AEGIS_ENV"] = "test"
os.environ["SECRET_KEY"] = "test-only-aegisai-secret-key-0123456789"
os.environ["AEGIS_ADMIN_USERNAME"] = "admin"
os.environ["AEGIS_ADMIN_PASSWORD"] = "test-admin-password-2026"
os.environ["AEGIS_VIEWER_USERNAME"] = "viewer"
os.environ["AEGIS_VIEWER_PASSWORD"] = "test-viewer-password-2026"
os.environ["DATABASE_URL"] = f"sqlite:///{(Path(_TEST_DATABASE_DIR.name) / 'aegisai.db').as_posix()}"


def pytest_unconfigure(config):
    from database.init_db import engine

    engine.dispose()
    _TEST_DATABASE_DIR.cleanup()
