from sqlalchemy.orm import sessionmaker

from backend import auth
from database import init_db, models


def test_security_config_rejects_example_values(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "replace-with-a-long-secret-value-that-is-not-real")
    monkeypatch.setenv("AEGIS_ADMIN_PASSWORD", "replace-with-admin-password")
    monkeypatch.setenv("AEGIS_VIEWER_PASSWORD", "replace-with-viewer-password")

    try:
        auth.validate_security_config()
    except RuntimeError as error:
        assert "SECRET_KEY" in str(error)
    else:
        raise AssertionError("Placeholder secrets must be rejected")


def test_bootstrap_users_are_persistent_and_token_role_is_database_backed(tmp_path, monkeypatch):
    engine = init_db.create_db_engine(f"sqlite:///{tmp_path / 'auth.sqlite'}")
    models.Base.metadata.create_all(bind=engine)
    test_sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(init_db, "SessionLocal", test_sessions)
    monkeypatch.setenv("SECRET_KEY", "test-only-aegisai-secret-key-0123456789")
    monkeypatch.setenv("AEGIS_ADMIN_USERNAME", "bootstrap-admin")
    monkeypatch.setenv("AEGIS_ADMIN_PASSWORD", "a-distinct-admin-password")
    monkeypatch.setenv("AEGIS_VIEWER_USERNAME", "bootstrap-viewer")
    monkeypatch.setenv("AEGIS_VIEWER_PASSWORD", "a-distinct-viewer-password")

    try:
        auth.ensure_bootstrap_users()
        admin = auth.authenticate_user("bootstrap-admin", "a-distinct-admin-password")
        viewer = auth.authenticate_user("bootstrap-viewer", "a-distinct-viewer-password")

        assert admin is not None
        assert admin["role"] == "admin"
        assert admin["hashed_password"] != "a-distinct-admin-password"
        assert viewer is not None
        assert viewer["role"] == "viewer"

        token = auth.create_access_token({"sub": "bootstrap-viewer", "role": "viewer"})
        db = test_sessions()
        try:
            row = db.query(models.User).filter_by(username="bootstrap-viewer").one()
            row.role = "admin"
            db.commit()
        finally:
            db.close()
        assert auth.get_user_from_token(token)["role"] == "admin"
    finally:
        engine.dispose()
