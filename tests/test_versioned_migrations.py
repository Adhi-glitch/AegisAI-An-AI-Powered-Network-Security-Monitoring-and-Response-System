import sqlite3

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import inspect

import database.init_db as database_init


PROJECT_ROOT = database_init.PROJECT_ROOT


def _migration_config():
    return Config(str(PROJECT_ROOT / "alembic.ini"))


def _head_revision():
    return ScriptDirectory.from_config(_migration_config()).get_current_head()


def test_fresh_database_is_created_by_alembic(tmp_path, monkeypatch):
    database_path = tmp_path / "fresh.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    monkeypatch.setenv("DATABASE_URL", database_url)

    command.upgrade(_migration_config(), "head")
    command.check(_migration_config())
    command.downgrade(_migration_config(), "base")
    command.upgrade(_migration_config(), "head")
    command.check(_migration_config())

    with sqlite3.connect(database_path) as connection:
        version = connection.execute("SELECT version_num FROM alembic_version").fetchone()
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert version == (_head_revision(),)
    assert {"alerts", "detections", "incidents", "response_audit", "users"} <= tables
    with sqlite3.connect(database_path) as connection:
        incident_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(incidents)")
        }
    assert {"events", "merged_into_id", "split_from_id"} <= incident_columns


def test_legacy_database_is_preserved_and_stamped(tmp_path, monkeypatch):
    database_path = tmp_path / "legacy.db"
    database_url = f"sqlite:///{database_path.as_posix()}"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TABLE alerts (id INTEGER PRIMARY KEY, timestamp DATETIME, source_ip VARCHAR(45), dest_ip VARCHAR(45), protocol VARCHAR(32), raw_features JSON)"
        )
        connection.execute(
            "INSERT INTO alerts (id, timestamp, source_ip, dest_ip) VALUES (7, '2026-11-14 00:00:00', '203.0.113.1', '198.51.100.2')"
        )
        connection.execute(
            "CREATE TABLE incidents (id INTEGER PRIMARY KEY, incident_key VARCHAR(128) UNIQUE, source_ip VARCHAR(45), dest_ip VARCHAR(45), attack_type VARCHAR(64), severity VARCHAR(32), status VARCHAR(32), kill_chain_stage VARCHAR(64), timeline JSON, created_at DATETIME, updated_at DATETIME)"
        )
        connection.execute(
            "INSERT INTO incidents (id, incident_key, status) VALUES (8, 'legacy-incident', 'open')"
        )

    legacy_engine = database_init.create_db_engine(database_url)
    monkeypatch.setattr(database_init, "engine", legacy_engine)
    monkeypatch.setattr(database_init, "DB_URL", database_url)
    monkeypatch.setenv("DATABASE_URL", database_url)
    try:
        database_init.init_db()
        with sqlite3.connect(database_path) as connection:
            alert = connection.execute(
                "SELECT id, source_ip, severity FROM alerts WHERE id = 7"
            ).fetchone()
            version = connection.execute(
                "SELECT version_num FROM alembic_version"
            ).fetchone()
            incident = connection.execute(
                "SELECT id, incident_key, events FROM incidents WHERE id = 8"
            ).fetchone()
        assert alert == (7, "203.0.113.1", "info")
        assert version == (_head_revision(),)
        assert incident == (8, "legacy-incident", None)
        assert {"events", "merged_into_id", "split_from_id"} <= {
            column["name"]
            for column in inspect(legacy_engine).get_columns("incidents")
        }
    finally:
        legacy_engine.dispose()
