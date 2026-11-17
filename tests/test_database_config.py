from sqlalchemy import inspect, text

from database.init_db import create_db_engine, migrate_schema


def test_database_engine_supports_sqlite(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path / 'aegisai.db'}")
    try:
        assert engine.dialect.name == "sqlite"
        with engine.connect():
            pass
    finally:
        engine.dispose()


def test_database_engine_accepts_postgresql_url():
    engine = create_db_engine(
        "postgresql+psycopg2://aegisai:password@localhost:5432/aegisai"
    )
    try:
        assert engine.dialect.name == "postgresql"
    finally:
        engine.dispose()


def test_migrate_schema_adds_detection_source_to_existing_database(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path / 'legacy.sqlite'}")
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE alerts (id INTEGER PRIMARY KEY)"))
            connection.execute(text("CREATE TABLE detections (id INTEGER PRIMARY KEY)"))
            connection.execute(text("INSERT INTO detections (id) VALUES (1)"))

        migrate_schema(engine)

        inspector = inspect(engine)
        assert "severity" in {column["name"] for column in inspector.get_columns("alerts")}
        assert "detection_source" in {
            column["name"] for column in inspector.get_columns("detections")
        }
        with engine.connect() as connection:
            assert connection.execute(
                text("SELECT detection_source FROM detections WHERE id = 1")
            ).scalar_one() == "model"
    finally:
        engine.dispose()
