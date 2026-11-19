import os
from pathlib import Path
import sys

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from config import get_config
try:
    from .models import Base
except ImportError:  # Direct execution: python database\init_db.py
    from database.models import Base

cfg = get_config()
DB_DIR = PROJECT_ROOT / "database"
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "aegisai.db"
DB_URL = os.getenv("DATABASE_URL", f"sqlite:///{DB_PATH.as_posix()}")


def create_db_engine(database_url: str):
    """Create a SQLAlchemy engine with SQLite-specific connection options."""
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite:") else {}
    return create_engine(database_url, echo=False, connect_args=connect_args)


engine = create_db_engine(DB_URL)
SessionLocal = sessionmaker(bind=engine)


def migrate_schema(database_engine=engine):
    """Add new columns/tables to pre-existing databases when needed."""
    inspector = inspect(database_engine)
    if inspector.has_table("alerts"):
        alert_columns = {
            column["name"] for column in inspector.get_columns("alerts")
        }
        if "severity" not in alert_columns:
            with database_engine.begin() as connection:
                connection.execute(
                    text("ALTER TABLE alerts ADD COLUMN severity VARCHAR(32) DEFAULT 'info'")
                )

    inspector = inspect(database_engine)
    if inspector.has_table("detections"):
        detection_columns = {
            column["name"] for column in inspector.get_columns("detections")
        }
        if "detection_source" not in detection_columns:
            with database_engine.begin() as connection:
                connection.execute(
                    text(
                        "ALTER TABLE detections ADD COLUMN detection_source "
                        "VARCHAR(32) NOT NULL DEFAULT 'model'"
                    )
                )

    # These nullable action fields preserve old rows while enabling response
    # audit, approval, TTL, and rollback workflows for new actions.
    if inspector.has_table("actions"):
        action_columns = {column["name"] for column in inspector.get_columns("actions")}
        additions = {
            "mode": "VARCHAR(32)",
            "policy_rule_id": "VARCHAR(96)",
            "approval_status": "VARCHAR(32)",
            "expires_at": "DATETIME",
            "target_ip": "VARCHAR(45)",
            "audit_metadata": "JSON",
        }
        missing = {name: definition for name, definition in additions.items() if name not in action_columns}
        if missing:
            with database_engine.begin() as connection:
                for name, definition in missing.items():
                    connection.execute(text(f"ALTER TABLE actions ADD COLUMN {name} {definition}"))

    # New tables are created through SQLAlchemy so SQLite and PostgreSQL use
    # the dialect's native types and constraints.
    Base.metadata.create_all(bind=database_engine)


def init_db():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    from alembic import command
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    migration_config = Config(str(PROJECT_ROOT / "alembic.ini"))
    migration_config.set_main_option("sqlalchemy.url", DB_URL.replace("%", "%%"))
    existing_tables = set(inspect(engine).get_table_names())
    if "alembic_version" not in existing_tables:
        if existing_tables:
            migrate_schema(engine)
            base_revision = ScriptDirectory.from_config(migration_config).get_base()
            if base_revision is None:
                raise RuntimeError("No base database migration is configured.")
            command.stamp(migration_config, base_revision)
        command.upgrade(migration_config, "head")
    else:
        command.upgrade(migration_config, "head")
    return DB_PATH


init_db()


if __name__ == "__main__":
    init_db()
    print("Initialized database at", DB_URL)
