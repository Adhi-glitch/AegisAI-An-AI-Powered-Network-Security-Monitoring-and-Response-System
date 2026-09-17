from pathlib import Path
import sqlite3

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import get_config
from .models import Base

cfg = get_config()
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_DIR = PROJECT_ROOT / "database"
DB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DB_DIR / "aegisai.db"
DB_URL = f"sqlite:///{DB_PATH.as_posix()}"

engine = create_engine(DB_URL, echo=False, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)


def migrate_schema():
    """Ensure newly added columns exist in existing SQLite tables."""
    if not DB_PATH.exists():
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check alerts table columns
        cursor.execute("PRAGMA table_info(alerts)")
        columns = [row[1] for row in cursor.fetchall()]
        if columns and "severity" not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN severity VARCHAR(32) DEFAULT 'info'")
            conn.commit()
            
        conn.close()
    except Exception:
        pass


def init_db():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    migrate_schema()
    return DB_PATH


init_db()


if __name__ == "__main__":
    init_db()
    print("Initialized database at", DB_URL)
