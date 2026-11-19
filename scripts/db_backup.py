"""Create and restore consistent, integrity-checked SQLite database copies."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sqlite3
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = PROJECT_ROOT / "database" / "aegisai.db"


def _validate_database(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Database file not found: {path}")
    uri = f"{path.resolve().as_uri()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        result = connection.execute("PRAGMA integrity_check").fetchone()
        tables = connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ).fetchone()
    if result is None or result[0] != "ok":
        raise sqlite3.DatabaseError(f"SQLite integrity check failed for {path}")
    if tables is None or tables[0] == 0:
        raise sqlite3.DatabaseError(f"No application tables found in {path}")


def _copy_database(source: Path, destination: Path) -> Path:
    source = source.resolve(strict=True)
    destination = destination.resolve()
    if source == destination:
        raise ValueError("Source and destination must be different files.")
    if destination.exists():
        raise FileExistsError(f"Refusing to overwrite existing file: {destination}")
    if not destination.parent.is_dir():
        raise FileNotFoundError(f"Destination directory does not exist: {destination.parent}")

    descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    try:
        source_uri = f"{source.as_uri()}?mode=ro"
        with sqlite3.connect(source_uri, uri=True) as source_connection:
            with sqlite3.connect(destination) as destination_connection:
                source_connection.backup(destination_connection)
        _validate_database(destination)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    return destination


def _database_path(database_url: str | None) -> Path:
    if not database_url:
        return DEFAULT_DATABASE
    if not database_url.startswith("sqlite:///"):
        raise ValueError("This utility supports SQLite URLs only; PostgreSQL backups require pg_dump.")
    value = database_url.removeprefix("sqlite:///")
    if value.startswith("/") and os.name == "nt" and len(value) > 2 and value[2] == ":":
        value = value[1:]
    return Path(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    backup_parser = subparsers.add_parser("backup", help="create a consistent SQLite backup")
    backup_parser.add_argument("destination", type=Path)
    backup_parser.add_argument("--database-url", default=os.getenv("DATABASE_URL"))
    restore_parser = subparsers.add_parser("restore", help="restore to a new SQLite file")
    restore_parser.add_argument("source", type=Path)
    restore_parser.add_argument("destination", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.command == "backup":
            source = _database_path(args.database_url)
            _validate_database(source)
            result = _copy_database(source, args.destination)
        else:
            _validate_database(args.source)
            result = _copy_database(args.source, args.destination)
        print(f"SQLite database copy verified: {result}")
        return 0
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"Database copy failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
