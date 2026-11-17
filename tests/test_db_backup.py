import sqlite3

from scripts.db_backup import main


def test_backup_and_restore_preserve_a_consistent_sqlite_snapshot(tmp_path):
    database_path = tmp_path / "source.db"
    backup_path = tmp_path / "backup.db"
    restored_path = tmp_path / "restored.db"
    with sqlite3.connect(database_path) as connection:
        connection.execute("CREATE TABLE sample (value TEXT)")
        connection.execute("INSERT INTO sample VALUES ('before')")

    database_url = f"sqlite:///{database_path.as_posix()}"
    assert main(["backup", str(backup_path), "--database-url", database_url]) == 0
    with sqlite3.connect(database_path) as connection:
        connection.execute("INSERT INTO sample VALUES ('after')")
    assert main(["restore", str(backup_path), str(restored_path)]) == 0

    with sqlite3.connect(restored_path) as connection:
        values = connection.execute("SELECT value FROM sample ORDER BY rowid").fetchall()
    assert values == [("before",)]
    assert main(["restore", str(backup_path), str(restored_path)]) == 1
