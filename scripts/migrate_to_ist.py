"""
Migrate existing SQLite database timestamps from UTC to India Standard Time (IST = +05:30).
"""
import sqlite3
from datetime import datetime, timedelta

DB_PATH = "database/aegisai.db"

def migrate():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # 1. Update alerts.timestamp
    c.execute("SELECT id, timestamp FROM alerts WHERE timestamp IS NOT NULL")
    rows = c.fetchall()
    updated_alerts = 0
    for row_id, ts_str in rows:
        try:
            # Format: '2026-09-29 09:01:22.936064'
            if "." in ts_str:
                dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
            else:
                dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            # Shift by +5 hours 30 minutes to match IST
            dt_ist = dt + timedelta(hours=5, minutes=30)
            c.execute("UPDATE alerts SET timestamp = ? WHERE id = ?", (dt_ist.strftime("%Y-%m-%d %H:%M:%S.%f"), row_id))
            updated_alerts += 1
        except Exception as e:
            pass

    # 2. Update actions.timestamp
    c.execute("SELECT id, timestamp FROM actions WHERE timestamp IS NOT NULL")
    rows = c.fetchall()
    updated_actions = 0
    for row_id, ts_str in rows:
        try:
            if "." in ts_str:
                dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
            else:
                dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            dt_ist = dt + timedelta(hours=5, minutes=30)
            c.execute("UPDATE actions SET timestamp = ? WHERE id = ?", (dt_ist.strftime("%Y-%m-%d %H:%M:%S.%f"), row_id))
            updated_actions += 1
        except Exception:
            pass

    conn.commit()
    conn.close()

    print(f"Migration completed successfully:")
    print(f"  - Updated {updated_alerts} alert timestamps to India Standard Time (IST)")
    print(f"  - Updated {updated_actions} action timestamps to India Standard Time (IST)")

if __name__ == "__main__":
    migrate()
