from sqlalchemy import inspect, text

from database.init_db import create_db_engine, migrate_schema


def test_migrate_schema_adds_response_columns_and_tables(tmp_path):
    engine = create_db_engine(f"sqlite:///{tmp_path / 'extensions.sqlite'}")
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE actions (id INTEGER PRIMARY KEY)"))
        migrate_schema(engine)
        inspector = inspect(engine)
        action_columns = {column["name"] for column in inspector.get_columns("actions")}
        assert {"mode", "policy_rule_id", "approval_status", "expires_at", "target_ip", "audit_metadata"} <= action_columns
        assert {"policy_rules", "incidents", "alert_feedback", "assets", "response_audit", "response_approvals", "saved_searches", "watchlists", "admin_tool_audit"} <= set(inspector.get_table_names())
    finally:
        engine.dispose()