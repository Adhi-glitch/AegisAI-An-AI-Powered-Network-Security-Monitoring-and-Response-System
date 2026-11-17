import os
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.orm import Session

from database import models
from database.init_db import PROJECT_ROOT, create_db_engine


def test_postgres_migration_and_persistence():
    database_url = os.getenv("AEGIS_TEST_POSTGRES_URL")
    if not database_url:
        pytest.skip("Set AEGIS_TEST_POSTGRES_URL to run PostgreSQL integration checks.")

    engine = create_db_engine(database_url)
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    try:
        with engine.connect() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            command.check(config)
        with Session(engine) as session:
            asset = models.Asset(
                ip=f"198.51.100.{int(uuid4().hex[:2], 16)}",
                criticality="medium",
                tags=["migration-smoke"],
            )
            session.add(asset)
            session.commit()
            stored = session.get(models.Asset, asset.id)
            assert stored is not None
            assert stored.tags == ["migration-smoke"]
    finally:
        engine.dispose()
