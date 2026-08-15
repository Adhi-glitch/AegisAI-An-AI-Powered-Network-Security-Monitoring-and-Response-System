import yaml
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

CONFIG_PATH = Path(__file__).parent / "config.yaml"

@dataclass
class Config:
    classes: list
    confidence_tiers: Dict[str, list]
    paths: Dict[str, str]
    database: Dict[str, Any]
    api_keys: Dict[str, str]
    api: Dict[str, Any]


def load_config(path: Path = CONFIG_PATH) -> Config:
    with open(path) as f:
        d = yaml.safe_load(f)
    return Config(
        classes=d.get("classes", []),
        confidence_tiers=d.get("confidence_tiers", {}),
        paths=d.get("paths", {}),
        database=d.get("database", {}),
        api_keys=d.get("api_keys", {}),
        api=d.get("api", {}),
    )


CONFIG = load_config()


def get_config() -> Config:
    return CONFIG
