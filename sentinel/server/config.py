import os
from dataclasses import dataclass


@dataclass
class Settings:
    db_path: str = os.environ.get("SENTINEL_DB", "sentinel.db")
    token: str = os.environ.get("SENTINEL_TOKEN", "dev-token")
    # Dangerous features are off unless explicitly enabled.
    allow_suspend: bool = os.environ.get("SENTINEL_ALLOW_SUSPEND", "0") == "1"
    allow_auto_contain: bool = os.environ.get("SENTINEL_ALLOW_AUTO", "0") == "1"
