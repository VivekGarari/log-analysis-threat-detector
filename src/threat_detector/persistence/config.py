import os
from pathlib import Path


DEFAULT_DATABASE_PATH = "threat_detector.sqlite3"
DATABASE_ENVIRONMENT_VARIABLE = "THREAT_DETECTOR_DATABASE"


def resolve_database_path(database_path: str | Path | None = None) -> str:
    return str(
        database_path
        or os.environ.get(DATABASE_ENVIRONMENT_VARIABLE)
        or DEFAULT_DATABASE_PATH
    )