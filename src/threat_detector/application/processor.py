from collections.abc import Iterable
from pathlib import Path
from typing import TypeVar

from threat_detector.application.pipeline import DetectionPipeline, ProcessingResult
from threat_detector.persistence.config import resolve_database_path
from threat_detector.persistence.repository import save_finding
from threat_detector.persistence.schema import connect, initialize_schema

ParsedEvent = TypeVar("ParsedEvent")


def process_and_persist(
    pipeline: DetectionPipeline[ParsedEvent],
    records: Iterable[str],
    database_path: str | Path | None = None,
) -> ProcessingResult:
    result = pipeline.process_with_findings(records)
    if not result.findings:
        return result

    connection = connect(resolve_database_path(database_path))
    try:
        initialize_schema(connection)
        connection.execute("BEGIN")
        for finding in result.findings:
            save_finding(connection, finding)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    return result