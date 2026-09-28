import base64
import binascii
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from threat_detector.investigation.models import FindingView
from threat_detector.investigation.view import build_finding_view
from threat_detector.persistence.repository import (
    FindingSummary,
    list_findings as repository_list_findings,
    load_finding,
)


SUPPORTED_SEVERITIES = frozenset({"high", "critical"})
SUPPORTED_FINDING_TYPES = frozenset(
    {"credential_attack_success", "reconnaissance_credential_attack"}
)
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
MAX_CURSOR_LENGTH = 512
MAX_SQLITE_INTEGER = (1 << 63) - 1


class InvalidInvestigationQuery(ValueError):
    pass


class FindingNotFoundError(LookupError):
    pass


@dataclass(frozen=True)
class FindingsPage:
    items: tuple[FindingSummary, ...]
    next_cursor: str | None


def _parse_timestamp(value: str, parameter: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise InvalidInvestigationQuery(
            f"{parameter} must be an ISO-8601 timestamp"
        ) from error

    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise InvalidInvestigationQuery(f"{parameter} must include a timezone")
    try:
        return timestamp.astimezone(timezone.utc)
    except OverflowError as error:
        raise InvalidInvestigationQuery(
            f"{parameter} is outside the supported timestamp range"
        ) from error


def _encode_cursor(timestamp: datetime, finding_pk: int) -> str:
    payload = json.dumps(
        [timestamp.astimezone(timezone.utc).isoformat(), finding_pk],
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _decode_cursor(value: str) -> tuple[datetime, int]:
    if not value or len(value) > MAX_CURSOR_LENGTH:
        raise InvalidInvestigationQuery("cursor is malformed")

    try:
        encoded = value.encode("ascii")
        padded = encoded + b"=" * (-len(encoded) % 4)
        payload = base64.b64decode(padded, altchars=b"-_", validate=True)
        decoded = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeError, binascii.Error) as error:
        raise InvalidInvestigationQuery("cursor is malformed") from error

    if (
        not isinstance(decoded, list)
        or len(decoded) != 2
        or not isinstance(decoded[0], str)
        or not isinstance(decoded[1], int)
        or isinstance(decoded[1], bool)
        or decoded[1] < 1
        or decoded[1] > MAX_SQLITE_INTEGER
    ):
        raise InvalidInvestigationQuery("cursor is malformed")

    try:
        timestamp = _parse_timestamp(decoded[0], "cursor timestamp")
    except InvalidInvestigationQuery as error:
        raise InvalidInvestigationQuery("cursor is malformed") from error
    return timestamp, decoded[1]


def list_investigations(
    connection: sqlite3.Connection,
    *,
    severity: str | None = None,
    finding_type: str | None = None,
    source_ip: str | None = None,
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
) -> FindingsPage:
    if severity is not None and severity not in SUPPORTED_SEVERITIES:
        raise InvalidInvestigationQuery("severity is not supported")
    if finding_type is not None and finding_type not in SUPPORTED_FINDING_TYPES:
        raise InvalidInvestigationQuery("finding_type is not supported")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_PAGE_SIZE:
        raise InvalidInvestigationQuery(
            f"limit must be between 1 and {MAX_PAGE_SIZE}"
        )

    start = (
        _parse_timestamp(from_timestamp, "from_timestamp")
        if from_timestamp is not None
        else None
    )
    end = (
        _parse_timestamp(to_timestamp, "to_timestamp")
        if to_timestamp is not None
        else None
    )
    if start is not None and end is not None and start >= end:
        raise InvalidInvestigationQuery(
            "from_timestamp must be earlier than to_timestamp"
        )

    position = _decode_cursor(cursor) if cursor is not None else None
    rows = repository_list_findings(
        connection,
        severity=severity,
        finding_type=finding_type,
        source_ip=source_ip,
        from_timestamp=start,
        to_timestamp=end,
        cursor=position,
        limit=limit,
    )
    items = tuple(rows[:limit])
    next_cursor = (
        _encode_cursor(items[-1].timestamp, items[-1].finding_pk)
        if len(rows) > limit
        else None
    )
    return FindingsPage(items=items, next_cursor=next_cursor)


def get_finding_view(
    connection: sqlite3.Connection, finding_pk: int
) -> FindingView:
    try:
        finding = load_finding(connection, finding_pk)
    except LookupError as error:
        raise FindingNotFoundError from error
    return build_finding_view(finding)