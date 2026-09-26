from dataclasses import dataclass
from datetime import datetime
from typing import Literal

EntityKind = Literal["source_ip", "username"]


@dataclass(frozen=True)
class EntityRef:
    """A structural reference to an investigation entity.

    This is not proof of identity: source IPs and usernames are structural
    attributes of existing Alerts/NormalizedEvents, not verified identities.
    """

    kind: EntityKind
    value: str


@dataclass(frozen=True)
class TimelineEntry:
    """One chronological point in a Finding's timeline.

    Built only from structured Alert/NormalizedEvent fields; never from raw
    log strings.
    """

    timestamp: datetime
    kind: Literal["alert", "event"]
    source_label: str
    description: str
    source_ip: str | None
    username: str | None


@dataclass(frozen=True)
class FindingTimeline:
    """A deterministically ordered view over one Finding's contributing data."""

    finding_id: str
    entries: tuple[TimelineEntry, ...]


@dataclass(frozen=True)
class FindingView:
    """A read-only, analyst-facing projection of a Finding."""

    finding_id: str
    finding_type: str
    severity: str
    title: str
    description: str
    timestamp: datetime
    entities: tuple[EntityRef, ...]
    timeline: FindingTimeline
    evidence: tuple[str, ...]
