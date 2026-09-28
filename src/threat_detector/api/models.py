from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from threat_detector.investigation.models import EntityKind


class FindingSummaryResponse(BaseModel):
    id: int
    finding_id: str
    finding_type: str
    severity: str
    title: str
    timestamp: datetime
    source_ip: str | None
    username: str | None


class FindingsListResponse(BaseModel):
    items: list[FindingSummaryResponse]
    next_cursor: str | None


class EntityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    kind: EntityKind
    value: str


class TimelineEntryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    timestamp: datetime
    kind: Literal["alert", "event"]
    source_label: str
    description: str
    source_ip: str | None
    username: str | None


class FindingTimelineResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    entries: list[TimelineEntryResponse]


class FindingDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    finding_type: str
    severity: str
    title: str
    description: str
    timestamp: datetime
    entities: list[EntityResponse]
    timeline: FindingTimelineResponse
    evidence: list[str]