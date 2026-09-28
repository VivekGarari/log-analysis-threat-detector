import sqlite3
from collections.abc import Generator
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request

from threat_detector.api.models import (
    FindingDetailResponse,
    FindingSummaryResponse,
    FindingsListResponse,
)
from threat_detector.investigation.service import (
    FindingNotFoundError,
    InvalidInvestigationQuery,
    get_finding_view,
    list_investigations,
)
from threat_detector.persistence.schema import connect


router = APIRouter(prefix="/findings", tags=["findings"])
FINDINGS_QUERY_PARAMETERS = frozenset(
    {
        "severity",
        "finding_type",
        "source_ip",
        "from_timestamp",
        "to_timestamp",
        "limit",
        "cursor",
    }
)


def get_connection(request: Request) -> Generator[sqlite3.Connection, None, None]:
    connection = connect(request.app.state.database_path)
    try:
        yield connection
    finally:
        connection.close()


@router.get("", response_model=FindingsListResponse)
def list_findings_endpoint(
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
    request: Request,
    severity: str | None = None,
    finding_type: str | None = None,
    source_ip: str | None = None,
    from_timestamp: str | None = None,
    to_timestamp: str | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    cursor: str | None = None,
) -> FindingsListResponse:
    unknown_parameters = set(request.query_params).difference(
        FINDINGS_QUERY_PARAMETERS
    )
    if unknown_parameters:
        names = ", ".join(sorted(unknown_parameters))
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported query parameter(s): {names}",
        )

    try:
        page = list_investigations(
            connection,
            severity=severity,
            finding_type=finding_type,
            source_ip=source_ip,
            from_timestamp=from_timestamp,
            to_timestamp=to_timestamp,
            limit=limit,
            cursor=cursor,
        )
    except InvalidInvestigationQuery as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    items = [
        FindingSummaryResponse(
            id=item.finding_pk,
            finding_id=item.finding_id,
            finding_type=item.finding_type,
            severity=item.severity,
            title=item.title,
            timestamp=item.timestamp,
            source_ip=item.source_ip,
            username=item.username,
        )
        for item in page.items
    ]
    return FindingsListResponse(items=items, next_cursor=page.next_cursor)


@router.get("/{finding_pk}", response_model=FindingDetailResponse)
def get_finding_endpoint(
    finding_pk: Annotated[int, Path(gt=0)],
    connection: Annotated[sqlite3.Connection, Depends(get_connection)],
) -> FindingDetailResponse:
    try:
        view = get_finding_view(connection, finding_pk)
    except FindingNotFoundError as error:
        raise HTTPException(status_code=404, detail="Finding not found") from error
    return FindingDetailResponse.model_validate(view)