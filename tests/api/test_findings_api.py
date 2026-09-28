import asyncio
import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
import httpx

from threat_detector.api.app import create_app
from threat_detector.api.routes import get_connection
from threat_detector.alerts.models import Alert
from threat_detector.correlation.models import Finding
from threat_detector.normalization.event import NormalizedEvent
from threat_detector.persistence.repository import save_finding
from threat_detector.persistence.schema import connect, initialize_schema


BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_finding(
    *,
    finding_id: str = "finding-1",
    finding_type: str = "credential_attack_success",
    severity: str = "critical",
    title: str = "Finding title",
    offset: int = 0,
    timestamp: datetime | None = None,
    source_ip: str | None = "192.0.2.10",
    username: str | None = "root",
    details: bool = False,
) -> Finding:
    alerts = (
        Alert(
            alert_id="alert-1",
            rule_id="ssh_brute_force",
            severity="high",
            title="Alert title",
            description="Repeated SSH failures",
            timestamp=BASE_TIME + timedelta(seconds=offset - 30),
            source_ip=source_ip,
            username="admin",
            evidence=["alert evidence"],
            raw_events=["PRIVATE ALERT RAW"],
        ),
    ) if details else ()
    events = (
        NormalizedEvent(
            timestamp=BASE_TIME + timedelta(seconds=offset),
            source="test",
            event_type="authentication_success",
            hostname="host-1",
            username=username,
            source_ip=source_ip,
            source_port=22,
            success=True,
            raw="PRIVATE NORMALIZED RAW",
            service="ssh",
        ),
    ) if details else ()
    return Finding(
        finding_id=finding_id,
        finding_type=finding_type,
        severity=severity,
        title=title,
        description="Finding description",
        timestamp=timestamp or BASE_TIME + timedelta(seconds=offset),
        source_ip=source_ip,
        username=username,
        evidence=("finding evidence",),
        contributing_alerts=alerts,
        contributing_events=events,
        raw_events=("PRIVATE FINDING RAW",),
    )


@pytest.fixture
def database_path(tmp_path):
    return tmp_path / "investigations.sqlite3"


def seed(database_path, *findings) -> list[int]:
    connection = connect(str(database_path))
    initialize_schema(connection)
    try:
        return [save_finding(connection, finding) for finding in findings]
    finally:
        connection.close()


class ASGITestClient:
    def __init__(self, application):
        self.application = application

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def get(self, path: str, *, params: dict[str, str] | None = None) -> httpx.Response:
        async def make_request() -> httpx.Response:
            async with self.application.router.lifespan_context(self.application):
                transport = httpx.ASGITransport(app=self.application)
                async with httpx.AsyncClient(
                    transport=transport, base_url="http://test"
                ) as client:
                    return await client.get(path, params=params)

        return asyncio.run(make_request())


def client_for(database_path) -> ASGITestClient:
    return ASGITestClient(create_app(database_path))


def test_empty_database_returns_empty_page(database_path):
    with client_for(database_path) as client:
        response = client.get("/findings")

    assert response.status_code == 200
    assert response.json() == {"items": [], "next_cursor": None}


@pytest.mark.parametrize("finding_pk", [0, -1, 2**63])
def test_cursor_rejects_nonpositive_or_out_of_range_finding_pk(
    database_path, finding_pk
):
    cursor = base64.urlsafe_b64encode(
        json.dumps([BASE_TIME.isoformat(), finding_pk]).encode("utf-8")
    ).decode("ascii").rstrip("=")

    with client_for(database_path) as client:
        response = client.get("/findings", params={"cursor": cursor})

    assert response.status_code == 422


@pytest.mark.parametrize("parameter", ["unexpected_filter", "severty"])
def test_unknown_query_parameters_are_rejected(database_path, parameter):
    with client_for(database_path) as client:
        response = client.get("/findings", params={parameter: "high"})

    assert response.status_code == 422


def test_list_orders_newest_first_and_uses_pk_for_timestamp_ties(database_path):
    first_pk, second_pk, older_pk = seed(
        database_path,
        make_finding(finding_id="duplicate", title="first", offset=10),
        make_finding(finding_id="duplicate", title="second", offset=10),
        make_finding(title="older", offset=0),
    )

    with client_for(database_path) as client:
        response = client.get("/findings")

    assert response.status_code == 200
    items = response.json()["items"]
    assert [item["id"] for item in items] == [second_pk, first_pk, older_pk]
    assert items[0]["finding_id"] == items[1]["finding_id"] == "duplicate"


@pytest.mark.parametrize(
    ("parameter", "value", "expected_titles"),
    [
        ("severity", "high", ["recon", "high", "target"]),
        ("finding_type", "reconnaissance_credential_attack", ["recon", "high"]),
        ("source_ip", "192.0.2.11", ["other-ip"]),
    ],
)
def test_exact_filters(database_path, parameter, value, expected_titles):
    seed(
        database_path,
        make_finding(title="target", severity="high", source_ip="192.0.2.10"),
        make_finding(
            title="high",
            severity="high",
            finding_type="reconnaissance_credential_attack",
            source_ip="192.0.2.10",
        ),
        make_finding(
            title="recon",
            severity="high",
            finding_type="reconnaissance_credential_attack",
            source_ip="192.0.2.10",
        ),
        make_finding(title="other-ip", source_ip="192.0.2.11"),
    )

    with client_for(database_path) as client:
        response = client.get("/findings", params={parameter: value})

    assert response.status_code == 200
    assert [item["title"] for item in response.json()["items"]] == expected_titles


def test_inclusive_from_and_exclusive_to_timestamp_filters(database_path):
    seed(
        database_path,
        make_finding(title="lower", offset=0),
        make_finding(title="inside", offset=1),
        make_finding(title="upper", offset=2),
    )

    with client_for(database_path) as client:
        response = client.get(
            "/findings",
            params={
                "from_timestamp": BASE_TIME.isoformat(),
                "to_timestamp": (BASE_TIME + timedelta(seconds=2)).isoformat(),
            },
        )

    assert response.status_code == 200
    assert [item["title"] for item in response.json()["items"]] == ["inside", "lower"]


def test_legacy_offset_timestamps_sort_and_filter_chronologically(database_path):
    finding_pks = seed(
        database_path,
        make_finding(title="older-offset"),
        make_finding(title="utc-tie"),
        make_finding(title="offset-tie"),
        make_finding(title="one-microsecond-later"),
    )
    connection = connect(str(database_path))
    try:
        connection.executemany(
            "UPDATE findings SET timestamp = ? WHERE finding_pk = ?",
            [
                ("2026-01-01T01:00:00+02:00", finding_pks[0]),
                ("2026-01-01T00:00:00+00:00", finding_pks[1]),
                ("2026-01-01T02:00:00+02:00", finding_pks[2]),
                ("2026-01-01T00:00:00.000001+00:00", finding_pks[3]),
            ],
        )
        connection.commit()
    finally:
        connection.close()

    with client_for(database_path) as client:
        all_items = client.get("/findings").json()["items"]
        from_items = client.get(
            "/findings", params={"from_timestamp": "2026-01-01T00:00:00Z"}
        ).json()["items"]
        to_items = client.get(
            "/findings", params={"to_timestamp": "2026-01-01T00:00:00Z"}
        ).json()["items"]
        microsecond_items = client.get(
            "/findings",
            params={
                "from_timestamp": "2026-01-01T00:00:00.000001Z",
                "to_timestamp": "2026-01-01T00:00:00.000002Z",
            },
        ).json()["items"]

    assert [item["title"] for item in all_items] == [
        "one-microsecond-later",
        "offset-tie",
        "utc-tie",
        "older-offset",
    ]
    assert [item["title"] for item in from_items] == [
        "one-microsecond-later",
        "offset-tie",
        "utc-tie",
    ]
    assert [item["title"] for item in to_items] == ["older-offset"]
    assert [item["title"] for item in microsecond_items] == [
        "one-microsecond-later"
    ]


def test_timestamp_filters_preserve_microsecond_precision(database_path):
    seed(
        database_path,
        make_finding(title="first-microsecond", offset=0),
        make_finding(
            title="second-microsecond",
            timestamp=BASE_TIME + timedelta(microseconds=1),
        ),
    )

    with client_for(database_path) as client:
        response = client.get(
            "/findings",
            params={
                "from_timestamp": (BASE_TIME + timedelta(microseconds=1)).isoformat(),
                "to_timestamp": (BASE_TIME + timedelta(microseconds=2)).isoformat(),
            },
        )

    assert response.status_code == 200
    assert [item["title"] for item in response.json()["items"]] == ["second-microsecond"]


def test_source_ip_filter_is_parameterized(database_path):
    seed(database_path, make_finding())

    with client_for(database_path) as client:
        response = client.get(
            "/findings", params={"source_ip": "192.0.2.10' OR 1=1 --"}
        )

    assert response.status_code == 200
    assert response.json() == {"items": [], "next_cursor": None}


@pytest.mark.parametrize(
    "query_timestamp",
    [
        "2026-01-01T05:30:00+05:30",
        "2025-12-31T19:00:00-05:00",
    ],
)
def test_timezone_offsets_are_normalized_for_query_filters(database_path, query_timestamp):
    seed(database_path, make_finding(title="utc", offset=0))

    with client_for(database_path) as client:
        response = client.get(
            "/findings",
            params={"from_timestamp": query_timestamp},
        )

    assert response.status_code == 200
    assert [item["title"] for item in response.json()["items"]] == ["utc"]


@pytest.mark.parametrize(
    "params",
    [
        {"from_timestamp": "2026-01-01T00:00:00"},
        {"from_timestamp": "not-a-timestamp"},
        {"from_timestamp": "9999-12-31T23:59:59-14:00"},
        {
            "from_timestamp": "2026-01-02T00:00:00Z",
            "to_timestamp": "2026-01-01T00:00:00Z",
        },
        {"severity": "medium"},
        {"finding_type": "unknown"},
        {"limit": "0"},
        {"limit": "101"},
        {"cursor": "not-a-cursor"},
    ],
)
def test_invalid_query_returns_422(database_path, params):
    with client_for(database_path) as client:
        response = client.get("/findings", params=params)

    assert response.status_code == 422


def test_combined_filters_and_limit_maximum(database_path):
    seed(
        database_path,
        make_finding(title="match", severity="high", source_ip="192.0.2.10"),
        make_finding(title="wrong-severity", source_ip="192.0.2.10"),
        make_finding(title="wrong-ip", severity="high", source_ip="192.0.2.11"),
    )

    with client_for(database_path) as client:
        response = client.get(
            "/findings",
            params={
                "severity": "high",
                "finding_type": "credential_attack_success",
                "source_ip": "192.0.2.10",
                "limit": "100",
            },
        )

    assert response.status_code == 200
    assert [item["title"] for item in response.json()["items"]] == ["match"]


def test_cursor_pagination_and_duplicate_ids_are_independently_addressable(database_path):
    first_pk, second_pk, third_pk = seed(
        database_path,
        make_finding(finding_id="same-id", title="first", offset=2),
        make_finding(finding_id="same-id", title="second", offset=1),
        make_finding(finding_id="same-id", title="third", offset=0),
    )

    with client_for(database_path) as client:
        first_page = client.get("/findings", params={"limit": 1})
        cursor = first_page.json()["next_cursor"]
        second_page = client.get("/findings", params={"limit": 1, "cursor": cursor})
        third_page = client.get(
            "/findings", params={"limit": 1, "cursor": second_page.json()["next_cursor"]}
        )
        detail = client.get(f"/findings/{second_pk}")

    assert [first_page.json()["items"][0]["id"], second_page.json()["items"][0]["id"], third_page.json()["items"][0]["id"]] == [first_pk, second_pk, third_pk]
    assert first_page.json()["next_cursor"] is not None
    assert third_page.json()["next_cursor"] is None
    assert detail.status_code == 200
    assert detail.json()["title"] == "second"


def test_detail_preserves_finding_view_and_excludes_raw_and_database_ids(database_path):
    finding_pk = seed(database_path, make_finding(details=True))[0]

    with client_for(database_path) as client:
        response = client.get(f"/findings/{finding_pk}")

    assert response.status_code == 200
    value = response.json()
    assert value["finding_id"] == "finding-1"
    assert value["entities"] == [
        {"kind": "source_ip", "value": "192.0.2.10"},
        {"kind": "username", "value": "root"},
        {"kind": "username", "value": "admin"},
    ]
    assert [entry["kind"] for entry in value["timeline"]["entries"]] == [
        "alert",
        "event",
    ]
    assert value["evidence"] == ["finding evidence"]
    serialized = response.text
    assert "raw_events" not in value
    assert "id" not in value and "finding_pk" not in value
    assert "alert_pk" not in serialized and "event_pk" not in serialized
    assert "PRIVATE" not in serialized


def test_missing_detail_returns_404(database_path):
    with client_for(database_path) as client:
        response = client.get("/findings/999")

    assert response.status_code == 404
    assert response.json() == {"detail": "Finding not found"}


def test_database_errors_are_generic_and_do_not_leak_details(database_path):
    application = create_app(database_path)
    closed_connection = connect(":memory:")
    closed_connection.close()
    application.dependency_overrides[get_connection] = lambda: closed_connection

    with ASGITestClient(application) as client:
        response = client.get("/findings")

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "SELECT" not in response.text
    assert str(database_path) not in response.text