import json
from datetime import datetime, timezone

import pytest

from threat_detector.alerts.models import Alert
from threat_detector.reporting.json import report
from threat_detector.resource_limits import ResourceLimitExceeded


def make_alert(alert_id: str = "alert-1") -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id="invalid_user",
        severity="medium",
        title="Invalid user",
        description="An invalid username was used",
        timestamp=datetime(2026, 9, 3, 12, 30, tzinfo=timezone.utc),
        source_ip=None,
        username="unknown",
        evidence=["invalid username"],
        raw_events=["raw event"],
    )


def test_one_alert_serializes_all_fields_and_datetime_as_iso8601():
    value = json.loads(report([make_alert()]))[0]

    assert value == {
        "alert_id": "alert-1",
        "rule_id": "invalid_user",
        "severity": "medium",
        "title": "Invalid user",
        "description": "An invalid username was used",
        "timestamp": "2026-09-03T12:30:00+00:00",
        "source_ip": None,
        "username": "unknown",
        "evidence": ["invalid username"],
        "raw_events": ["raw event"],
    }


def test_output_is_valid_json_and_collections_remain_arrays():
    value = json.loads(report([make_alert()]))[0]

    assert value["source_ip"] is None
    assert isinstance(value["evidence"], list)
    assert isinstance(value["raw_events"], list)


def test_multiple_alerts_preserve_input_order():
    value = json.loads(report([make_alert("first"), make_alert("second")]))

    assert [item["alert_id"] for item in value] == ["first", "second"]


def test_empty_input_produces_empty_array():
    assert report([]) == "[]"
    assert report([], max_bytes=2) == "[]"
    with pytest.raises(ResourceLimitExceeded, match="report UTF-8 bytes"):
        report([], max_bytes=1)


def test_report_byte_limit_accepts_exact_size_and_rejects_one_byte_less():
    alerts = [make_alert()]
    expected = report(alerts)

    assert report(alerts, max_bytes=len(expected.encode("utf-8"))) == expected
    with pytest.raises(ResourceLimitExceeded, match="report UTF-8 bytes"):
        report(alerts, max_bytes=len(expected.encode("utf-8")) - 1)


def test_output_is_deterministic():
    assert report([make_alert()]) == (
        '[{"alert_id": "alert-1", "description": "An invalid username was used", '
        '"evidence": ["invalid username"], "raw_events": ["raw event"], '
        '"rule_id": "invalid_user", "severity": "medium", "source_ip": null, '
        '"timestamp": "2026-09-03T12:30:00+00:00", "title": "Invalid user", '
        '"username": "unknown"}]'
    )
