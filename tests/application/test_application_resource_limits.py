from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

import threat_detector.application.processor as processor
from threat_detector.alerts.models import Alert
from threat_detector.application.pipeline import DetectionPipeline
from threat_detector.correlation.engine import CorrelationEngine
from threat_detector.correlation.models import Finding
from threat_detector.detection.engine import DetectionEngine
from threat_detector.detection.rules.ssh_brute_force import SSHBruteForceRule
from threat_detector.normalization.event import NormalizedEvent
from threat_detector.persistence.schema import connect, initialize_schema
from threat_detector.resource_limits import (
    DEFAULT_RESOURCE_LIMITS,
    ResourceBudget,
    ResourceLimitExceeded,
    alert_payload_bytes,
    finding_graph_payload_bytes,
    finding_result_payload_bytes,
)


BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)
TABLES = (
    "findings",
    "finding_alerts",
    "finding_events",
    "alerts",
    "normalized_events",
)


def make_alert(alert_id: str = "alert-1") -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id="ssh_brute_force",
        severity="high",
        title="Brute force",
        description="Repeated SSH failures",
        timestamp=BASE_TIME,
        source_ip="192.0.2.10",
        username="alice",
        evidence=["failure evidence"],
        raw_events=["raw failure"],
    )


def make_event(second: int = 0, *, success: bool = False) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=BASE_TIME + timedelta(seconds=second),
        source="test",
        event_type="authentication_success" if success else "authentication_failure",
        hostname="host",
        username="root" if success else "alice",
        source_ip="192.0.2.10",
        source_port=22,
        success=success,
        raw=f"raw event {second}",
        service="ssh",
    )


def make_finding(alert: Alert | None = None) -> Finding:
    alert = alert or make_alert()
    event = make_event(1, success=True)
    return Finding(
        finding_id="finding-1",
        finding_type="credential_attack_success",
        severity="critical",
        title="Credential attack success",
        description="A success followed brute force",
        timestamp=event.timestamp,
        source_ip=event.source_ip,
        username=event.username,
        evidence=("structured evidence",),
        contributing_alerts=(alert,),
        contributing_events=(event,),
        raw_events=tuple(alert.raw_events) + (event.raw,),
    )


def assert_database_empty(database_path):
    connection = connect(str(database_path))
    try:
        for table in TABLES:
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0
    finally:
        connection.close()


def make_success_pipeline() -> tuple[DetectionPipeline, list[NormalizedEvent]]:
    events = [make_event(second) for second in (0, 1, 2, 3, 4)]
    events.extend(make_event(second, success=True) for second in (5, 6))
    return (
        DetectionPipeline(
            lambda record: record,
            lambda event: event,
            DetectionEngine([SSHBruteForceRule()]),
            CorrelationEngine(),
        ),
        events,
    )


def test_alert_and_finding_budgets_accept_exact_and_reject_over():
    alert = make_alert()
    alert_cost = alert_payload_bytes(alert)
    finding = make_finding(alert)
    finding_cost = finding_graph_payload_bytes(finding)

    exact_alert_budget = ResourceBudget(
        replace(DEFAULT_RESOURCE_LIMITS, max_alerts=1, max_result_bytes=alert_cost)
    )
    exact_alert_budget.charge_alert(alert)
    assert exact_alert_budget.alert_count == 1
    assert exact_alert_budget.result_bytes == alert_cost
    with pytest.raises(ResourceLimitExceeded, match="Alert count"):
        exact_alert_budget.charge_alert(alert)
    with pytest.raises(ResourceLimitExceeded, match="logical result bytes"):
        ResourceBudget(
            replace(DEFAULT_RESOURCE_LIMITS, max_result_bytes=alert_cost - 1)
        ).charge_alert(alert)

    exact_finding_budget = ResourceBudget(
        replace(
            DEFAULT_RESOURCE_LIMITS,
            max_findings=1,
            max_result_bytes=finding_cost,
            max_persistence_bytes=finding_cost,
        )
    )
    exact_finding_budget.charge_finding(finding)
    assert exact_finding_budget.finding_count == 1
    assert exact_finding_budget.persistence_bytes == finding_cost
    with pytest.raises(ResourceLimitExceeded, match="Finding count"):
        exact_finding_budget.charge_finding(finding)
    with pytest.raises(ResourceLimitExceeded, match="logical persistence bytes"):
        ResourceBudget(
            replace(DEFAULT_RESOURCE_LIMITS, max_persistence_bytes=finding_cost - 1)
        ).charge_finding(finding)

    finding_result_cost = finding_result_payload_bytes(finding)
    exact_result_budget = ResourceBudget(
        replace(DEFAULT_RESOURCE_LIMITS, max_result_bytes=finding_result_cost)
    )
    exact_result_budget.charge_finding(finding)
    assert exact_result_budget.result_bytes == finding_result_cost
    with pytest.raises(ResourceLimitExceeded, match="logical result bytes"):
        ResourceBudget(
            replace(DEFAULT_RESOURCE_LIMITS, max_result_bytes=finding_result_cost - 1)
        ).charge_finding(finding)


def test_pipeline_record_limits_fail_before_parser_receives_offending_item():
    parser_calls = []
    pipeline = DetectionPipeline(
        lambda record: parser_calls.append(record),
        lambda parsed: parsed,
        DetectionEngine([]),
    )
    record_limit = replace(DEFAULT_RESOURCE_LIMITS, max_record_bytes=3)

    with pytest.raises(ResourceLimitExceeded, match="input record UTF-8 bytes"):
        pipeline.process(["four"], record_limit)
    assert parser_calls == []

    count_limit = replace(DEFAULT_RESOURCE_LIMITS, max_records=1)
    with pytest.raises(ResourceLimitExceeded, match="input record count"):
        pipeline.process(["a", "b"], count_limit)
    assert parser_calls == ["a"]


def test_repeated_finding_graph_contributions_are_charged_each_time():
    alert = make_alert()
    finding = make_finding(alert)
    one_graph_bytes = finding_graph_payload_bytes(finding)
    budget = ResourceBudget(
        replace(
            DEFAULT_RESOURCE_LIMITS,
            max_findings=2,
            max_result_bytes=one_graph_bytes * 2,
            max_persistence_bytes=one_graph_bytes * 2,
        )
    )

    budget.charge_finding(finding)
    budget.charge_finding(finding)

    assert budget.persistence_bytes == one_graph_bytes * 2


def test_persistence_budget_failure_precedes_database_writes(tmp_path):
    pipeline, events = make_success_pipeline()
    database_path = tmp_path / "findings.sqlite3"
    connection = connect(str(database_path))
    initialize_schema(connection)
    connection.close()
    limits = replace(DEFAULT_RESOURCE_LIMITS, max_persistence_bytes=1)

    with pytest.raises(ResourceLimitExceeded, match="logical persistence bytes"):
        processor.process_and_persist(
            pipeline, events, database_path, limits=limits
        )

    assert_database_empty(database_path)


def test_exact_persistence_budget_commits_all_finding_graphs(tmp_path):
    measure_pipeline, measure_events = make_success_pipeline()
    expected = measure_pipeline.process_with_findings(measure_events)
    exact_graph_bytes = sum(
        finding_graph_payload_bytes(finding) for finding in expected.findings
    )
    pipeline, events = make_success_pipeline()
    database_path = tmp_path / "findings.sqlite3"
    limits = replace(DEFAULT_RESOURCE_LIMITS, max_persistence_bytes=exact_graph_bytes)

    result = processor.process_and_persist(
        pipeline, events, database_path, limits=limits
    )

    assert len(result.findings) == len(expected.findings) == 2
    connection = connect(str(database_path))
    try:
        assert connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM finding_alerts").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM finding_events").fetchone()[0] == 2
    finally:
        connection.close()


def test_write_failure_rolls_back_all_finding_graph_rows(tmp_path, monkeypatch):
    pipeline, events = make_success_pipeline()
    database_path = tmp_path / "findings.sqlite3"
    original_save_finding = processor.save_finding
    calls = 0

    def fail_on_second_graph(connection, finding):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("simulated persistence failure")
        return original_save_finding(connection, finding)

    monkeypatch.setattr(processor, "save_finding", fail_on_second_graph)
    with pytest.raises(RuntimeError, match="simulated persistence failure"):
        processor.process_and_persist(pipeline, events, database_path)

    assert calls == 2
    assert_database_empty(database_path)


def test_result_validator_runs_before_database_connection(tmp_path):
    pipeline, events = make_success_pipeline()
    database_path = tmp_path / "not-created.sqlite3"

    def reject_result(_result):
        raise ResourceLimitExceeded("report UTF-8 bytes", 1, 2)

    with pytest.raises(ResourceLimitExceeded, match="report UTF-8 bytes"):
        processor.process_and_persist(
            pipeline,
            events,
            database_path,
            before_persist=reject_result,
        )

    assert not database_path.exists()
