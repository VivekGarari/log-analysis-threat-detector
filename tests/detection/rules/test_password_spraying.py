from datetime import datetime, timedelta, timezone

from threat_detector.detection.engine import DetectionEngine
from threat_detector.detection.rules.invalid_user import InvalidUserRule
from threat_detector.detection.rules.password_spraying import PasswordSprayingRule
from threat_detector.detection.rules.ssh_brute_force import SSHBruteForceRule
from threat_detector.normalization.event import NormalizedEvent


def make_event(
    username: str | None,
    *,
    event_type: str = "authentication_failure",
    source_ip: str | None = "203.0.113.50",
    source: str = "linux_auth",
    service: str | None = "ssh",
    timestamp: datetime | None = None,
    raw: str | None = None,
) -> NormalizedEvent:
    timestamp = timestamp or datetime(2026, 1, 1, tzinfo=timezone.utc)
    return NormalizedEvent(
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        hostname="auth-host",
        username=username,
        source_ip=source_ip,
        source_port=40000,
        success=False,
        raw=raw or f"{event_type} for {username} at {timestamp}",
        service=service,
    )


def events_for_usernames(
    usernames: list[str],
    *,
    event_type: str = "authentication_failure",
    source_ip: str | None = "203.0.113.50",
    source: str = "linux_auth",
    service: str | None = "ssh",
    timestamp: datetime | None = None,
    raw: str | None = None,
) -> list[NormalizedEvent]:
    return [
        make_event(
            username,
            event_type=event_type,
            source_ip=source_ip,
            source=source,
            service=service,
            timestamp=timestamp,
            raw=raw,
        )
        for username in usernames
    ]


def test_five_distinct_authentication_failures_trigger():
    rule = PasswordSprayingRule()

    alerts = [rule.process(event) for event in events_for_usernames(["alice", "bob", "carol", "dave", "erin"])]

    assert alerts[:4] == [None, None, None, None]
    assert alerts[4] is not None


def test_alert_id_is_independent_of_username_event_order():
    def detect_alert(usernames: list[str]):
        rule = PasswordSprayingRule()
        alert = None
        for event in events_for_usernames(usernames):
            alert = rule.process(event)
        assert alert is not None
        return alert

    first_alert = detect_alert(["alice", "bob", "carol", "dave", "erin"])
    second_alert = detect_alert(["erin", "dave", "carol", "bob", "alice"])

    assert first_alert.alert_id == second_alert.alert_id


def test_alert_id_includes_the_distinct_username_set():
    def detect_alert(usernames: list[str]):
        rule = PasswordSprayingRule()
        alert = None
        for event in events_for_usernames(usernames):
            alert = rule.process(event)
        assert alert is not None
        return alert

    baseline = detect_alert(["alice", "bob", "carol", "dave", "erin"])
    different_user_set = detect_alert(["alice", "bob", "carol", "dave", "frank"])

    assert baseline.username is None
    assert baseline.alert_id != different_user_set.alert_id


def test_four_distinct_usernames_do_not_trigger():
    rule = PasswordSprayingRule()

    alerts = [
        rule.process(event)
        for event in events_for_usernames(["alice", "bob", "carol", "dave"])
    ]

    assert alerts == [None, None, None, None]


def test_distinct_username_at_exactly_sixty_second_boundary_still_counts():
    rule = PasswordSprayingRule()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    alerts = [
        rule.process(
            make_event(
                username,
                timestamp=base + timedelta(seconds=second),
            )
        )
        for username, second in zip(
            ["alice", "bob", "carol", "dave", "erin"],
            [0, 10, 20, 30, 60],
        )
    ]

    assert alerts[-1] is not None


def test_distinct_username_just_beyond_sixty_second_window_does_not_count():
    rule = PasswordSprayingRule()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    alerts = [
        rule.process(
            make_event(
                username,
                timestamp=base + timedelta(seconds=second),
            )
        )
        for username, second in zip(
            ["alice", "bob", "carol", "dave", "erin"],
            [0, 10, 20, 30, 61],
        )
    ]

    assert alerts == [None, None, None, None, None]


def test_five_distinct_invalid_users_trigger():
    rule = PasswordSprayingRule()

    alerts = [
        rule.process(event)
        for event in events_for_usernames(
            ["alice", "bob", "carol", "dave", "erin"],
            event_type="invalid_user",
        )
    ]

    assert alerts[-1] is not None


def test_linux_and_windows_events_contribute_to_same_source_state():
    rule = PasswordSprayingRule()
    events = [
        make_event("alice", source="linux_auth", service="ssh"),
        make_event("bob", source="windows_security", service=None),
        make_event("carol", source="linux_auth", service="ssh"),
        make_event("dave", source="windows_security", service=None),
        make_event("erin", source="linux_auth", service="ssh"),
    ]

    alerts = [rule.process(event) for event in events]

    assert alerts[-1] is not None


def test_repeated_attempts_against_one_username_do_not_trigger():
    rule = PasswordSprayingRule()

    alerts = [rule.process(make_event("alice")) for _ in range(10)]

    assert alerts == [None] * 10


def test_attempts_against_two_usernames_do_not_trigger():
    rule = PasswordSprayingRule()

    alerts = [rule.process(make_event(username)) for username in ["alice", "bob"] * 5]

    assert alerts == [None] * 10


def test_different_source_ips_do_not_combine():
    rule = PasswordSprayingRule()

    alerts = [
        rule.process(make_event(username, source_ip=f"203.0.113.{index + 1}"))
        for index, username in enumerate(["alice", "bob", "carol", "dave", "erin"])
    ]

    assert alerts == [None] * 5


def test_missing_source_ip_is_ignored():
    rule = PasswordSprayingRule()

    assert rule.process(make_event("alice", source_ip=None)) is None


def test_missing_username_is_ignored():
    rule = PasswordSprayingRule()

    assert rule.process(make_event(None)) is None


def test_success_and_http_events_are_ignored():
    rule = PasswordSprayingRule()

    assert rule.process(make_event("alice", event_type="authentication_success")) is None
    assert rule.process(make_event("bob", event_type="http_access", source="apache_access", service="http")) is None


def test_service_does_not_affect_eligibility():
    rule = PasswordSprayingRule()

    alerts = [
        rule.process(event)
        for event in events_for_usernames(
            ["alice", "bob", "carol", "dave", "erin"],
            service=None,
        )
    ]

    assert alerts[-1] is not None


def test_username_equality_is_exact_and_case_sensitive():
    rule = PasswordSprayingRule()
    usernames = ["alice", "Alice", "bob", "carol", "dave"]

    alerts = [rule.process(event) for event in events_for_usernames(usernames)]

    assert alerts[-1] is not None


def test_alert_fields_evidence_and_representative_raw_events():
    rule = PasswordSprayingRule()
    events = events_for_usernames(
        ["alice", "bob", "carol", "dave", "erin"],
    )

    alert = None
    for event in events:
        alert = rule.process(event)

    assert alert is not None
    assert alert.rule_id == "password_spraying"
    assert alert.severity == "high"
    assert alert.timestamp == events[-1].timestamp
    assert alert.source_ip == events[-1].source_ip
    assert alert.username is None
    assert len(alert.raw_events) == 5
    assert alert.raw_events == [event.raw for event in events]
    assert "203.0.113.50" in alert.evidence[0]
    assert "5 distinct usernames" in alert.evidence[0]
    assert all(username in alert.evidence[0] for username in ["alice", "bob", "carol", "dave", "erin"])
    assert "60 seconds" in alert.evidence[0]


def test_repeated_events_after_threshold_are_suppressed():
    rule = PasswordSprayingRule()
    events = events_for_usernames(["alice", "bob", "carol", "dave", "erin", "frank"])

    alerts = [rule.process(event) for event in events]

    assert sum(alert is not None for alert in alerts) == 1


def test_expiration_allows_a_later_independent_alert():
    rule = PasswordSprayingRule()
    first_events = events_for_usernames(["alice", "bob", "carol", "dave", "erin"])
    for event in first_events:
        assert rule.process(event) is None or event.username == "erin"

    later = datetime(2026, 1, 1, 0, 1, 5, tzinfo=timezone.utc)
    second_events = events_for_usernames(
        ["frank", "gina", "henry", "irene", "jane"],
        timestamp=later,
    )
    alerts = [rule.process(event) for event in second_events]

    assert alerts[-1] is not None


def test_usernames_from_expired_window_do_not_contribute_to_later_alert():
    rule = PasswordSprayingRule()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    first_alerts = [
        rule.process(make_event(username, timestamp=base))
        for username in ["alice", "bob", "carol", "dave", "erin"]
    ]
    assert first_alerts[-1] is not None

    later = base + timedelta(seconds=61)
    later_alerts = [
        rule.process(make_event(username, timestamp=later))
        for username in ["alice", "bob", "carol", "dave"]
    ]

    assert later_alerts == [None, None, None, None]


def test_out_of_order_events_inside_window_are_accepted():
    rule = PasswordSprayingRule()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    timestamps = [40, 0, 10, 20, 30]

    alerts = [
        rule.process(make_event(username, timestamp=base + timedelta(seconds=second)))
        for username, second in zip(["alice", "bob", "carol", "dave", "erin"], timestamps)
    ]

    assert alerts[-1] is not None


def test_events_older_than_watermark_cutoff_are_ignored():
    rule = PasswordSprayingRule()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert (
        rule.process(make_event("alice", timestamp=base + timedelta(seconds=120)))
        is None
    )

    old_event = make_event("bob", timestamp=base)

    assert rule.process(old_event) is None
    assert "203.0.113.50" not in rule._attempts or "bob" not in rule._attempts["203.0.113.50"]


def test_rule_state_is_independent_from_ssh_brute_force_rule():
    password_rule = PasswordSprayingRule()
    ssh_rule = SSHBruteForceRule()
    event = make_event("alice")

    password_rule.process(event)

    assert password_rule._attempts
    assert not ssh_rule._failures


def test_engine_runs_password_spraying_and_existing_rules_independently():
    engine = DetectionEngine(
        [SSHBruteForceRule(), InvalidUserRule(), PasswordSprayingRule()]
    )
    events = [
        make_event(username, event_type="invalid_user", service=None)
        for username in ["alice", "bob", "carol", "dave", "erin"]
    ]

    results = [engine.process(event) for event in events]

    assert len(results[-1]) == 2
    assert {alert.rule_id for alert in results[-1]} == {
        "invalid_user",
        "password_spraying",
    }
