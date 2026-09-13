from datetime import datetime, timedelta, timezone

from threat_detector.detection.rules.web_reconnaissance import WebReconnaissanceRule
from threat_detector.normalization.event import NormalizedEvent


def make_event(
    http_path: str | None = "/admin",
    *,
    event_type: str = "http_access",
    source_ip: str | None = "203.0.113.50",
    source: str = "apache_access",
    service: str = "http",
    timestamp: datetime | None = None,
    raw: str | None = None,
    username: str | None = None,
) -> NormalizedEvent:
    timestamp = timestamp or datetime(2026, 1, 1, tzinfo=timezone.utc)
    return NormalizedEvent(
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        hostname=None,
        username=username,
        source_ip=source_ip,
        source_port=None,
        success=None,
        raw=raw or f"http access for {http_path} at {timestamp}",
        service=service,
        http_path=http_path,
    )


def test_five_distinct_suspicious_paths_trigger():
    rule = WebReconnaissanceRule()

    alerts = [
        rule.process(make_event(http_path="/admin")),
        rule.process(make_event(http_path="/wp-admin")),
        rule.process(make_event(http_path="/phpmyadmin")),
        rule.process(make_event(http_path="/.env")),
        rule.process(make_event(http_path="/server-status")),
    ]

    assert alerts[:4] == [None, None, None, None]
    assert alerts[4] is not None


def test_four_distinct_suspicious_paths_no_alert():
    rule = WebReconnaissanceRule()

    alerts = [
        rule.process(make_event(http_path="/admin")),
        rule.process(make_event(http_path="/wp-admin")),
        rule.process(make_event(http_path="/phpmyadmin")),
        rule.process(make_event(http_path="/.env")),
    ]

    assert alerts == [None, None, None, None]


def test_repeated_same_suspicious_path_no_count_inflate():
    rule = WebReconnaissanceRule()

    alerts = [rule.process(make_event(http_path="/admin")) for _ in range(10)]

    assert alerts == [None] * 10


def test_query_string_variants_count_as_same():
    rule = WebReconnaissanceRule()

    alerts = [
        rule.process(make_event(http_path="/admin?user=1")),
        rule.process(make_event(http_path="/admin?token=abc")),
        rule.process(make_event(http_path="/admin?x=y")),
        rule.process(make_event(http_path="/admin")),
        rule.process(make_event(http_path="/admin#frag")),
    ]

    assert alerts == [None] * 5


def test_five_normal_paths_no_alert():
    rule = WebReconnaissanceRule()

    alerts = [
        rule.process(make_event(http_path="/index.html")),
        rule.process(make_event(http_path="/about")),
        rule.process(make_event(http_path="/contact")),
        rule.process(make_event(http_path="/products")),
        rule.process(make_event(http_path="/services")),
    ]

    assert alerts == [None, None, None, None, None]


def test_exactly_60_second_boundary_qualifies():
    rule = WebReconnaissanceRule()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    alerts = [
        rule.process(make_event(http_path="/admin", timestamp=base + timedelta(seconds=0))),
        rule.process(make_event(http_path="/wp-admin", timestamp=base + timedelta(seconds=10))),
        rule.process(make_event(http_path="/phpmyadmin", timestamp=base + timedelta(seconds=20))),
        rule.process(make_event(http_path="/.env", timestamp=base + timedelta(seconds=30))),
        rule.process(make_event(http_path="/server-status", timestamp=base + timedelta(seconds=60))),
    ]

    assert alerts[:4] == [None, None, None, None]
    assert alerts[4] is not None


def test_just_beyond_60_second_boundary_does_not_qualify():
    rule = WebReconnaissanceRule()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    alerts = [
        rule.process(make_event(http_path="/admin", timestamp=base + timedelta(seconds=0))),
        rule.process(make_event(http_path="/wp-admin", timestamp=base + timedelta(seconds=10))),
        rule.process(make_event(http_path="/phpmyadmin", timestamp=base + timedelta(seconds=20))),
        rule.process(make_event(http_path="/.env", timestamp=base + timedelta(seconds=30))),
        rule.process(make_event(http_path="/server-status", timestamp=base + timedelta(seconds=61))),
    ]

    assert alerts == [None, None, None, None, None]


def test_out_of_order_events_within_active_window_accepted():
    rule = WebReconnaissanceRule()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    alerts = [
        rule.process(make_event(http_path="/server-status", timestamp=base + timedelta(seconds=40))),
        rule.process(make_event(http_path="/admin", timestamp=base + timedelta(seconds=0))),
        rule.process(make_event(http_path="/wp-admin", timestamp=base + timedelta(seconds=10))),
        rule.process(make_event(http_path="/phpmyadmin", timestamp=base + timedelta(seconds=20))),
        rule.process(make_event(http_path="/.env", timestamp=base + timedelta(seconds=30))),
    ]

    assert alerts[:4] == [None, None, None, None]
    assert alerts[4] is not None


def test_stale_event_older_than_cutoff_ignored():
    rule = WebReconnaissanceRule()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    # Set watermark to 120 seconds
    rule.process(make_event(http_path="/admin", timestamp=base + timedelta(seconds=120)))
    # cutoff = 120 - 60 = 60

    # Event at time 50 is older than cutoff (50 < 60) -> ignored
    stale_alert = rule.process(make_event(http_path="/wp-admin", timestamp=base + timedelta(seconds=50)))
    assert stale_alert is None

    # Now add 4 more fresh events at 120 to reach threshold
    rule.process(make_event(http_path="/phpmyadmin", timestamp=base + timedelta(seconds=120)))
    rule.process(make_event(http_path="/.env", timestamp=base + timedelta(seconds=120)))
    rule.process(make_event(http_path="/server-status", timestamp=base + timedelta(seconds=120)))
    alert = rule.process(make_event(http_path="/backup", timestamp=base + timedelta(seconds=120)))

    # 5th distinct path triggers alert; /wp-admin was NOT counted
    assert alert is not None
    assert alert.rule_id == "web_reconnaissance"


def test_different_source_ips_independent():
    rule = WebReconnaissanceRule()

    alerts = [
        rule.process(make_event(http_path="/admin", source_ip="203.0.113.50")),
        rule.process(make_event(http_path="/wp-admin", source_ip="203.0.113.50")),
        rule.process(make_event(http_path="/phpmyadmin", source_ip="203.0.113.50")),
        rule.process(make_event(http_path="/.env", source_ip="203.0.113.50")),
        rule.process(make_event(http_path="/server-status", source_ip="203.0.113.51")),  # Different IP
    ]

    assert alerts == [None, None, None, None, None]


def test_suppression_prevents_duplicate_alerts():
    rule = WebReconnaissanceRule()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    # Trigger alert at time 40
    for i, path in enumerate(["/admin", "/wp-admin", "/phpmyadmin", "/.env"]):
        rule.process(make_event(http_path=path, timestamp=base + timedelta(seconds=i * 10)))
    alert1 = rule.process(make_event(http_path="/server-status", timestamp=base + timedelta(seconds=40)))
    assert alert1 is not None

    # Additional requests in same window should not alert
    alerts = [
        rule.process(make_event(http_path="/backup", timestamp=base + timedelta(seconds=50))),
        rule.process(make_event(http_path="/sql", timestamp=base + timedelta(seconds=60))),
    ]
    assert alerts == [None, None]

    # After expiration, new alert possible
    # Advance watermark to time 101 to expire the old window
    rule.process(make_event(http_path="/admin", timestamp=base + timedelta(seconds=101)))
    # Now old paths expire, new alert possible
    alerts = [
        rule.process(make_event(http_path="/wp-admin", timestamp=base + timedelta(seconds=102))),
        rule.process(make_event(http_path="/phpmyadmin", timestamp=base + timedelta(seconds=103))),
        rule.process(make_event(http_path="/.env", timestamp=base + timedelta(seconds=104))),
        rule.process(make_event(http_path="/server-status", timestamp=base + timedelta(seconds=105))),
    ]
    # The retained /backup path plus four new paths reaches the threshold at 104.
    assert alerts[0] is None
    assert alerts[1] is None
    assert alerts[2] is not None
    assert alerts[3] is None  # suppressed


def test_missing_source_ip_ignored():
    rule = WebReconnaissanceRule()
    assert rule.process(make_event(source_ip=None)) is None


def test_missing_http_path_ignored():
    rule = WebReconnaissanceRule()
    assert rule.process(make_event(http_path=None)) is None


def test_non_http_events_ignored():
    rule = WebReconnaissanceRule()
    assert rule.process(
        make_event(event_type="authentication_failure", service="ssh", http_path="/admin")
    ) is None
    assert rule.process(
        make_event(event_type="invalid_user", service="ssh", http_path="/wp-admin")
    ) is None


def test_alert_fields_deterministic_identity_evidence():
    rule = WebReconnaissanceRule()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    alert = None
    paths = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/server-status"]
    for i, path in enumerate(paths):
        alert = rule.process(
            make_event(
                http_path=path,
                timestamp=base + timedelta(seconds=i * 10),
                raw=f"GET {path} HTTP/1.1",
            )
        )

    assert alert is not None
    assert alert.rule_id == "web_reconnaissance"
    assert alert.severity == "medium"
    assert alert.title == "Web reconnaissance detected"
    assert alert.source_ip == "203.0.113.50"
    assert alert.username is None
    assert len(alert.raw_events) == 5
    sorted_paths = sorted(paths)
    assert alert.raw_events == [f"GET {path} HTTP/1.1" for path in sorted_paths]
    assert alert.timestamp == base + timedelta(seconds=40)
    expected_suffix = ",".join(sorted(paths))
    assert alert.alert_id.endswith(expected_suffix)
    assert alert.alert_id.startswith("web_reconnaissance:203.0.113.50:2026-01-01 00:00:40+00:00:")
    assert "Source 203.0.113.50 requested 5 distinct suspicious paths within 60 seconds." in alert.description
    assert len(alert.evidence) == 5
    timestamps = {path: base + timedelta(seconds=i * 10) for i, path in enumerate(paths)}
    for i, path in enumerate(sorted_paths):
        assert f"Source 203.0.113.50 requested suspicious path {path} at {timestamps[path]}" in alert.evidence[i]


def test_alert_id_includes_distinct_path_set():
    def detect_alert(paths: list[str]):
        rule = WebReconnaissanceRule()
        alert = None
        for path in paths:
            alert = rule.process(make_event(http_path=path))
        assert alert is not None
        return alert

    baseline = detect_alert(["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/server-status"])
    different_path_set = detect_alert(["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/backup"])

    assert baseline.alert_id != different_path_set.alert_id


def test_alert_id_is_independent_of_event_order():
    def detect_alert(paths: list[str]):
        rule = WebReconnaissanceRule()
        alert = None
        for path in paths:
            alert = rule.process(make_event(http_path=path))
        assert alert is not None
        return alert

    first_alert = detect_alert(["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/server-status"])
    second_alert = detect_alert(["/server-status", "/.env", "/phpmyadmin", "/wp-admin", "/admin"])

    assert first_alert.alert_id == second_alert.alert_id


def test_engine_runs_web_reconnaissance_and_existing_rules_independently():
    from threat_detector.detection.engine import DetectionEngine
    from threat_detector.detection.rules.invalid_user import InvalidUserRule
    from threat_detector.detection.rules.password_spraying import PasswordSprayingRule
    from threat_detector.detection.rules.ssh_brute_force import SSHBruteForceRule

    engine = DetectionEngine(
        [SSHBruteForceRule(), InvalidUserRule(), PasswordSprayingRule(), WebReconnaissanceRule()]
    )
    # Send an Apache http_access event
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i, path in enumerate(["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/server-status"]):
        event = make_event(http_path=path, timestamp=base + timedelta(seconds=i * 10))
        results = engine.process(event)

    # Last event should produce web_reconnaissance alert
    assert len(results) == 1
    assert results[0].rule_id == "web_reconnaissance"

    # Send an invalid_user event
    invalid_event = make_event(
        event_type="invalid_user",
        service="ssh",
        http_path=None,
        source_ip="203.0.113.50",
        username="invalid1",
        timestamp=base,
    )
    results = engine.process(invalid_event)
    assert len(results) == 1
    assert results[0].rule_id == "invalid_user"

    # Send ssh brute force
    ssh_events = [
        make_event(
            event_type="authentication_failure",
            service="ssh",
            http_path=None,
            source_ip="192.0.2.10",
            username="alice",
            timestamp=base + timedelta(seconds=i),
        )
        for i in range(5)
    ]
    for event in ssh_events:
        results = engine.process(event)
    assert len(results) == 1
    assert results[0].rule_id == "ssh_brute_force"