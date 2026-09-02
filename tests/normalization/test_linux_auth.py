from threat_detector.normalization.linux_auth import normalize_linux_event
from threat_detector.parsers.linux_auth import parse_line


def test_normalize_linux_event_failure():
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Failed password for alice from 192.0.2.10 port 2222"
    )

    event = parse_line(raw)

    assert event is not None

    normalized = normalize_linux_event(event)

    assert normalized.timestamp == "Jan  1 12:34:56"
    assert normalized.source == "linux_auth"
    assert normalized.service == "ssh"
    assert normalized.event_type == "authentication_failure"
    assert normalized.hostname == "server"
    assert normalized.username == "alice"
    assert normalized.source_ip == "192.0.2.10"
    assert normalized.source_port == 2222
    assert normalized.success is False
    assert normalized.raw == raw


def test_normalize_linux_event_success():
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Accepted password for alice from 192.0.2.10 port 2222 ssh2"
    )

    event = parse_line(raw)

    assert event is not None

    normalized = normalize_linux_event(event)

    assert normalized.timestamp == "Jan  1 12:34:56"
    assert normalized.source == "linux_auth"
    assert normalized.service == "ssh"
    assert normalized.event_type == "authentication_success"
    assert normalized.hostname == "server"
    assert normalized.username == "alice"
    assert normalized.source_ip == "192.0.2.10"
    assert normalized.source_port == 2222
    assert normalized.success is True
    assert normalized.raw == raw


def test_normalize_linux_event_invalid_user():
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Invalid user unknown60 from 198.51.100.239 port 2238"
    )

    event = parse_line(raw)

    assert event is not None

    normalized = normalize_linux_event(event)

    assert normalized.timestamp == "Jan  1 12:34:56"
    assert normalized.source == "linux_auth"
    assert normalized.service == "ssh"
    assert normalized.event_type == "invalid_user"
    assert normalized.hostname == "server"
    assert normalized.username == "unknown60"
    assert normalized.source_ip == "198.51.100.239"
    assert normalized.source_port == 2238
    assert normalized.success is False
    assert normalized.raw == raw


# Contract tests: explicitly document and protect NormalizedEvent semantics


def test_normalized_event_contract_source_identifies_parser():
    """
    source field identifies the parser/input origin (e.g., "linux_auth").
    This distinguishes WHERE the event came from.
    """
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Failed password for alice from 192.0.2.10 port 2222"
    )
    event = parse_line(raw)
    assert event is not None

    normalized = normalize_linux_event(event)

    # source identifies the parser/input origin
    assert normalized.source == "linux_auth"


def test_normalized_event_contract_service_identifies_protocol():
    """
    service field identifies the service/protocol the event concerns (e.g., "ssh").
    This distinguishes WHAT service/protocol the event is about.
    Source and service are independent concerns.
    """
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Failed password for alice from 192.0.2.10 port 2222"
    )
    event = parse_line(raw)
    assert event is not None

    normalized = normalize_linux_event(event)

    # service identifies the service/protocol (separate from source)
    assert normalized.service == "ssh"
    # Both are present and can differ in future multi-service scenarios
    assert normalized.source != normalized.service


def test_normalized_event_contract_success_true_on_successful_auth():
    """
    success field is True for authentication_success events.
    """
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Accepted password for alice from 192.0.2.10 port 2222 ssh2"
    )
    event = parse_line(raw)
    assert event is not None

    normalized = normalize_linux_event(event)

    assert normalized.event_type == "authentication_success"
    assert normalized.success is True


def test_normalized_event_contract_success_false_on_failed_auth():
    """
    success field is False for authentication_failure events.
    """
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Failed password for alice from 192.0.2.10 port 2222"
    )
    event = parse_line(raw)
    assert event is not None

    normalized = normalize_linux_event(event)

    assert normalized.event_type == "authentication_failure"
    assert normalized.success is False


def test_normalized_event_contract_success_false_on_invalid_user():
    """
    success field is False for invalid_user events (not a successful login).
    """
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Invalid user unknown60 from 198.51.100.239 port 2238"
    )
    event = parse_line(raw)
    assert event is not None

    normalized = normalize_linux_event(event)

    assert normalized.event_type == "invalid_user"
    assert normalized.success is False


def test_linux_ssh_normalized_event_required_fields_present():
    """
    Linux SSH normalizer guarantees these fields are present (not None):
    - timestamp
    - source
    - event_type
    - raw
    - service

    Note: service is optional at the generic NormalizedEvent level (str | None).
    However, Linux SSH normalization guarantees service == "ssh".
    """
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Failed password for alice from 192.0.2.10 port 2222"
    )
    event = parse_line(raw)
    assert event is not None

    normalized = normalize_linux_event(event)

    # Guaranteed by Linux SSH normalizer
    assert normalized.timestamp is not None
    assert isinstance(normalized.timestamp, str)
    assert normalized.source is not None
    assert isinstance(normalized.source, str)
    assert normalized.event_type is not None
    assert isinstance(normalized.event_type, str)
    assert normalized.raw is not None
    assert isinstance(normalized.raw, str)
    assert normalized.service is not None
    assert isinstance(normalized.service, str)
