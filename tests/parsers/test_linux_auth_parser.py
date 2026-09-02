from threat_detector.parsers.linux_auth import parse_line


def test_parse_failed_password():
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Failed password for alice from 192.0.2.10 port 2222"
    )

    event = parse_line(raw)

    assert event is not None
    assert event.timestamp == "Jan  1 12:34:56"
    assert event.hostname == "server"
    assert event.process == "sshd"
    assert event.pid == 1234
    assert event.event_type == "authentication_failure"
    assert event.username == "alice"
    assert event.source_ip == "192.0.2.10"
    assert event.source_port == 2222
    assert event.raw == raw


def test_parse_failed_password_with_ssh2():
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Failed password for alice from 192.0.2.10 port 2222 ssh2"
    )

    event = parse_line(raw)

    assert event is not None
    assert event.event_type == "authentication_failure"
    assert event.username == "alice"
    assert event.source_ip == "192.0.2.10"
    assert event.source_port == 2222


def test_parse_accepted_password():
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Accepted password for alice from 192.0.2.10 port 2222 ssh2"
    )

    event = parse_line(raw)

    assert event is not None
    assert event.event_type == "authentication_success"
    assert event.username == "alice"
    assert event.source_ip == "192.0.2.10"
    assert event.source_port == 2222
    assert event.raw == raw


def test_parse_accepted_password_no_ssh2():
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Accepted password for alice from 192.0.2.10 port 2222"
    )

    event = parse_line(raw)

    assert event is not None
    assert event.event_type == "authentication_success"
    assert event.username == "alice"
    assert event.source_ip == "192.0.2.10"
    assert event.source_port == 2222


def test_parse_invalid_user():
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Invalid user unknown60 from 198.51.100.239 port 2238 ssh2"
    )

    event = parse_line(raw)

    assert event is not None
    assert event.event_type == "invalid_user"
    assert event.username == "unknown60"
    assert event.source_ip == "198.51.100.239"
    assert event.source_port == 2238


def test_parse_invalid_user_no_ssh2():
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Invalid user unknown60 from 198.51.100.239 port 2238"
    )

    event = parse_line(raw)

    assert event is not None
    assert event.event_type == "invalid_user"
    assert event.username == "unknown60"
    assert event.source_ip == "198.51.100.239"
    assert event.source_port == 2238


def test_parse_port_no_space():
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Failed password for alice from 192.0.2.10 port2222"
    )

    event = parse_line(raw)

    assert event is not None
    assert event.event_type == "authentication_failure"
    assert event.username == "alice"
    assert event.source_ip == "192.0.2.10"
    assert event.source_port == 2222


def test_parse_rejects_unrecognized_message():
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Connection closed by 192.0.2.10"
    )

    assert parse_line(raw) is None


def test_parse_rejects_malformed_ip_port_concatenation():
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Failed password for alice from 192.0.2.120port 2299"
    )

    assert parse_line(raw) is None


def test_parse_rejects_trailing_text_after_valid_ssh_message():
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Failed password for alice from 192.0.2.10 port 2222 ssh2 extra"
    )

    assert parse_line(raw) is None


def test_parse_rejects_unknown_suffix_after_valid_ssh_message():
    raw = (
        "Jan  1 12:34:56 server sshd[1234]: "
        "Accepted password for alice from 192.0.2.10 port 2222 extra"
    )

    assert parse_line(raw) is None