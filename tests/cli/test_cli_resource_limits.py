from dataclasses import replace
from pathlib import Path

from threat_detector.cli import main
from threat_detector.resource_limits import DEFAULT_RESOURCE_LIMITS


FIXTURES = Path(__file__).parents[2] / "data" / "fixtures"


def test_windows_xml_exact_limit_reaches_existing_parser(tmp_path, capsys, monkeypatch):
    source = FIXTURES / "windows" / "security_4624.xml"
    input_path = tmp_path / "event.xml"
    raw_xml = source.read_bytes()
    input_path.write_bytes(raw_xml)
    monkeypatch.setattr(
        "threat_detector.cli.DEFAULT_RESOURCE_LIMITS",
        replace(DEFAULT_RESOURCE_LIMITS, windows_xml_max_bytes=len(raw_xml)),
    )

    assert main(["--input", str(input_path), "--format", "windows-security"]) == 0
    assert capsys.readouterr().err == ""


def test_windows_xml_over_limit_fails_before_elementtree_parser(
    tmp_path, capsys, monkeypatch
):
    input_path = tmp_path / "oversized.xml"
    input_path.write_bytes(b"<Event/>")
    monkeypatch.setattr(
        "threat_detector.cli.DEFAULT_RESOURCE_LIMITS",
        replace(DEFAULT_RESOURCE_LIMITS, windows_xml_max_bytes=7),
    )
    parser_called = False

    def fail_if_parsed(_xml):
        nonlocal parser_called
        parser_called = True
        raise AssertionError("oversized XML must be rejected before parsing")

    monkeypatch.setattr("threat_detector.cli.parse_windows_event", fail_if_parsed)

    assert main(["--input", str(input_path), "--format", "windows-security"]) == 1
    output = capsys.readouterr()
    assert "resource limit exceeded: Windows XML bytes" in output.err
    assert "Event/" not in output.err
    assert output.out == ""
    assert not parser_called


def test_windows_xml_uses_document_limit_not_line_limit(tmp_path, capsys):
    source = (FIXTURES / "windows" / "security_4624.xml").read_text(encoding="utf-8")
    xml = source.replace(
        "<Data Name=\"TargetUserName\">alice</Data>",
        f"<Data Name=\"TargetUserName\">{'x' * (70 * 1024)}</Data>",
    )
    input_path = tmp_path / "large-event.xml"
    input_path.write_text(xml, encoding="utf-8")

    assert main(["--input", str(input_path), "--format", "windows-security"]) == 0
    assert capsys.readouterr().err == ""


def test_report_limit_fails_before_persistence_and_stdout(tmp_path, capsys, monkeypatch):
    input_path = tmp_path / "attack.log"
    lines = [
        f"Jan  1 00:00:{second:02d} host sshd[1001]: Failed password for alice from 192.0.2.10 port 2222"
        for second in (0, 10, 20, 30, 40)
    ]
    lines.append(
        "Jan  1 00:00:50 host sshd[1002]: Accepted password for root from 192.0.2.10 port 2222"
    )
    input_path.write_text("\n".join(lines), encoding="utf-8")
    database_path = tmp_path / "findings.sqlite3"
    monkeypatch.setattr(
        "threat_detector.cli.DEFAULT_RESOURCE_LIMITS",
        replace(DEFAULT_RESOURCE_LIMITS, max_report_bytes=1),
    )

    code = main(
        [
            "--input", str(input_path),
            "--format", "linux-auth",
            "--reference-time", "2026-09-02T12:00:00+00:00",
            "--database", str(database_path),
        ]
    )

    output = capsys.readouterr()
    assert code == 1
    assert "resource limit exceeded: report UTF-8 bytes" in output.err
    assert output.out == ""
    assert not database_path.exists()


def test_result_budget_failure_is_processing_error_without_persistence(
    tmp_path, capsys, monkeypatch
):
    input_path = tmp_path / "invalid-users.log"
    lines = [
        f"Jan  1 00:00:0{index} host sshd[1001]: Invalid user user{index} from 192.0.2.10 port 2222"
        for index in range(2)
    ]
    input_path.write_text("\n".join(lines), encoding="utf-8")
    database_path = tmp_path / "findings.sqlite3"
    monkeypatch.setattr(
        "threat_detector.cli.DEFAULT_RESOURCE_LIMITS",
        replace(DEFAULT_RESOURCE_LIMITS, max_alerts=1),
    )

    code = main(
        [
            "--input", str(input_path),
            "--format", "linux-auth",
            "--reference-time", "2026-09-02T12:00:00+00:00",
            "--database", str(database_path),
        ]
    )

    output = capsys.readouterr()
    assert code == 1
    assert "resource limit exceeded: Alert count" in output.err
    assert "Invalid user" not in output.err
    assert output.out == ""
    assert not database_path.exists()


def test_input_byte_limit_is_processing_error_without_output_or_database(
    tmp_path, capsys, monkeypatch
):
    input_path = tmp_path / "input.log"
    input_path.write_bytes(b"123456")
    database_path = tmp_path / "findings.sqlite3"
    monkeypatch.setattr(
        "threat_detector.cli.DEFAULT_RESOURCE_LIMITS",
        replace(DEFAULT_RESOURCE_LIMITS, max_input_bytes=5),
    )

    code = main(
        [
            "--input", str(input_path),
            "--format", "linux-auth",
            "--reference-time", "2026-09-02T12:00:00+00:00",
            "--database", str(database_path),
        ]
    )

    output = capsys.readouterr()
    assert code == 1
    assert "resource limit exceeded: input file bytes" in output.err
    assert output.out == ""
    assert not database_path.exists()
