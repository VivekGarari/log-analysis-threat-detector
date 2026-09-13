import json
from pathlib import Path

import pytest

from threat_detector.cli import main
from threat_detector.detection.rules.web_reconnaissance import WebReconnaissanceRule


FIXTURES = Path(__file__).parents[2] / "data" / "fixtures"


def linux_line(message: str, second: int = 0) -> str:
    return (
        f"Jan  1 00:00:{second:02d} web-01 sshd[1001]: {message}"
    )


def invoke_linux(path: Path, *extra: str) -> int:
    return main(
        [
            "--input",
            str(path),
            "--format",
            "linux-auth",
            "--reference-time",
            "2026-09-02T12:00:00+00:00",
            *extra,
        ]
    )


def test_help(capsys):
    with pytest.raises(SystemExit) as error:
        main(["--help"])

    assert error.value.code == 0
    assert "--input" in capsys.readouterr().out


def test_missing_required_arguments(capsys):
    with pytest.raises(SystemExit) as error:
        main([])

    assert error.value.code == 2
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("option", "value"),
    [("--format", "nonsense"), ("--output", "unsupported")],
)
def test_unsupported_choices_are_argument_errors(tmp_path, capsys, option, value):
    arguments = ["--input", str(tmp_path / "input.log"), option, value]

    with pytest.raises(SystemExit) as error:
        main(arguments)

    assert error.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_missing_linux_reference_time(tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        main(
            [
                "--input",
                str(FIXTURES / "linux" / "password_spraying.log"),
                "--format",
                "linux-auth",
                "--output",
                "json",
            ]
        )

    assert error.value.code == 2
    assert "--reference-time is required" in capsys.readouterr().err


def test_malformed_linux_reference_time(tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        main(
            [
                "--input",
                str(FIXTURES / "linux" / "password_spraying.log"),
                "--format",
                "linux-auth",
                "--reference-time",
                "not-a-date",
                "--output",
                "json",
            ]
        )

    assert error.value.code == 2
    assert "invalid --reference-time" in capsys.readouterr().err


def test_successful_linux_processing_and_text_output(tmp_path, capsys):
    input_path = tmp_path / "input.log"
    input_path.write_text(linux_line("Invalid user bob from 192.0.2.10 port 22"))

    assert invoke_linux(input_path) == 0

    output = capsys.readouterr()
    assert "invalid_user" in output.out
    assert output.err == ""


def test_successful_windows_processing(tmp_path, capsys):
    output_code = main(
        [
            "--input",
            str(FIXTURES / "windows" / "security_4625.xml"),
            "--format",
            "windows-security",
        ]
    )

    assert output_code == 0
    assert capsys.readouterr().err == ""


def test_successful_apache_processing(tmp_path, capsys):
    output_code = main(
        [
            "--input",
            str(FIXTURES / "apache" / "access_combined_200.log"),
            "--format",
            "apache-access",
        ]
    )

    assert output_code == 0
    assert capsys.readouterr().err == ""


def test_apache_web_reconnaissance_detection(tmp_path, capsys):
    lines = [
        f'203.0.113.10 - alice [02/Sep/2026:12:40:{i:02d} +0000] "GET {path} HTTP/1.1" 200 512 "https://example.com" "Mozilla/5.0"'
        for i, path in enumerate(["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/server-status"])
    ]
    input_path = tmp_path / "recon.log"
    input_path.write_text("\n".join(lines))

    output_code = main(
        [
            "--input",
            str(input_path),
            "--format",
            "apache-access",
            "--output",
            "json",
        ]
    )

    assert output_code == 0
    alerts = json.loads(capsys.readouterr().out)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "web_reconnaissance"
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["source_ip"] == "203.0.113.10"
    assert alerts[0]["username"] is None
    assert len(alerts[0]["evidence"]) == 5
    assert len(alerts[0]["raw_events"]) == 5


def test_json_output(tmp_path, capsys):
    input_path = tmp_path / "input.log"
    input_path.write_text(linux_line("Invalid user bob from 192.0.2.10 port 22"))

    assert invoke_linux(input_path, "--output", "json") == 0

    output = json.loads(capsys.readouterr().out)
    assert output[0]["rule_id"] == "invalid_user"


def test_zero_alerts_return_success_and_empty_json_output(tmp_path, capsys):
    input_path = tmp_path / "no-detections.log"
    input_path.write_text("not a valid Linux authentication record")

    assert invoke_linux(input_path, "--output", "json") == 0

    output = capsys.readouterr()
    assert json.loads(output.out) == []
    assert output.err == ""


def test_input_file_error(capsys):
    with pytest.raises(SystemExit) as error:
        main(
            [
                "--input",
                str(FIXTURES / "linux" / "definitely-nonexistent.log"),
                "--format",
                "linux-auth",
                "--reference-time",
                "2026-09-02T14:00:00+00:00",
                "--output",
                "json",
            ]
        )

    assert error.value.code == 2
    assert "input file not found" in capsys.readouterr().err


def test_alert_detection_returns_zero(tmp_path, capsys):
    lines = [
        linux_line(
            "Failed password for alice from 203.0.113.50 port 2222", second
        )
        for second in (0, 10, 20, 30, 40)
    ]
    input_path = tmp_path / "brute-force.log"
    input_path.write_text("\n".join(lines))

    assert invoke_linux(input_path, "--output", "json") == 0

    output = json.loads(capsys.readouterr().out)
    assert output[0]["rule_id"] == "ssh_brute_force"


def test_linux_brute_force_and_invalid_user_fixture(capsys):
    output_code = main(
        [
            "--input",
            str(FIXTURES / "linux" / "ssh_bruteforce_and_invalid_user.log"),
            "--format",
            "linux-auth",
            "--reference-time",
            "2026-09-02T14:00:00+00:00",
            "--output",
            "json",
        ]
    )

    assert output_code == 0
    alerts = json.loads(capsys.readouterr().out)
    assert [alert["rule_id"] for alert in alerts] == [
        "ssh_brute_force",
        "invalid_user",
    ]
    assert len(alerts) == 2
    assert alerts[0]["severity"] == "high"
    assert alerts[1]["severity"] == "medium"
    assert alerts[0]["source_ip"] == "198.51.100.50"
    assert alerts[0]["username"] == "alice"
    assert alerts[1]["username"] == "admin"
    assert len(alerts[0]["evidence"]) == 5
    assert len(alerts[0]["raw_events"]) == 5


def test_linux_password_spraying_fixture(capsys):
    output_code = main(
        [
            "--input",
            str(FIXTURES / "linux" / "password_spraying.log"),
            "--format",
            "linux-auth",
            "--reference-time",
            "2026-09-02T14:00:00+00:00",
            "--output",
            "json",
        ]
    )

    assert output_code == 0
    alerts = json.loads(capsys.readouterr().out)
    assert [alert["rule_id"] for alert in alerts] == [
        "invalid_user",
        "password_spraying",
    ]
    assert len(alerts) == 2
    password_spraying = alerts[1]
    assert password_spraying["severity"] == "high"
    assert password_spraying["source_ip"] == "203.0.113.50"
    assert password_spraying["username"] is None
    assert password_spraying["evidence"] == [
        "Source 203.0.113.50 attempted authentication for 5 distinct "
        "usernames within 60 seconds: alice, bob, charlie, david, eve."
    ]
    assert len(password_spraying["raw_events"]) == 5
