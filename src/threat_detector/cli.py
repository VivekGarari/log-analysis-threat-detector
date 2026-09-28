import argparse
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from threat_detector.application.pipeline import DetectionPipeline
from threat_detector.application.processor import process_and_persist
from threat_detector.correlation.engine import CorrelationEngine
from threat_detector.detection.engine import DetectionEngine
from threat_detector.detection.rules.invalid_user import InvalidUserRule
from threat_detector.detection.rules.password_spraying import PasswordSprayingRule
from threat_detector.detection.rules.ssh_brute_force import SSHBruteForceRule
from threat_detector.detection.rules.web_reconnaissance import WebReconnaissanceRule
from threat_detector.ingestion.reader import read_log_file
from threat_detector.normalization.apache_access import normalize_apache_access_event
from threat_detector.normalization.linux_auth import normalize_linux_event
from threat_detector.normalization.windows_security import (
    normalize_windows_security_event,
)
from threat_detector.parsers.apache_access import parse_line as parse_apache_line
from threat_detector.parsers.linux_auth import parse_line as parse_linux_line
from threat_detector.parsers.windows_security import parse_event as parse_windows_event
from threat_detector.reporting import report_json, report_text


SUPPORTED_FORMATS = ("linux-auth", "windows-security", "apache-access")
SUPPORTED_OUTPUTS = ("text", "json")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="threat-detector")
    parser.add_argument("--input", required=True, help="input log file")
    parser.add_argument("--format", required=True, choices=SUPPORTED_FORMATS)
    parser.add_argument(
        "--output", choices=SUPPORTED_OUTPUTS, default="text", help="output format"
    )
    parser.add_argument(
        "--reference-time",
        help="timezone-aware ISO-8601 reference time for linux-auth",
    )
    parser.add_argument(
        "--database",
        type=Path,
        help=(
            "SQLite database for Findings (defaults to THREAT_DETECTOR_DATABASE "
            "or threat_detector.sqlite3 in the current directory)"
        ),
    )
    return parser


def _parse_reference_time(parser: argparse.ArgumentParser, value: str | None) -> datetime:
    if value is None:
        parser.error("--reference-time is required for --format linux-auth")

    try:
        reference_time = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        parser.error(f"invalid --reference-time: {error}")

    if reference_time.tzinfo is None or reference_time.utcoffset() is None:
        parser.error("--reference-time must be timezone-aware")

    return reference_time


def _build_pipeline(
    record_format: str,
    reference_time: datetime | None,
) -> DetectionPipeline:
    engine = DetectionEngine(
        [SSHBruteForceRule(), InvalidUserRule(), PasswordSprayingRule(), WebReconnaissanceRule()]
    )

    if record_format == "linux-auth":
        assert reference_time is not None
        return DetectionPipeline(
            parse_linux_line,
            lambda event: normalize_linux_event(event, reference_time),
            engine,
            CorrelationEngine(),
        )
    elif record_format == "windows-security":
        return DetectionPipeline(
            parse_windows_event,
            normalize_windows_security_event,
            engine,
            CorrelationEngine(),
        )
    return DetectionPipeline(
        parse_apache_line,
        normalize_apache_access_event,
        engine,
        CorrelationEngine(),
    )


def main(argv: Sequence[str] | None = None) -> int:
    argument_parser = _build_parser()
    args = argument_parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.exists():
        argument_parser.error(f"input file not found: {args.input}")
    if not input_path.is_file():
        argument_parser.error(f"input path is not a file: {args.input}")

    reference_time = (
        _parse_reference_time(argument_parser, args.reference_time)
        if args.format == "linux-auth"
        else None
    )

    try:
        if args.format == "windows-security":
            records = [input_path.read_text(encoding="utf-8")]
        else:
            records = read_log_file(str(input_path))

        result = process_and_persist(
            _build_pipeline(args.format, reference_time), records, args.database
        )
        output = (
            report_json(result.alerts)
            if args.output == "json"
            else report_text(result.alerts)
        )
        print(output)
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
