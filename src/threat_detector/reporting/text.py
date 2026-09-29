from collections.abc import Iterable

from threat_detector.alerts.models import Alert
from threat_detector.resource_limits import ResourceLimitExceeded


def _display(value: object) -> str:
    return "N/A" if value is None else str(value)


def _display_list(values: list[str]) -> str:
    if not values:
        return "N/A"
    return "\n".join(f"  - {value}" for value in values)


def _escape_terminal_controls(value: str) -> str:
    escaped: list[str] = []
    for character in value:
        if character.isprintable():
            escaped.append(character)
        elif ord(character) <= 0xFF:
            escaped.append(f"\\x{ord(character):02x}")
        elif ord(character) <= 0xFFFF:
            escaped.append(f"\\u{ord(character):04x}")
        else:
            escaped.append(f"\\U{ord(character):08x}")
    return "".join(escaped)


def _display_raw_events(values: list[str]) -> str:
    if not values:
        return "N/A"
    return _display_list([_escape_terminal_controls(value) for value in values])


def _render_alert(alert: Alert) -> str:
    return "\n".join(
        [
            "Alert",
            f"alert_id: {_display(alert.alert_id)}",
            f"rule_id: {_display(alert.rule_id)}",
            f"severity: {_display(alert.severity)}",
            f"title: {_display(alert.title)}",
            f"description: {_display(alert.description)}",
            f"timestamp: {_display(alert.timestamp.isoformat())}",
            f"source_ip: {_display(alert.source_ip)}",
            f"username: {_display(alert.username)}",
            "evidence:",
            _display_list(alert.evidence),
            "raw_events:",
            _display_raw_events(alert.raw_events),
        ]
    )


def _raw_event_display_bytes(value: str) -> int:
    output_bytes = 0
    for character in value:
        if character.isprintable():
            output_bytes += len(character.encode("utf-8"))
        elif ord(character) <= 0xFF:
            output_bytes += 4
        elif ord(character) <= 0xFFFF:
            output_bytes += 6
        else:
            output_bytes += 10
    return output_bytes


def _alert_report_bytes(alert: Alert) -> int:
    lines = [
        "Alert",
        f"alert_id: {_display(alert.alert_id)}",
        f"rule_id: {_display(alert.rule_id)}",
        f"severity: {_display(alert.severity)}",
        f"title: {_display(alert.title)}",
        f"description: {_display(alert.description)}",
        f"timestamp: {_display(alert.timestamp.isoformat())}",
        f"source_ip: {_display(alert.source_ip)}",
        f"username: {_display(alert.username)}",
        "evidence:",
    ]
    if alert.evidence:
        lines.extend(f"  - {value}" for value in alert.evidence)
    else:
        lines.append("N/A")
    lines.append("raw_events:")
    if alert.raw_events:
        raw_event_line_count = len(alert.raw_events)
        raw_event_bytes = sum(
            len("  - ".encode("utf-8")) + _raw_event_display_bytes(value)
            for value in alert.raw_events
        )
    else:
        raw_event_line_count = 1
        raw_event_bytes = len("N/A".encode("utf-8"))
    return (
        sum(len(line.encode("utf-8")) for line in lines)
        + raw_event_bytes
        + (len(lines) + raw_event_line_count - 1)
    )


def report(alerts: Iterable[Alert], *, max_bytes: int | None = None) -> str:
    blocks: list[str] = []
    output_bytes = 0
    for alert in alerts:
        if max_bytes is not None:
            attempted_bytes = output_bytes + _alert_report_bytes(alert) + (2 if blocks else 0)
            if attempted_bytes > max_bytes:
                raise ResourceLimitExceeded(
                    "report UTF-8 bytes", max_bytes, attempted_bytes
                )
        block = _render_alert(alert)
        block_bytes = len(block.encode("utf-8"))
        next_bytes = output_bytes + block_bytes + (2 if blocks else 0)
        if max_bytes is not None and next_bytes > max_bytes:
            raise ResourceLimitExceeded("report UTF-8 bytes", max_bytes, next_bytes)
        blocks.append(block)
        output_bytes = next_bytes
    return "\n\n".join(blocks)
