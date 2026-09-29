from collections.abc import Iterable

from threat_detector.alerts.models import Alert


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


def report(alerts: Iterable[Alert]) -> str:
    blocks: list[str] = []

    for alert in alerts:
        blocks.append(
            "\n".join(
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
        )

    return "\n\n".join(blocks)
