import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass
class WindowsSecurityAuthEvent:
    timestamp: str | None
    hostname: str | None
    username: str | None
    source_ip: str | None
    source_port: int | None
    event_id: int
    raw: str


SUPPORTED_EVENT_IDS = {4624, 4625}


def _element_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _clean_value(value: str | None) -> str | None:
    if value is None:
        return None

    value = value.strip()
    return None if not value or value == "-" else value


def _event_data_values(root: ET.Element) -> dict[str, str | None]:
    values: dict[str, str | None] = {}
    for element in root.iter():
        if _element_name(element.tag) != "Data":
            continue
        name = element.attrib.get("Name")
        if name:
            values[name] = _clean_value(element.text)
    return values


def parse_event(xml_text: str) -> WindowsSecurityAuthEvent | None:
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, TypeError):
        return None

    event_id_text = next(
        (element.text for element in root.iter() if _element_name(element.tag) == "EventID"),
        None,
    )
    try:
        event_id = int(event_id_text.strip()) if event_id_text else None
    except ValueError:
        return None

    if event_id not in SUPPORTED_EVENT_IDS:
        return None

    time_created = next(
        (
            element.attrib.get("SystemTime")
            for element in root.iter()
            if _element_name(element.tag) == "TimeCreated"
        ),
        None,
    )
    hostname = next(
        (element.text for element in root.iter() if _element_name(element.tag) == "Computer"),
        None,
    )
    values = _event_data_values(root)
    source_port_text = values.get("IpPort")
    try:
        source_port = int(source_port_text) if source_port_text else None
    except ValueError:
        source_port = None

    return WindowsSecurityAuthEvent(
        timestamp=_clean_value(time_created),
        hostname=_clean_value(hostname),
        username=values.get("TargetUserName"),
        source_ip=values.get("IpAddress"),
        source_port=source_port,
        event_id=event_id,
        raw=xml_text,
    )