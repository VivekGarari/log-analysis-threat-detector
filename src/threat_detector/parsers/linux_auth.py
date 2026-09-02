import re
from dataclasses import dataclass


@dataclass
class LinuxAuthEvent:
    timestamp: str
    hostname: str
    process: str
    pid: int | None
    event_type: str
    username: str | None
    source_ip: str | None
    source_port: int | None
    raw: str


BASE_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\w+)\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.+)$"
)


FAILED_PATTERN = re.compile(
    r"Failed\s+password\s+for\s+(?P<username>\S+)\s+"
    r"from\s+(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
    r"port\s*(?P<source_port>\d+)"
    r"(?:\s+ssh2)?$"
)


ACCEPTED_PATTERN = re.compile(
    r"Accepted\s+password\s+for\s+(?P<username>\S+)\s+"
    r"from\s+(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
    r"port\s*(?P<source_port>\d+)"
    r"(?:\s+ssh2)?$"
)


INVALID_USER_PATTERN = re.compile(
    r"Invalid\s+user\s+(?P<username>\S+)\s+"
    r"from\s+(?P<source_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
    r"port\s*(?P<source_port>\d+)"
    r"(?:\s+ssh2)?$"
)


def parse_line(line: str) -> LinuxAuthEvent | None:
    match = BASE_PATTERN.match(line)

    if not match:
        return None

    data = match.groupdict()
    message = data["message"]

    event_type = None
    event_match = None

    for candidate_type, pattern in (
        ("authentication_failure", FAILED_PATTERN),
        ("authentication_success", ACCEPTED_PATTERN),
        ("invalid_user", INVALID_USER_PATTERN),
    ):
        event_match = pattern.fullmatch(message)
        if event_match:
            event_type = candidate_type
            break

    if event_type is None or event_match is None:
        return None

    event_data = event_match.groupdict()

    return LinuxAuthEvent(
        timestamp=data["timestamp"],
        hostname=data["hostname"],
        process=data["process"],
        pid=int(data["pid"]),
        event_type=event_type,
        username=event_data["username"],
        source_ip=event_data["source_ip"],
        source_port=int(event_data["source_port"]),
        raw=line,
    )
