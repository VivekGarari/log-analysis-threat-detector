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


FAILED_PASSWORD_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\w+)\[(?P<pid>\d+)\]:\s+"
    r"Failed password for (?P<username>\S+) from "
    r"(?P<source_ip>\S+) port (?P<source_port>\d+)"
)


def parse_line(line: str) -> LinuxAuthEvent | None:
    match = FAILED_PASSWORD_PATTERN.match(line)

    if not match:
        return None

    data = match.groupdict()

    return LinuxAuthEvent(
        timestamp=data["timestamp"],
        hostname=data["hostname"],
        process=data["process"],
        pid=int(data["pid"]),
        event_type="authentication_failure",
        username=data["username"],
        source_ip=data["source_ip"],
        source_port=int(data["source_port"]),
        raw=line,
    )