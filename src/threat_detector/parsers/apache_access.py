import re
from dataclasses import dataclass


@dataclass
class ApacheAccessEvent:
    timestamp: str
    client_ip: str | None
    username: str | None
    method: str
    path: str
    protocol: str
    status_code: int
    response_size: int | None
    referrer: str | None
    user_agent: str | None
    raw: str


COMBINED_PATTERN = re.compile(
    r'^(?P<client_ip>\S+)\s+\S+\s+(?P<username>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]+)"\s+(?P<status_code>\d{3})\s+'
    r'(?P<response_size>\S+)\s+"(?P<referrer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"$'
)

REQUEST_PATTERN = re.compile(
    r'^(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>HTTP/\d(?:\.\d)?)$'
)


def _clean_value(value: str) -> str | None:
    return None if value == "-" else value


def parse_line(line: str) -> ApacheAccessEvent | None:
    match = COMBINED_PATTERN.fullmatch(line)
    if match is None:
        return None

    data = match.groupdict()
    request_match = REQUEST_PATTERN.fullmatch(data["request"])
    if request_match is None:
        return None

    try:
        status_code = int(data["status_code"])
        response_size = (
            None
            if data["response_size"] == "-"
            else int(data["response_size"])
        )
    except ValueError:
        return None

    request_data = request_match.groupdict()
    return ApacheAccessEvent(
        timestamp=data["timestamp"],
        client_ip=_clean_value(data["client_ip"]),
        username=_clean_value(data["username"]),
        method=request_data["method"],
        path=request_data["path"],
        protocol=request_data["protocol"],
        status_code=status_code,
        response_size=response_size,
        referrer=_clean_value(data["referrer"]),
        user_agent=_clean_value(data["user_agent"]),
        raw=line,
    )