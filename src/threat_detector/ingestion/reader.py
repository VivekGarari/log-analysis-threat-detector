import codecs
from collections.abc import Iterator
from io import BufferedReader
from pathlib import Path
import re

from threat_detector.resource_limits import (
    DEFAULT_RESOURCE_LIMITS,
    ResourceLimitExceeded,
    ResourceLimits,
)


_READ_CHUNK_BYTES = 64 * 1024
_SPLITLINE_PATTERN = re.compile(r"\r\n|[\r\n\v\f\x1c-\x1e\x85\u2028\u2029]")


def _decoded_chunks(stream: BufferedReader, limits: ResourceLimits) -> Iterator[str]:
    decoder = codecs.getincrementaldecoder("utf-8")()
    bytes_read = 0

    while True:
        remaining = limits.max_input_bytes - bytes_read
        chunk = stream.read(min(_READ_CHUNK_BYTES, remaining + 1))
        if not chunk:
            break

        bytes_read += len(chunk)
        if bytes_read > limits.max_input_bytes:
            raise ResourceLimitExceeded(
                "input file bytes", limits.max_input_bytes, bytes_read
            )

        decoded = decoder.decode(chunk, final=False)
        if decoded:
            yield decoded

    final_text = decoder.decode(b"", final=True)
    if final_text:
        yield final_text


def _splitlines(chunks: Iterator[str], max_record_bytes: int) -> Iterator[str]:
    fragments: list[str] = []
    record_bytes = 0
    trailing_carriage_return = False

    for chunk in chunks:
        text = ("\r" if trailing_carriage_return else "") + chunk
        trailing_carriage_return = text.endswith("\r")
        if trailing_carriage_return:
            text = text[:-1]

        position = 0
        for match in _SPLITLINE_PATTERN.finditer(text):
            fragment = text[position : match.start()]
            fragment_bytes = len(fragment.encode("utf-8"))
            attempted_bytes = record_bytes + fragment_bytes
            if attempted_bytes > max_record_bytes:
                raise ResourceLimitExceeded(
                    "input record UTF-8 bytes", max_record_bytes, attempted_bytes
                )
            if fragment:
                fragments.append(fragment)
            yield "".join(fragments)
            fragments.clear()
            record_bytes = 0
            position = match.end()

        fragment = text[position:]
        fragment_bytes = len(fragment.encode("utf-8"))
        attempted_bytes = record_bytes + fragment_bytes
        if attempted_bytes > max_record_bytes:
            raise ResourceLimitExceeded(
                "input record UTF-8 bytes", max_record_bytes, attempted_bytes
            )
        if fragment:
            fragments.append(fragment)
        record_bytes = attempted_bytes

    if trailing_carriage_return:
        yield "".join(fragments)
    elif fragments:
        yield "".join(fragments)


def iter_log_file(
    path: str,
    limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS,
) -> Iterator[str]:
    log_path = Path(path)

    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    if not log_path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    with log_path.open("rb") as stream:
        record_count = 0
        for record in _splitlines(
            _decoded_chunks(stream, limits), limits.max_record_bytes
        ):
            record_count += 1
            if record_count > limits.max_records:
                raise ResourceLimitExceeded(
                    "input record count", limits.max_records, record_count
                )
            yield record


def read_log_file(
    path: str,
    limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS,
) -> list[str]:
    return list(iter_log_file(path, limits))


def read_windows_xml_file(
    path: str | Path,
    limits: ResourceLimits = DEFAULT_RESOURCE_LIMITS,
) -> str:
    xml_path = Path(path)

    if not xml_path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    if not xml_path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    max_bytes = min(limits.max_input_bytes, limits.windows_xml_max_bytes)
    with xml_path.open("rb") as stream:
        raw_xml = stream.read(max_bytes + 1)
    if len(raw_xml) > max_bytes:
        raise ResourceLimitExceeded("Windows XML bytes", max_bytes, len(raw_xml))

    decoded_xml = raw_xml.decode("utf-8")
    return decoded_xml.replace("\r\n", "\n").replace("\r", "\n")