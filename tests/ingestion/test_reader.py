from dataclasses import replace

import pytest

from threat_detector.ingestion.reader import iter_log_file, read_log_file, read_windows_xml_file
from threat_detector.resource_limits import DEFAULT_RESOURCE_LIMITS, ResourceLimitExceeded


def limits(**overrides):
    return replace(DEFAULT_RESOURCE_LIMITS, **overrides)


def test_streaming_reader_preserves_splitlines_boundaries(tmp_path):
    cases = (
        (b"", []),
        (b"one\ntwo", ["one", "two"]),
        (b"one\r\ntwo\rthree", ["one", "two", "three"]),
        (b"\n\n", ["", ""]),
        ("one\vtwo\fthree\x1cfour\x1dfive\x1esix\x85seven\u2028eight\u2029".encode(),
         ["one", "two", "three", "four", "five", "six", "seven", "eight"]),
        ("café\n尾".encode("utf-8"), ["café", "尾"]),
    )

    for index, (raw, expected) in enumerate(cases):
        path = tmp_path / f"case-{index}.log"
        path.write_bytes(raw)
        assert list(iter_log_file(str(path), limits())) == expected
        assert read_log_file(str(path), limits()) == expected


def test_file_byte_limit_accepts_exact_and_rejects_one_over(tmp_path):
    path = tmp_path / "input.log"
    path.write_bytes(b"a\nb")

    assert list(iter_log_file(str(path), limits(max_input_bytes=3))) == ["a", "b"]

    path.write_bytes(b"a\nbx")
    with pytest.raises(ResourceLimitExceeded, match="input file bytes"):
        list(iter_log_file(str(path), limits(max_input_bytes=3)))


def test_record_count_limit_accepts_exact_and_rejects_one_over(tmp_path):
    path = tmp_path / "input.log"
    path.write_bytes(b"a\nb")

    assert list(iter_log_file(str(path), limits(max_records=2))) == ["a", "b"]

    path.write_bytes(b"a\nb\nc")
    with pytest.raises(ResourceLimitExceeded, match="input record count"):
        list(iter_log_file(str(path), limits(max_records=2)))


def test_record_byte_limit_accepts_exact_and_rejects_one_over(tmp_path):
    path = tmp_path / "input.log"
    path.write_bytes(b"ab\nc")

    assert list(iter_log_file(str(path), limits(max_record_bytes=2))) == ["ab", "c"]

    path.write_bytes(b"abc")
    with pytest.raises(ResourceLimitExceeded, match="input record UTF-8 bytes"):
        list(iter_log_file(str(path), limits(max_record_bytes=2)))


def test_record_byte_limit_counts_utf8_bytes_not_characters(tmp_path):
    path = tmp_path / "utf8.log"
    path.write_text("é", encoding="utf-8")

    assert list(iter_log_file(str(path), limits(max_record_bytes=2))) == ["é"]
    with pytest.raises(ResourceLimitExceeded, match="input record UTF-8 bytes"):
        list(iter_log_file(str(path), limits(max_record_bytes=1)))


def test_crlf_split_across_binary_chunks_is_one_record_boundary(tmp_path):
    path = tmp_path / "chunk-boundary.log"
    path.write_bytes(b"a" * (64 * 1024 - 1) + b"\r\nb")

    assert list(
        iter_log_file(
            str(path),
            limits(max_input_bytes=64 * 1024 + 2, max_record_bytes=64 * 1024),
        )
    ) == ["a" * (64 * 1024 - 1), "b"]


def test_utf8_codepoint_split_across_binary_chunks_is_counted_correctly(tmp_path):
    path = tmp_path / "utf8-chunk-boundary.log"
    path.write_bytes(("a" * (64 * 1024 - 1) + "é").encode("utf-8"))

    assert list(
        iter_log_file(
            str(path),
            limits(max_input_bytes=64 * 1024 + 1, max_record_bytes=64 * 1024 + 1),
        )
    ) == ["a" * (64 * 1024 - 1) + "é"]


def test_windows_xml_reader_accepts_exact_byte_limit_and_rejects_one_over(tmp_path):
    path = tmp_path / "event.xml"
    path.write_bytes(b"<Event/>")

    exact_limits = limits(max_input_bytes=8, windows_xml_max_bytes=8)
    assert read_windows_xml_file(path, exact_limits) == "<Event/>"

    path.write_bytes(b"<Event />")
    with pytest.raises(ResourceLimitExceeded, match="Windows XML bytes"):
        read_windows_xml_file(path, exact_limits)


def test_windows_xml_respects_common_input_limit(tmp_path):
    path = tmp_path / "event.xml"
    path.write_bytes(b"<Event/>")

    with pytest.raises(ResourceLimitExceeded, match="Windows XML bytes"):
        read_windows_xml_file(
            path,
            limits(max_input_bytes=7, windows_xml_max_bytes=8),
        )
