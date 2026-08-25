import gc
import time
import tracemalloc
from datetime import datetime, timedelta, timezone

from threat_detector.detection.rules.ssh_brute_force import SSHBruteForceRule
from threat_detector.normalization.event import NormalizedEvent


# Investigative benchmark for retained state, not a pytest correctness requirement.
def test_state_retention_by_source_ip_cardinality():
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat()
    cardinalities = (10_000, 100_000, 500_000)

    print("unique_ips,failures_entries,retained_events,current_bytes,peak_bytes")
    for unique_ip_count in cardinalities:
        gc.collect()
        tracemalloc.start()
        rule = SSHBruteForceRule()

        for index in range(unique_ip_count):
            source_ip = f"198.51.{index // 256}.{index % 256}"
            rule.process(
                NormalizedEvent(
                    timestamp=timestamp,
                    source="linux_auth",
                    event_type="authentication_failure",
                    hostname="server",
                    username="alice",
                    source_ip=source_ip,
                    source_port=22,
                    success=False,
                    raw=f"authentication failure from {source_ip}",
                )
            )

        current_bytes, peak_bytes = tracemalloc.get_traced_memory()
        retained_events = sum(len(failures) for failures in rule._failures.values())
        print(
            f"{unique_ip_count},{len(rule._failures)},{retained_events},"
            f"{current_bytes},{peak_bytes}"
        )

        tracemalloc.stop()
        del rule
        gc.collect()


def test_expiration_of_500_000_source_ips():
    start_timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    sentinel_ip = "203.0.113.254"
    rule = SSHBruteForceRule()

    gc.collect()
    tracemalloc.start()
    start_time = time.perf_counter()
    for index in range(500_000):
        source_ip = f"198.51.{index // 256}.{index % 256}"
        rule.process(
            NormalizedEvent(
                timestamp=start_timestamp.isoformat(),
                source="linux_auth",
                event_type="authentication_failure",
                hostname="server",
                username="alice",
                source_ip=source_ip,
                source_port=22,
                success=False,
                raw=f"authentication failure from {source_ip}",
            )
        )

    sentinel_timestamp = start_timestamp + timedelta(
        seconds=rule.window_seconds + 1
    )
    rule.process(
        NormalizedEvent(
            timestamp=sentinel_timestamp.isoformat(),
            source="linux_auth",
            event_type="authentication_failure",
            hostname="server",
            username="alice",
            source_ip=sentinel_ip,
            source_port=22,
            success=False,
            raw="sentinel authentication failure",
        )
    )
    elapsed_seconds = time.perf_counter() - start_time
    current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    retained_events = sum(len(failures) for failures in rule._failures.values())
    print(
        "active_ips,retained_events,expiration_heap_entries,current_bytes,"
        "peak_bytes,elapsed_seconds"
    )
    print(
        f"{len(rule._failures)},{retained_events},{len(rule._expiration_heap)},"
        f"{current_bytes},{peak_bytes},{elapsed_seconds:.6f}"
    )

    assert set(rule._failures) == {sentinel_ip}
    assert retained_events == 1
    assert len(rule._expiration_heap) == 1

    tracemalloc.stop()


def test_expired_per_ip_state_is_removed():
    rule = SSHBruteForceRule()
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    source_ips = ("198.51.100.1", "198.51.100.2", "198.51.100.3")

    for source_ip in source_ips:
        rule.process(
            NormalizedEvent(
                timestamp=timestamp.isoformat(),
                source="linux_auth",
                event_type="authentication_failure",
                hostname="server",
                username="alice",
                source_ip=source_ip,
                source_port=22,
                success=False,
                raw=f"authentication failure from {source_ip}",
            )
        )

    expired_timestamp = timestamp + timedelta(seconds=rule.window_seconds + 1)
    rule.process(
        NormalizedEvent(
            timestamp=expired_timestamp.isoformat(),
            source="linux_auth",
            event_type="authentication_failure",
            hostname="server",
            username="alice",
            source_ip="198.51.100.1",
            source_port=22,
            success=False,
            raw="authentication failure after the window",
        )
    )

    assert set(rule._failures) == {"198.51.100.1"}
