"""Replay a generated dataset through the real detection pipeline."""

import argparse
import json
import sys
import time
import tracemalloc
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from threat_detector.detection.engine import DetectionEngine
from threat_detector.detection.rules.ssh_brute_force import SSHBruteForceRule
from threat_detector.normalization.linux_auth import normalize_linux_event
from threat_detector.parsers.linux_auth import parse_line


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("dataset", type=Path, help="Generated log file to replay")
	parser.add_argument(
		"--results-dir",
		type=Path,
		default=Path(__file__).resolve().parent / "results",
	)
	parser.add_argument(
		"--memory",
		action="store_true",
		help="Enable tracemalloc peak-allocation measurement",
	)
	return parser.parse_args()


def run(dataset: Path, memory: bool = False) -> dict[str, Any]:
	engine = DetectionEngine([SSHBruteForceRule()])
	total_events = 0
	parsed_events = 0
	alerts_generated = 0

	if memory:
		tracemalloc.start()
	started = time.perf_counter()
	with dataset.open(encoding="utf-8") as input_file:
		for line in input_file:
			total_events += 1
			raw_line = line.rstrip("\r\n")
			parsed = parse_line(raw_line)
			if parsed is None:
				continue
			event = normalize_linux_event(parsed)
			parsed_events += 1
			alerts_generated += len(engine.process(event))
	elapsed_seconds = time.perf_counter() - started
	peak_bytes = None
	if memory:
		_, peak_bytes = tracemalloc.get_traced_memory()
		tracemalloc.stop()
	events_per_second = total_events / elapsed_seconds if elapsed_seconds else 0.0

	return {
		"timestamp": datetime.now().astimezone().isoformat(),
		"dataset": dataset.name,
		"event_count": total_events,
		"parsed_event_count": parsed_events,
		"elapsed_seconds": elapsed_seconds,
		"events_per_second": events_per_second,
		"alerts_generated": alerts_generated,
		"memory_tracing_enabled": memory,
		"memory": (
			{
				"measurement": "peak traced Python allocations",
				"peak_bytes": peak_bytes,
				"peak_megabytes": peak_bytes / (1024 * 1024),
			}
			if peak_bytes is not None
			else None
		),
	}


def main() -> None:
	args = parse_args()
	if not args.dataset.is_file():
		raise SystemExit(f"Dataset not found: {args.dataset}")

	result = run(args.dataset, memory=args.memory)
	args.results_dir.mkdir(parents=True, exist_ok=True)
	result_path = args.results_dir / f"{args.dataset.stem}_{datetime.now():%Y%m%dT%H%M%S}.json"
	result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

	print(f"Dataset: {result['dataset']}")
	print(f"Events: {result['event_count']}")
	print(f"Elapsed: {result['elapsed_seconds']:.6f} seconds")
	print(f"Events/sec: {result['events_per_second']:.2f}")
	print(f"Alerts: {result['alerts_generated']}")
	if result["memory"] is None:
		print("Memory: disabled")
	else:
		print(
			f"Memory: {result['memory']['peak_megabytes']:.2f} MiB "
			"peak traced Python allocations"
		)
	print(f"Results: {result_path}")


if __name__ == "__main__":
	main()
