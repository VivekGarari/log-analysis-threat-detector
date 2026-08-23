"""Generate deterministic synthetic Linux SSH authentication logs."""

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path
from collections.abc import Iterator

DEFAULT_SEED = 20260823
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[1] / "data" / "generated"
HOSTNAMES = ("web-01", "web-02", "app-01", "gateway-01")
USERS = ("alice", "bob", "carol", "dave", "deploy", "svc-backup")
SOURCE_IPS = tuple(
	[f"192.0.2.{index}" for index in range(1, 255)]
	+ [f"198.51.100.{index}" for index in range(1, 255)]
)
ATTACK_IP = "203.0.113.50"


def _failure(timestamp: datetime, rng: random.Random, source_ip: str | None = None) -> str:
	hostname = rng.choice(HOSTNAMES)
	pid = rng.randint(1000, 99999)
	username = rng.choice(USERS)
	source_ip = source_ip or rng.choice(SOURCE_IPS)
	port = rng.randint(2200, 2299)
	return (
		f"{timestamp.strftime('%b %e %H:%M:%S')} {hostname} sshd[{pid}]: "
		f"Failed password for {username} from {source_ip} port {port} ssh2"
	)


def _success(timestamp: datetime, rng: random.Random) -> str:
	hostname = rng.choice(HOSTNAMES)
	pid = rng.randint(1000, 99999)
	username = rng.choice(USERS)
	source_ip = rng.choice(SOURCE_IPS)
	port = rng.randint(2200, 2299)
	return (
		f"{timestamp.strftime('%b %e %H:%M:%S')} {hostname} sshd[{pid}]: "
		f"Accepted password for {username} from {source_ip} port {port} ssh2"
	)


def _invalid_user(timestamp: datetime, rng: random.Random) -> str:
	hostname = rng.choice(HOSTNAMES)
	pid = rng.randint(1000, 99999)
	username = f"unknown{rng.randint(1, 999)}"
	source_ip = rng.choice(SOURCE_IPS)
	port = rng.randint(2200, 2299)
	return (
		f"{timestamp.strftime('%b %e %H:%M:%S')} {hostname} sshd[{pid}]: "
		f"Invalid user {username} from {source_ip} port {port}"
	)


def generate_lines(
    event_count: int,
    scenario: str,
    seed: int,
) -> Iterator[str]:
	rng = random.Random(seed)
	timestamp = datetime(2026, 1, 1)

	attack_count = 0
	attack_start = event_count
	if scenario in {"brute-force", "mixed"}:
		attack_count = min(event_count, max(5, event_count // 10))
		if scenario == "brute-force":
			attack_start = 0
		elif event_count > attack_count:
			minimum_start = min(event_count // 4, event_count - attack_count)
			maximum_start = max(
				minimum_start,
				min((event_count * 3) // 4, event_count - attack_count),
			)
			attack_start = rng.randint(minimum_start, maximum_start)

	for index in range(event_count):
		if attack_start <= index < attack_start + attack_count:
			line = _failure(timestamp, rng, ATTACK_IP)
			timestamp += timedelta(seconds=rng.randint(1, 8))
		else:
			event_kind = rng.choices(
				("failure", "success", "invalid"),
				weights=(55, 30, 15),
				k=1,
			)[0]
			if event_kind == "failure":
				line = _failure(timestamp, rng)
			elif event_kind == "success":
				line = _success(timestamp, rng)
			else:
				line = _invalid_user(timestamp, rng)
			timestamp += timedelta(seconds=rng.randint(1, 30))
		yield line


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--events", type=int, required=True, help="Number of log lines to generate")
	parser.add_argument(
		"--scenario",
		choices=("normal", "brute-force", "mixed"),
		default="normal",
		help="Authentication activity profile (default: normal)",
	)
	parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Random seed")
	parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
	return parser.parse_args()


def main() -> None:
	args = parse_args()
	if args.events < 1:
		raise SystemExit("--events must be at least 1")

	args.output_dir.mkdir(parents=True, exist_ok=True)
	output_path = args.output_dir / f"{args.events}_{args.scenario}.log"
	with output_path.open("w", encoding="utf-8", newline="\n") as output_file:
		for line in generate_lines(args.events, args.scenario, args.seed):
			output_file.write(line + "\n")
	print(f"Generated {args.events} events at {output_path}")


if __name__ == "__main__":
	main()
