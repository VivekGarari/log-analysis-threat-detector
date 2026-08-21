from pathlib import Path


def read_log_file(path: str) -> list[str]:
    log_path = Path(path)

    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    if not log_path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    return log_path.read_text(encoding="utf-8").splitlines()