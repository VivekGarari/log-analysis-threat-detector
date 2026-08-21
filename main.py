from src.threat_detector.ingestion.reader import read_log_file
from src.threat_detector.parsers.linux_auth import parse_line


def main():
    lines = read_log_file("data/linux/auth.log")

    for line in lines:
        event = parse_line(line)

        if event:
            print(event)


if __name__ == "__main__":
    main()