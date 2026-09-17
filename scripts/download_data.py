"""Download or validate raw datasets.

The actual source URLs and checksums must be recorded in config before download.
"""
from pathlib import Path


def main() -> None:
    for path in (Path("data/raw/BGL"), Path("data/raw/HDFS")):
        path.mkdir(parents=True, exist_ok=True)
        print(f"Raw data directory ready: {path}")


if __name__ == "__main__":
    main()
