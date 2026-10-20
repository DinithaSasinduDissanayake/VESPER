"""Build the publication-date-filtered CVE population from monthly NVD snapshots."""

from __future__ import annotations

import argparse
import csv
import gzip
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RESEARCH_START = datetime(2016, 1, 1, tzinfo=UTC)
RESEARCH_END_EXCLUSIVE = datetime(2026, 10, 15, tzinfo=UTC)


def parse_published(value: str) -> datetime:
    """Parse an NVD publication timestamp, treating naive values as UTC."""
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    published = datetime.fromisoformat(normalized)

    if published.tzinfo is None:
        published = published.replace(tzinfo=UTC)

    return published.astimezone(UTC)


def build_population(
    snapshot_dir: Path,
) -> dict[str, datetime]:
    """Collect unique CVEs published within the research interval."""
    population: dict[str, datetime] = {}

    for path in sorted(snapshot_dir.glob("nvd_*.json.gz")):
        try:
            with gzip.open(path, "rt", encoding="utf-8") as file:
                data: dict[str, Any] = json.load(file)
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"Cannot read snapshot {path}: {error}") from error

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            published_value = cve.get("published")

            if not isinstance(cve_id, str) or not cve_id:
                raise ValueError(f"Missing CVE ID in {path}")

            if not isinstance(published_value, str) or not published_value:
                raise ValueError(f"Missing publication timestamp for {cve_id}")

            try:
                published = parse_published(published_value)
            except ValueError as error:
                raise ValueError(
                    f"Invalid publication timestamp for {cve_id}: {published_value}"
                ) from error

            if RESEARCH_START <= published < RESEARCH_END_EXCLUSIVE:
                previous = population.get(cve_id)

                if previous is not None and previous != published:
                    raise ValueError(
                        f"Conflicting publication timestamps for {cve_id}: "
                        f"{previous.isoformat()} and {published.isoformat()}"
                    )

                population[cve_id] = published

    return population


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the VESPER Component C research population."
    )
    parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=Path("data/raw/nvd"),
        help="Directory containing monthly NVD gzip snapshots.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/processed/c_graph/research_population.csv"),
        help="Output CSV path.",
    )
    args = parser.parse_args()

    if not args.snapshot_dir.is_dir():
        parser.error(f"Snapshot directory does not exist: {args.snapshot_dir}")

    population = build_population(args.snapshot_dir)

    if not population:
        parser.error("No CVEs found within the research interval.")

    args.output.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = args.output.with_suffix(args.output.suffix + ".tmp")
    try:
        with temporary_path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["cve_id", "published"])

            for cve_id, published in sorted(population.items()):
                writer.writerow([cve_id, published.isoformat()])

        temporary_path.replace(args.output)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    print(f"Research start (UTC): {RESEARCH_START.isoformat()}")
    print(f"Research end (exclusive, UTC): {RESEARCH_END_EXCLUSIVE.isoformat()}")
    print(f"Unique CVEs: {len(population)}")
    print(f"Output: {args.output}")


if __name__ == "__main__":
    main()
