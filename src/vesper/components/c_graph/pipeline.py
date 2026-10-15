"""Run the Component C NVD-to-graph-feature pipeline."""

import argparse
import gzip
import json
import os
import re
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from vesper.components.c_graph.export_features import export_features_to_csv
from vesper.components.c_graph.graph import build_graph, graph_summary
from vesper.components.c_graph.nvd_parser import parse_nvd_record
from vesper.config import load_settings

MONTH_FILE_PATTERN = re.compile(r"^nvd_(\d{4})-(\d{2})\.json\.gz$")


def discover_monthly_files(nvd_dir: Path) -> list[tuple[date, Path]]:
    """Find valid monthly NVD files and sort them chronologically."""
    nvd_dir = Path(nvd_dir)
    files: list[tuple[date, Path]] = []

    for path in nvd_dir.glob("nvd_*.json.gz"):
        match = MONTH_FILE_PATTERN.fullmatch(path.name)
        if not match:
            continue

        year, month = map(int, match.groups())

        try:
            month_date = date(year, month, 1)
        except ValueError:
            continue

        files.append((month_date, path))

    return sorted(files, key=lambda item: item[0])


def read_month(path: Path) -> list[dict[str, Any]]:
    """Read and validate one compressed NVD monthly dataset."""
    with gzip.open(path, "rt", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(f"{path} does not contain a valid JSON object")

    records = data.get("vulnerabilities")
    if not isinstance(records, list):
        raise ValueError(f"{path} does not contain a vulnerabilities list")

    return [record for record in records if isinstance(record, dict)]


def _write_json_atomically(path: Path, data: dict[str, Any]) -> None:
    """Write JSON to a temporary file and atomically replace the destination."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(path.suffix + ".tmp")

    try:
        with temporary_path.open("w", encoding="utf-8", newline="\n") as file:
            json.dump(data, file, indent=2, ensure_ascii=False)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())

        temporary_path.replace(path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def run_pipeline(
    nvd_dir: Path,
    output_path: Path,
    snapshot_date: date,
) -> dict[str, Any]:
    """Build and export graph features from local NVD monthly files.

    Records published after the snapshot date are excluded. Records modified
    after the snapshot date are excluded because their earlier state cannot
    be reconstructed by this pipeline.

    Records marked Rejected in the supplied NVD records are also excluded.
    This is the status in the downloaded record; it does not establish the
    record's status at every historical snapshot date.

    This is not historical reconstruction: the pipeline filters downloaded
    records rather than restoring their historical vendor/product/CWE values.
    """
    nvd_dir = Path(nvd_dir)
    output_path = Path(output_path)

    monthly_files = discover_monthly_files(nvd_dir)
    if not monthly_files:
        raise FileNotFoundError(f"No monthly NVD files found in {nvd_dir}")

    vulnerabilities = []
    skipped_after_cutoff = 0
    skipped_published_after_cutoff = 0
    skipped_rejected = 0
    seen_cves: set[str] = set()

    for _month_date, path in monthly_files:
        records = read_month(path)

        for record in records:
            cve = record.get("cve")
            if not isinstance(cve, dict):
                continue

            cve_id = cve.get("id")
            if not isinstance(cve_id, str) or not cve_id.strip():
                continue

            # Track every encountered CVE before cutoff checks. This prevents
            # duplicates from escaping detection when an earlier record is
            # excluded by the cutoff.
            if cve_id in seen_cves:
                raise ValueError(f"Duplicate CVE across input files: {cve_id}")
            seen_cves.add(cve_id)

            parsed = parse_nvd_record(record, snapshot_date)

            if parsed.published_at.date() > snapshot_date:
                skipped_published_after_cutoff += 1
                continue

            if parsed.last_modified_at.date() > snapshot_date:
                skipped_after_cutoff += 1
                continue

            # Exclude records marked Rejected in the supplied NVD record.
            if parsed.nvd_status.strip().casefold() == "rejected":
                skipped_rejected += 1
                continue

            vulnerabilities.append(parsed)

    graph = build_graph(vulnerabilities)
    export_features_to_csv(graph, output_path)

    metadata = {
        "snapshot_date": snapshot_date.isoformat(),
        "input_directory": str(nvd_dir),
        "monthly_files": [path.name for _, path in monthly_files],
        "monthly_file_count": len(monthly_files),
        "parsed_cve_count": len(vulnerabilities),
        "skipped_after_cutoff_count": skipped_after_cutoff,
        "skipped_published_after_cutoff_count": (skipped_published_after_cutoff),
        "skipped_rejected_count": skipped_rejected,
        "graph_summary": graph_summary(graph),
        "output_csv": str(output_path),
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "historical_reconstruction": "not_performed",
    }

    metadata_path = output_path.with_suffix(".metadata.json")
    _write_json_atomically(metadata_path, metadata)

    return metadata


def main() -> None:
    """Run the pipeline from the command line."""
    settings = load_settings()

    parser = argparse.ArgumentParser(
        description="Build Component C graph features from local NVD files."
    )
    parser.add_argument(
        "--nvd-dir",
        type=Path,
        default=settings.raw_source("nvd"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=settings.outputs / "c_graph_features.csv",
    )
    parser.add_argument(
        "--snapshot-date",
        type=date.fromisoformat,
        default=date.today(),
        help="Snapshot cutoff in YYYY-MM-DD format (default: today).",
    )
    args = parser.parse_args()

    metadata = run_pipeline(
        nvd_dir=args.nvd_dir,
        output_path=args.output,
        snapshot_date=args.snapshot_date,
    )

    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
