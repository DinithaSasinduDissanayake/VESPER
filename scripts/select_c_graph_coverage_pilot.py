"""Draw and materialize a probability sample for the Component C coverage pilot."""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import random
import secrets
import shutil
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = PROJECT_ROOT / "data/processed/c_graph/research_population.csv"
DEFAULT_HISTORY_DIR = PROJECT_ROOT / "data/raw/nvd/history"
DEFAULT_OUTPUT = PROJECT_ROOT / "outputs/c_graph_probability_pilot_2026-10-16"
SAMPLE_PER_STRATUM = 10
EXPECTED_POPULATION = 333_178
STRATA = [str(year) for year in range(2016, 2026)] + [
    "2026_pre_2026-06-17",
    "2026_2026-06-17_to_2026-08-25",
    "2026_from_2026-08-26",
]

sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
import download_nvd_history as downloader  # noqa: E402


def parse_publication(value: str) -> datetime:
    """Parse a manifest publication timestamp and normalize it to UTC."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"Publication timestamp lacks timezone: {value}")
    return parsed.astimezone(UTC)


def stratum_for(published: datetime) -> str:
    """Return the approved publication-date stratum for a manifest record."""
    if published.year < 2026:
        if published.year < 2016:
            raise ValueError(f"Publication outside research window: {published.isoformat()}")
        return str(published.year)
    if published < datetime(2026, 6, 17, tzinfo=UTC):
        return STRATA[10]
    if published < datetime(2026, 8, 26, tzinfo=UTC):
        return STRATA[11]
    if published < datetime(2026, 10, 15, tzinfo=UTC):
        return STRATA[12]
    raise ValueError(f"Publication outside research window: {published.isoformat()}")


def load_manifest(path: Path) -> list[dict[str, str]]:
    """Read and validate the unchanged research manifest."""
    with path.open(encoding="utf-8-sig", newline="") as file:
        rows = list(csv.DictReader(file))
    ids = [row.get("cve_id", "") for row in rows]
    if len(rows) != EXPECTED_POPULATION or len(set(ids)) != EXPECTED_POPULATION:
        raise ValueError(
            f"Expected {EXPECTED_POPULATION} unique manifest CVEs; found {len(rows)} rows"
        )
    for row in rows:
        published = parse_publication(row["published"])
        if not datetime(2016, 1, 1, tzinfo=UTC) <= published < datetime(2026, 10, 15, tzinfo=UTC):
            raise ValueError(f"Manifest CVE outside approved research window: {row['cve_id']}")
        row["stratum"] = stratum_for(published)
    return rows


def select_sample(
    rows: list[dict[str, str]], seed: int, sample_per_stratum: int = SAMPLE_PER_STRATUM
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Perform within-stratum simple random sampling without replacement."""
    by_stratum: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_stratum[row["stratum"]].append(row)
    rng = random.Random(seed)
    selected: list[dict[str, Any]] = []
    population_counts: dict[str, int] = {}
    for stratum in STRATA:
        members = sorted(by_stratum[stratum], key=lambda item: item["cve_id"])
        population_counts[stratum] = len(members)
        if len(members) < sample_per_stratum:
            raise ValueError(f"Stratum {stratum} has fewer than {sample_per_stratum} CVEs")
        pi = sample_per_stratum / len(members)
        for row in rng.sample(members, sample_per_stratum):
            selected.append(
                {
                    "cve_id": row["cve_id"],
                    "published": row["published"],
                    "stratum": stratum,
                    "stratum_population": len(members),
                    "stratum_sample": sample_per_stratum,
                    "inclusion_probability": pi,
                    "analysis_weight": 1.0 / pi,
                }
            )
    return selected, population_counts


def write_sample(
    manifest_path: Path,
    history_dir: Path,
    output_dir: Path,
    seed: int,
) -> dict[str, Any]:
    """Write immutable selection artifacts and copy only selected valid histories."""
    if output_dir.exists():
        raise FileExistsError(f"Pilot output directory already exists: {output_dir}")
    rows = load_manifest(manifest_path)
    sample, population_counts = select_sample(rows, seed)
    output_dir.mkdir(parents=True, exist_ok=False)
    histories_dir = output_dir / "histories"
    requests_dir = output_dir / "requests"
    histories_dir.mkdir()
    requests_dir.mkdir()

    dispositions: Counter[str] = Counter()
    request_records: list[dict[str, str]] = []
    for record in sample:
        cve_id = record["cve_id"]
        source = history_dir / f"{cve_id}.json"
        if not source.exists():
            status = "absent"
        elif downloader.load_saved_history(source) is None:
            status = "invalid_existing"
        else:
            status = "valid_existing"
            shutil.copy2(source, histories_dir / source.name)
        record["preexisting_history_status"] = status
        dispositions[status] += 1
        if status != "valid_existing":
            request_records.append(record)

    sample_path = output_dir / "sample_frame.csv"
    columns = [
        "cve_id",
        "published",
        "stratum",
        "stratum_population",
        "stratum_sample",
        "inclusion_probability",
        "analysis_weight",
        "preexisting_history_status",
    ]
    with sample_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(
            sorted(sample, key=lambda item: (STRATA.index(item["stratum"]), item["cve_id"]))
        )

    request_input = requests_dir / "pilot_nvd.json.gz"
    with gzip.open(request_input, "wt", encoding="utf-8") as file:
        json.dump(
            {
                "vulnerabilities": [
                    {"cve": {"id": row["cve_id"], "published": row["published"]}}
                    for row in request_records
                ]
            },
            file,
        )

    metadata = {
        "design": "stratified simple random sample without replacement",
        "seed": seed,
        "manifest_path": str(manifest_path),
        "manifest_rows": len(rows),
        "manifest_unique_cves": len({row["cve_id"] for row in rows}),
        "research_start_inclusive_utc": "2016-01-01T00:00:00+00:00",
        "research_end_exclusive_utc": "2026-10-15T00:00:00+00:00",
        "selection_stratum_basis": "NVD published timestamp; CVE identifier year is not used",
        "sample_per_stratum": SAMPLE_PER_STRATUM,
        "sample_size": len(sample),
        "stratum_population_counts": population_counts,
        "stratum_sample_counts": {stratum: SAMPLE_PER_STRATUM for stratum in STRATA},
        "selection_probabilities": {
            stratum: SAMPLE_PER_STRATUM / population_counts[stratum] for stratum in STRATA
        },
        "analysis_weights": {
            stratum: population_counts[stratum] / SAMPLE_PER_STRATUM for stratum in STRATA
        },
        "preexisting_history_dispositions": dict(dispositions),
        "valid_existing_histories_copied": dispositions["valid_existing"],
        "new_request_ids": len(request_records),
        "sample_frame_csv": str(sample_path),
        "request_input_gzip": str(request_input),
        "copied_history_dir": str(histories_dir),
        "created_before_collection": True,
    }
    metadata_path = output_dir / "selection_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--history-dir", type=Path, default=DEFAULT_HISTORY_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()
    seed = args.seed if args.seed is not None else secrets.randbits(64)
    print(
        json.dumps(write_sample(args.manifest, args.history_dir, args.output_dir, seed), indent=2)
    )


if __name__ == "__main__":
    main()
