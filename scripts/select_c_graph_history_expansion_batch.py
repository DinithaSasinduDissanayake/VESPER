"""Select an offline, deterministic batch for incremental Component C history retrieval."""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vesper.components.c_graph.historical import validate_history_response

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_c_graph_history_expansion_pilot import DurableRequestBudget  # noqa: E402

DEFAULT_MANIFEST = Path("data/processed/c_graph/research_population.csv")
DEFAULT_OUTPUT = Path("outputs/c_graph_history_evidence_expansion_2026-10-17_run3")
DEFAULT_HISTORY_DIRS = (
    Path("data/raw/nvd/history"),
    Path("outputs/c_graph_historical_pilot_2026-10-16/histories"),
    Path("outputs/c_graph_probability_pilot_2026-10-16/histories"),
    Path("outputs/c_graph_history_expansion_pilot_2026-10-16/histories"),
    Path("outputs/c_graph_history_expansion_pilot_2026-10-16_run2/histories"),
    Path("outputs/c_graph_history_evidence_expansion_2026-10-17_run1/histories"),
    Path("outputs/c_graph_history_evidence_expansion_2026-10-17_run2/histories"),
    Path("outputs/c_graph_smoke_2026-10-15/history"),
    Path("outputs/c_graph_independent_history_pilot_2026-10-16/histories"),
)
SEED = "VESPER-C-history-evidence-expansion-20-2026-10-17"
CUTOFFS = tuple(datetime(year, 1, 1, tzinfo=UTC) for year in range(2022, 2027))
SAMPLE_PER_YEAR = 2


def _parse_utc(value: str) -> datetime:
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError(f"Timestamp has no timezone: {value!r}")
    return parsed.astimezone(UTC)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _valid_history_ids(
    manifest_ids: set[str], history_dirs: tuple[Path, ...]
) -> tuple[set[str], dict[str, list[str]]]:
    valid_ids: set[str] = set()
    files_by_id: dict[str, list[str]] = defaultdict(list)
    for directory in history_dirs:
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.json")):
            if path.stem not in manifest_ids:
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                validate_history_response(payload, path.stem)
            except (OSError, json.JSONDecodeError, ValueError):
                continue
            valid_ids.add(path.stem)
            files_by_id[path.stem].append(str(path))
    return valid_ids, files_by_id


def select_batch(
    *,
    manifest_path: Path,
    history_dirs: tuple[Path, ...],
    output_dir: Path,
    seed: str = SEED,
    sample_per_year: int = SAMPLE_PER_YEAR,
    request_ceiling: int = 60,
) -> dict[str, Any]:
    """Persist selected IDs and all request inputs before any collection begins."""
    if output_dir.exists():
        raise FileExistsError(f"Refusing to overwrite existing batch directory: {output_dir}")
    if sample_per_year < 1:
        raise ValueError("sample_per_year must be positive")
    if request_ceiling < 1:
        raise ValueError("request_ceiling must be positive")

    with manifest_path.open(encoding="utf-8-sig", newline="") as source:
        rows = list(csv.DictReader(source))
    required = {"cve_id", "published"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError("Research manifest must contain cve_id and published columns")
    ids = [row["cve_id"].strip().upper() for row in rows]
    if any(not cve_id for cve_id in ids) or len(ids) != len(set(ids)):
        raise ValueError("Research manifest CVE IDs must be present and unique")
    for row, cve_id in zip(rows, ids, strict=True):
        row["cve_id"] = cve_id
        row["published_dt"] = _parse_utc(row["published"])
    manifest_ids = set(ids)
    valid_history_ids, valid_files = _valid_history_ids(manifest_ids, history_dirs)

    candidates_by_year: dict[int, list[dict[str, Any]]] = defaultdict(list)
    year_population_counts: Counter[int] = Counter()
    year_missing_history_counts: Counter[int] = Counter()
    for row in rows:
        published = row["published_dt"]
        if published.year < 2016 or published.year > 2025:
            continue
        year_population_counts[published.year] += 1
        if row["cve_id"] in valid_history_ids:
            continue
        year_missing_history_counts[published.year] += 1
        cutoff_opportunities = sum(published <= cutoff for cutoff in CUTOFFS)
        selection_stratum = f"{published.year}|{cutoff_opportunities}_cutoffs"
        order_hash = hashlib.sha256(f"{seed}|{row['cve_id']}".encode()).hexdigest()
        prior_files = [
            str(directory / f"{row['cve_id']}.json")
            for directory in history_dirs
            if (directory / f"{row['cve_id']}.json").is_file()
        ]
        candidates_by_year[published.year].append(
            {
                "cve_id": row["cve_id"],
                "published": row["published"],
                "publication_year_stratum": str(published.year),
                "cutoff_opportunity_stratum": selection_stratum,
                "cutoffs_eligible_by_publication": cutoff_opportunities,
                "existing_cpe_cwe_history_status": "unknown_no_valid_local_history",
                "prior_invalid_history_files_preserved": json.dumps(prior_files),
                "selection_hash": order_hash,
                "selection_reason": (
                    "No valid local NVD history exists; adding history may support one or more "
                    "cutoff-specific CPE/CWE reconstructions."
                ),
            }
        )

    selected: list[dict[str, Any]] = []
    for year in range(2016, 2026):
        candidates = sorted(
            candidates_by_year[year], key=lambda item: (item["selection_hash"], item["cve_id"])
        )
        if len(candidates) < sample_per_year:
            raise ValueError(f"Year {year} has only {len(candidates)} eligible missing histories")
        selected.extend(candidates[:sample_per_year])
    selected.sort(key=lambda item: (int(item["publication_year_stratum"]), item["cve_id"]))
    selected_ids = [item["cve_id"] for item in selected]
    if len(selected_ids) != len(set(selected_ids)) or not set(selected_ids).issubset(manifest_ids):
        raise ValueError("Selected IDs must be distinct members of the research manifest")
    if set(selected_ids) & valid_history_ids:
        raise ValueError("Selection unexpectedly includes a CVE with a valid local history")

    output_dir.mkdir(parents=True, exist_ok=False)
    input_dir = output_dir / "request_input"
    input_dir.mkdir()
    (output_dir / "histories").mkdir()
    (output_dir / "request_metadata").mkdir()
    budget = DurableRequestBudget(
        output_dir / "request_reservations.sqlite3", maximum=request_ceiling
    )
    budget.close()
    request_input = input_dir / "selected_nvd_ids.json.gz"
    with gzip.open(request_input, "wt", encoding="utf-8", newline="") as destination:
        json.dump(
            {
                "vulnerabilities": [
                    {"cve": {"id": item["cve_id"], "published": item["published"]}}
                    for item in selected
                ]
            },
            destination,
            separators=(",", ":"),
        )

    selection_path = output_dir / "selection_manifest.csv"
    fields = list(selected[0])
    with selection_path.open("x", encoding="utf-8", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(selected)

    queue_path = output_dir / "request_queue.csv"
    with queue_path.open("x", encoding="utf-8", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=["cve_id", "stratum", "published"])
        writer.writeheader()
        writer.writerows(
            {
                "cve_id": item["cve_id"],
                "stratum": item["publication_year_stratum"],
                "published": item["published"],
            }
            for item in selected
        )

    metadata = {
        "analysis_type": "deterministic_stratified_historical_evidence_expansion_batch",
        "sample_is_probability_sample": False,
        "selection_method": (
            f"For each publication year 2016-2025, choose the {sample_per_year} smallest "
            "SHA-256 values of seed + CVE ID among manifest CVEs without any valid local history."
        ),
        "selection_seed": seed,
        "strata": "manifest publication year; cutoff opportunity count recorded per CVE",
        "per_year_allocation": sample_per_year,
        "sample_size": len(selected),
        "collection_started": False,
        "manifest_path": str(manifest_path),
        "manifest_sha256": _sha256(manifest_path),
        "manifest_rows": len(rows),
        "manifest_unique_ids": len(manifest_ids),
        "selected_cve_ids": selected_ids,
        "history_directories_checked": [str(path) for path in history_dirs],
        "valid_manifest_history_ids_before_selection": len(valid_history_ids),
        "valid_history_files_for_selected_ids": {
            cve_id: valid_files[cve_id] for cve_id in selected_ids if cve_id in valid_files
        },
        "year_population_counts_2016_2025": {
            str(year): year_population_counts[year] for year in range(2016, 2026)
        },
        "year_candidates_without_valid_history": {
            str(year): year_missing_history_counts[year] for year in range(2016, 2026)
        },
        "year_excluded_valid_history_counts": {
            str(year): year_population_counts[year] - year_missing_history_counts[year]
            for year in range(2016, 2026)
        },
        "manifest_rows_excluded_outside_2016_2025": len(rows)
        - sum(year_population_counts.values()),
        "cutoffs_utc": [cutoff.isoformat() for cutoff in CUTOFFS],
        "cutoff_opportunity_counts": dict(
            sorted(Counter(item["cutoffs_eligible_by_publication"] for item in selected).items())
        ),
        "selection_manifest": selection_path.name,
        "request_queue": queue_path.name,
        "selection_manifest_sha256": _sha256(selection_path),
        "request_input": str(request_input),
        "request_input_sha256": _sha256(request_input),
        "request_ceiling_including_retries": request_ceiling,
        "new_output_directory_only": True,
        "created_before_collection": True,
        "local_cpe_cwe_status_for_selected": (
            "unknown, not empty or unsupported, until retrieval and replay"
        ),
    }
    (output_dir / "selection_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--history-dir", type=Path, action="append", dest="history_dirs")
    parser.add_argument("--seed", default=SEED)
    parser.add_argument("--per-year", type=int, default=SAMPLE_PER_YEAR)
    parser.add_argument("--request-ceiling", type=int, default=60)
    args = parser.parse_args()
    result = select_batch(
        manifest_path=args.manifest,
        history_dirs=tuple(args.history_dirs) if args.history_dirs else DEFAULT_HISTORY_DIRS,
        output_dir=args.output_dir,
        seed=args.seed,
        sample_per_year=args.per_year,
        request_ceiling=args.request_ceiling,
    )
    print(
        json.dumps(
            {
                "output_dir": str(args.output_dir),
                "sample_size": result["sample_size"],
                "selection_manifest_sha256": result["selection_manifest_sha256"],
                "request_input_sha256": result["request_input_sha256"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
