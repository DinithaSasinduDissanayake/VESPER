"""Summarize dated NVD history evidence across the Component C population."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import download_nvd_history as downloader  # noqa: E402

from vesper.components.c_graph.layered_historical import (  # noqa: E402
    reconstruct_relationship_layers,
)
from vesper.components.c_graph.multi_historical_pipeline import load_research_manifest  # noqa: E402

DEFAULT_MANIFEST = PROJECT_ROOT / "data/processed/c_graph/research_population.csv"
DEFAULT_HISTORY_DIRS = (
    PROJECT_ROOT / "data/raw/nvd/history",
    PROJECT_ROOT / "outputs/c_graph_probability_pilot_2026-10-16/histories",
    PROJECT_ROOT / "outputs/c_graph_history_expansion_pilot_2026-10-16_run2/histories",
)
DEFAULT_OUTPUT = PROJECT_ROOT / "outputs/c_graph_full_population_history_coverage_2026-10-16"
CUTOFFS = tuple(datetime(year, 1, 1, tzinfo=UTC) for year in range(2022, 2027))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_coverage_report(
    manifest_path: Path = DEFAULT_MANIFEST,
    history_dirs: tuple[Path, ...] = DEFAULT_HISTORY_DIRS,
    output_dir: Path = DEFAULT_OUTPUT,
    cutoffs: tuple[datetime, ...] = CUTOFFS,
) -> dict[str, Any]:
    """Write cutoff/layer coverage using only local manifest and history files."""
    if output_dir.exists():
        raise FileExistsError(f"Coverage output already exists: {output_dir}")
    started = time.monotonic()
    population = load_research_manifest(manifest_path)
    histories: dict[str, Path] = {}
    duplicate_ids: list[str] = []
    for history_dir in history_dirs:
        for path in sorted(history_dir.glob("*.json")):
            if not path.stem.startswith("CVE-"):
                continue
            if path.stem not in population:
                continue
            if path.stem in histories:
                duplicate_ids.append(path.stem)
            else:
                histories[path.stem] = path

    all_result_rows: list[dict[str, Any]] = []
    per_cutoff: dict[str, Any] = {}
    for cutoff in cutoffs:
        cutoff = cutoff.astimezone(UTC)
        published = {cve for cve, date in population.items() if date <= cutoff}
        future = len(population) - len(published)
        available_ids = published.intersection(histories)
        valid_histories: dict[str, dict[str, Any]] = {}
        dispositions: Counter[str] = Counter()
        invalid_reasons: dict[str, str] = {}
        for cve_id in sorted(available_ids):
            path = histories[cve_id]
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                event_count = downloader._validate_aggregated_history(payload, cve_id)
                valid_histories[cve_id] = payload
                dispositions[
                    "valid_empty_history" if event_count == 0 else "valid_history_with_events"
                ] += 1
            except (OSError, json.JSONDecodeError, ValueError) as error:
                invalid_reasons[cve_id] = f"{type(error).__name__}: {error}"
                dispositions["invalid_history"] += 1

        cutoff_results: dict[str, Any] = {
            "population_cves": len(population),
            "published_by_cutoff_cves": len(published),
            "future_published_cves": future,
            "history_file_cves_published_by_cutoff": len(available_ids),
            "missing_history_cves": len(published - available_ids),
            "invalid_history_cves": len(invalid_reasons),
            "valid_empty_history_cves": dispositions["valid_empty_history"],
            "valid_histories_with_events_cves": dispositions["valid_history_with_events"],
            "layers": {},
        }
        for layer in ("cpe", "cwe"):
            layer_records = []
            missing_layer_ids = published - available_ids
            for cve_id, history in valid_histories.items():
                layer_records.append(
                    reconstruct_relationship_layers(history, cutoff, cve_id)[layer]
                )
            supported = [record for record in layer_records if record.eligible]
            known_empty = [record for record in supported if not record.relationships]
            feature_eligible = [record for record in supported if record.relationships]
            evidence_reasons = Counter(
                reason
                for record in layer_records
                if not record.eligible
                for reason in record.exclusion_reasons
            )
            layer_counts = {
                "usable_dated_relationship_evidence_cves": len(feature_eligible),
                "supported_layer_state_cves_including_known_empty": len(supported),
                "known_empty_relationship_cves": len(known_empty),
                "unavailable_or_unsupported_history_evidence_cves": len(layer_records)
                - len(supported),
                "missing_histories_cves": len(missing_layer_ids),
                "invalid_histories_cves": len(invalid_reasons),
                "valid_empty_histories_cves": dispositions["valid_empty_history"],
                "history_evidence_exclusion_reason_counts_overlapping": dict(
                    sorted(evidence_reasons.items())
                ),
            }
            cutoff_results["layers"][layer] = layer_counts
            all_result_rows.append(
                {
                    "cutoff_utc": cutoff.isoformat(),
                    "layer": layer,
                    "population_cves": len(population),
                    "published_by_cutoff_cves": len(published),
                    "future_published_cves": future,
                    "history_file_cves_published_by_cutoff": len(available_ids),
                    "missing_history_cves": len(published - available_ids),
                    "invalid_history_cves": len(invalid_reasons),
                    "valid_empty_history_cves": dispositions["valid_empty_history"],
                    "valid_histories_with_events_cves": dispositions["valid_history_with_events"],
                    **layer_counts,
                }
            )
        per_cutoff[cutoff.isoformat()] = cutoff_results

    output_dir.mkdir(parents=True, exist_ok=False)
    csv_path = output_dir / "coverage_by_cutoff.csv"
    with csv_path.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(all_result_rows[0]))
        writer.writeheader()
        writer.writerows(all_result_rows)

    metadata = {
        "analysis_type": "offline_full_population_history_evidence_coverage",
        "population_cves": len(population),
        "manifest_path": str(manifest_path),
        "manifest_sha256": _sha256(manifest_path),
        "history_sources": [str(path) for path in history_dirs],
        "unique_manifest_history_files": len(histories),
        "duplicate_history_ids_across_sources": sorted(set(duplicate_ids)),
        "history_file_hashes": {
            cve_id: _sha256(path) for cve_id, path in sorted(histories.items())
        },
        "cutoff_results": per_cutoff,
        "current_monthly_nvd_snapshots_used_for_historical_states": False,
        "event_timestamps_prove_public_availability": False,
        "independent_historical_cpe_validation": False,
        "cpe_applicability_scope": (
            "Vendor/product relationship abstraction only; not complete CPE configuration history."
        ),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "coverage_csv": csv_path.name,
    }
    (output_dir / "coverage_metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# Component C full-population historical evidence coverage",
        "",
        (
            "Offline audit over the unchanged manifest and saved local NVD histories. "
            "This is not a population-wide reconstructed graph or predictive evaluation."
        ),
        "",
        (
            "Monthly NVD files are current-record publication-month partitions, not historical "
            "record versions; they were not used as cutoff relationship states. Recorded history "
            "event times are an event-time proxy and do not prove public availability at that time."
        ),
        "",
        (
            "| Cutoff | Published | Future | Histories available | Missing histories | "
            "CPE usable dated evidence | CPE known-empty | CWE usable dated evidence | "
            "CWE known-empty |"
        ),
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for cutoff, item in per_cutoff.items():
        lines.append(
            f"| {cutoff[:10]} | {item['published_by_cutoff_cves']:,} "
            f"| {item['future_published_cves']:,} | "
            f"{item['history_file_cves_published_by_cutoff']:,} "
            f"| {item['missing_history_cves']:,} | "
            f"{item['layers']['cpe']['usable_dated_relationship_evidence_cves']:,} | "
            f"{item['layers']['cpe']['known_empty_relationship_cves']:,} | "
            f"{item['layers']['cwe']['usable_dated_relationship_evidence_cves']:,} | "
            f"{item['layers']['cwe']['known_empty_relationship_cves']:,} |"
        )
    lines.extend(
        [
            "",
            f"Distinct local history files matched to the manifest: {len(histories):,}.",
            f"Output records: `{csv_path.name}` and `{output_dir / 'coverage_metadata.json'}`.",
            (
                "Usable dated evidence counts evidence-eligible CVEs with at least one active "
                "relationship after cutoff replay. Known-empty states are separate; reason "
                "counts can overlap."
            ),
            "",
            (
                "This report does not claim complete history, independently validated CPE "
                "applicability, or decision-maker availability of NVD changes."
            ),
        ]
    )
    (output_dir / "coverage_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--history-dir", type=Path, action="append", dest="history_dirs")
    args = parser.parse_args()
    dirs = tuple(args.history_dirs) if args.history_dirs else DEFAULT_HISTORY_DIRS
    result = run_coverage_report(args.manifest, dirs, args.output_dir)
    print(
        json.dumps(
            {"output_dir": str(args.output_dir), "cutoffs": result["cutoff_results"]}, indent=2
        )
    )


if __name__ == "__main__":
    main()
