"""Build graph features from multiple reconstructed NVD history files."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vesper.components.c_graph.historical import (
    build_multi_cve_historical_graph,
    reconstruct_relationships,
    validate_history_response,
)
from vesper.components.c_graph.scoring import calculate_graph_features

RESEARCH_START = datetime(2016, 1, 1, tzinfo=UTC)
RESEARCH_END_EXCLUSIVE = datetime(2026, 10, 15, tzinfo=UTC)
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
DEFAULT_MANIFEST = Path("data/processed/c_graph/research_population.csv")


def _parse_timestamp(value: Any) -> datetime:
    """Parse a timestamp and normalize it to UTC."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty string")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def load_research_manifest(path: Path) -> dict[str, datetime]:
    """Load and strictly validate the publication-filtered research manifest."""
    population: dict[str, datetime] = {}
    with Path(path).open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file)
        try:
            headers = next(reader)
        except StopIteration as error:
            raise ValueError(f"Research manifest is empty: {path}") from error

        required = {"cve_id", "published"}
        if len(headers) != len(set(headers)) or not required.issubset(headers):
            raise ValueError("Research manifest must have unique cve_id and published columns")
        cve_index = headers.index("cve_id")
        published_index = headers.index("published")

        for line_number, row in enumerate(reader, start=2):
            if len(row) != len(headers):
                raise ValueError(f"Malformed research manifest row {line_number}")
            cve_id = row[cve_index].strip()
            if not CVE_ID_PATTERN.fullmatch(cve_id):
                raise ValueError(
                    f"Invalid CVE ID in research manifest row {line_number}: {cve_id!r}"
                )
            try:
                published = _parse_timestamp(row[published_index])
            except ValueError as error:
                raise ValueError(
                    f"Invalid publication timestamp in manifest row {line_number}: "
                    f"{row[published_index]!r}"
                ) from error
            if not RESEARCH_START <= published < RESEARCH_END_EXCLUSIVE:
                raise ValueError(f"Publication timestamp outside research interval for {cve_id}")
            if cve_id in population:
                raise ValueError(f"Duplicate CVE in research manifest: {cve_id}")
            population[cve_id] = published

    if not population:
        raise ValueError("Research manifest contains no target CVEs")
    return population


def _validate_history_response(history: Any, expected_cve_id: str) -> int:
    """Validate a complete aggregated NVD history response before reconstruction."""
    return validate_history_response(history, expected_cve_id)


def _write_json_atomically(path: Path, data: dict[str, Any]) -> None:
    """Write JSON metadata safely using a temporary file."""
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


def run_multi_historical_pipeline(
    history_dir: Path,
    output_path: Path,
    snapshot_at: datetime,
    limit: int | None = None,
    manifest_path: Path = DEFAULT_MANIFEST,
) -> dict[str, Any]:
    """Build population-filtered graph features and auditable coverage outputs."""
    history_dir = Path(history_dir)
    output_path = Path(output_path)
    manifest_path = Path(manifest_path)

    if snapshot_at.tzinfo is None:
        raise ValueError("snapshot_at must be timezone-aware")

    if limit is not None and limit < 1:
        raise ValueError("limit must be at least 1")

    if not history_dir.is_dir():
        raise NotADirectoryError(f"History directory not found: {history_dir}")

    snapshot_at = snapshot_at.astimezone(UTC)
    population = load_research_manifest(manifest_path)
    not_yet_published_ids = {
        cve_id for cve_id, published_at in population.items() if published_at > snapshot_at
    }
    eligible_population_ids = set(population) - not_yet_published_ids
    history_files = sorted(history_dir.glob("CVE-*.json"))
    files_by_id = {path.stem: path for path in history_files if CVE_ID_PATTERN.fullmatch(path.stem)}
    invalid_filenames = [
        str(path) for path in history_files if not CVE_ID_PATTERN.fullmatch(path.stem)
    ]
    target_file_ids = set(files_by_id).intersection(eligible_population_ids)
    missing_ids = eligible_population_ids.difference(files_by_id)
    outside_population = [
        str(path)
        for path in history_files
        if CVE_ID_PATTERN.fullmatch(path.stem) and path.stem not in population
    ]

    files_to_process = [files_by_id[cve_id] for cve_id in sorted(target_file_ids)]
    processing_files = files_to_process[:limit] if limit is not None else files_to_process
    processed_ids = {path.stem for path in processing_files}

    relationships_list = []
    errors: list[dict[str, str]] = []
    invalid_files: list[dict[str, str]] = []
    reconstruction_failures: list[dict[str, str]] = []
    cve_reconstruction_warnings = []
    valid_responses = 0
    valid_empty_responses = 0
    responses_with_events = 0
    processing_exclusions: dict[str, str] = {}

    for history_path in processing_files:
        cve_id = history_path.stem
        try:
            with history_path.open("r", encoding="utf-8") as file:
                history = json.load(file)
            event_count = _validate_history_response(history, cve_id)
            valid_responses += 1
            if event_count == 0:
                valid_empty_responses += 1
            else:
                responses_with_events += 1
        except (OSError, json.JSONDecodeError, ValueError) as error:
            invalid_files.append(
                {"cve_id": cve_id, "history_file": str(history_path), "error": str(error)}
            )
            errors.append({"history_file": str(history_path), "error": str(error)})
            processing_exclusions[cve_id] = "invalid_history_response"
            continue

        try:
            relationships = reconstruct_relationships(
                history,
                snapshot_at,
                cve_id=cve_id,
            )
        except (ValueError, TypeError, KeyError) as error:
            reconstruction_failures.append(
                {"cve_id": cve_id, "history_file": str(history_path), "error": str(error)}
            )
            errors.append({"history_file": str(history_path), "error": str(error)})
            processing_exclusions[cve_id] = "reconstruction_failed"
            continue

        relationships_list.append(relationships)
        if not relationships.feature_eligible:
            processing_exclusions[cve_id] = ";".join(relationships.exclusion_reasons)
        if relationships.warnings:
            cve_reconstruction_warnings.append(
                {"cve_id": relationships.cve_id, "warnings": list(relationships.warnings)}
            )

    graph = build_multi_cve_historical_graph(relationships_list)
    features = calculate_graph_features(graph)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_suffix(output_path.suffix + ".tmp")

    try:
        features.to_csv(temporary_path, index=False)
        temporary_path.replace(output_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    exclusions_path = output_path.with_suffix(".exclusions.csv")
    exclusions_temp = exclusions_path.with_suffix(exclusions_path.suffix + ".tmp")
    exclusion_counts: dict[str, int] = {}
    try:
        with exclusions_temp.open("w", encoding="utf-8", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["cve_id", "reason"])
            for cve_id in sorted(population):
                reason = processing_exclusions.get(cve_id)
                if cve_id in not_yet_published_ids:
                    reason = "not_yet_published_at_cutoff"
                elif reason is None and cve_id not in files_by_id:
                    reason = "missing_history"
                elif reason is None and cve_id not in processed_ids:
                    reason = "not_processed_limit" if limit is not None else "not_processed"
                if reason is not None:
                    writer.writerow([cve_id, reason])
                    exclusion_counts[reason] = exclusion_counts.get(reason, 0) + 1
        exclusions_temp.replace(exclusions_path)
    finally:
        if exclusions_temp.exists():
            exclusions_temp.unlink()

    graph_summary = {
        node_type: sum(
            1 for _, data in graph.nodes(data=True) if data.get("node_type") == node_type
        )
        for node_type in ("vendor", "product", "cve", "cwe")
    }

    metadata = {
        "snapshot_at": snapshot_at.isoformat(),
        "research_start_utc": RESEARCH_START.isoformat(),
        "research_end_exclusive_utc": RESEARCH_END_EXCLUSIVE.isoformat(),
        "manifest_path": str(manifest_path),
        "target_population_size": len(population),
        "eligible_population_size": len(eligible_population_ids),
        "target_cves_not_yet_published_at_cutoff": len(not_yet_published_ids),
        "processing_limit": limit,
        "history_files_selected_for_processing": len(processing_files),
        "coverage_metric_definitions": {
            "target_cves_with_local_history_files": (
                "Cutoff-eligible target CVE IDs whose matching local JSON path exists, "
                "regardless of whether its contents validate."
            ),
            "valid_history_responses": (
                "Selected in-population files with a complete NVD history response "
                "envelope and matching CVE identities."
            ),
            "valid_empty_responses": "Valid responses with totalResults equal to zero.",
            "responses_with_recorded_events": ("Valid responses with one or more change events."),
            "successfully_reconstructed_cves": (
                "Valid responses for which relationship reconstruction completed."
            ),
            "feature_eligible_cves": (
                "Reconstructed CVEs with interpretable CPE and CWE event streams whose "
                "first relevant event establishes a known state, with no unsupported "
                "affected relationship event or incomplete change values by the cutoff."
            ),
            "cves_in_feature_dataset": (
                "Unique CVE rows emitted by the scorer over the reconstructed graph."
            ),
            "target_cves_missing_local_history": (
                "Manifest CVEs with no matching local JSON path."
            ),
        },
        "target_cves_with_local_history_files": len(target_file_ids),
        "target_cves_missing_local_history": len(missing_ids),
        "valid_history_responses": valid_responses,
        "valid_empty_responses": valid_empty_responses,
        "responses_with_recorded_events": responses_with_events,
        "invalid_history_files": len(invalid_files),
        "invalid_files": invalid_files,
        "reconstruction_failures": len(reconstruction_failures),
        "reconstruction_failure_details": reconstruction_failures,
        "successfully_reconstructed_cves": len(relationships_list),
        "feature_eligible_cves": sum(
            relationships.feature_eligible for relationships in relationships_list
        ),
        "cves_in_feature_dataset": len(features),
        "feature_graph_scope": (
            "All vendor, product, CVE, and CWE nodes reconstructed from successfully "
            "processed target history files at snapshot_at. Statistics are global to "
            "this graph and its available-history subset."
        ),
        "history_files_outside_population": len(outside_population),
        "out_of_population_history_files": outside_population,
        "invalid_history_filenames": invalid_filenames,
        "exclusions_csv": str(exclusions_path),
        "exclusion_counts": exclusion_counts,
        "history_directory": str(history_dir),
        "history_files_found": len(history_files),
        "history_files_reconstructed": len(relationships_list),
        "history_files_failed": len(invalid_files) + len(reconstruction_failures),
        "errors": errors,
        "history_complete": False,
        "historical_completeness_note": (
            "NVD history alone does not prove that every original or historical "
            "relationship is represented. Features describe this reconstructed "
            "sample, not a proven complete historical graph."
        ),
        "cves_with_reconstruction_warnings": len(cve_reconstruction_warnings),
        "cve_reconstruction_warnings": cve_reconstruction_warnings,
        "graph_nodes": graph.number_of_nodes(),
        "graph_edges": graph.number_of_edges(),
        "graph_summary": graph_summary,
        "feature_rows": len(features),
        "output_csv": str(output_path),
        "generated_at_utc": datetime.now(UTC).isoformat(),
    }

    metadata_path = output_path.with_suffix(".metadata.json")
    _write_json_atomically(metadata_path, metadata)

    return metadata


def main() -> None:
    """Run multi-CVE historical feature export from the command line."""
    parser = argparse.ArgumentParser(
        description="Export Component C features from multiple NVD history files."
    )
    parser.add_argument(
        "--history-dir",
        type=Path,
        required=True,
        help="Directory containing CVE history JSON files.",
    )
    parser.add_argument(
        "--snapshot-at",
        required=True,
        help="Historical cutoff timestamp, for example 2025-01-01T00:00:00Z.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="Validated publication-filtered research_population.csv.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("outputs/c_graph_multi_historical_features.csv"),
        help="Output CSV path.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional maximum number of history files to process.",
    )

    args = parser.parse_args()
    normalized = args.snapshot_at.strip()

    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        snapshot_at = datetime.fromisoformat(normalized)
    except ValueError as error:
        parser.error(f"Invalid --snapshot-at timestamp: {error}")

    if snapshot_at.tzinfo is None:
        parser.error("--snapshot-at must include a timezone, such as Z or +00:00")

    try:
        metadata = run_multi_historical_pipeline(
            history_dir=args.history_dir,
            output_path=args.output,
            snapshot_at=snapshot_at,
            limit=args.limit,
            manifest_path=args.manifest,
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
