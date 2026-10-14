
"""Build graph features from multiple reconstructed NVD history files."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any

from vesper.components.c_graph.historical import (
    build_multi_cve_historical_graph,
    reconstruct_relationships,
)
from vesper.components.c_graph.scoring import calculate_graph_features


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
) -> dict[str, Any]:
    """Build one shared historical graph from a directory of CVE histories."""
    history_dir = Path(history_dir)
    output_path = Path(output_path)

    if snapshot_at.tzinfo is None:
        raise ValueError("snapshot_at must be timezone-aware")

    if limit is not None and limit < 1:
        raise ValueError("limit must be at least 1")

    if not history_dir.is_dir():
        raise NotADirectoryError(f"History directory not found: {history_dir}")

    snapshot_at = snapshot_at.astimezone(timezone.utc)
    history_files = sorted(history_dir.glob("CVE-*.json"))

    if limit is not None:
        history_files = history_files[:limit]

    if not history_files:
        raise ValueError(f"No CVE history JSON files found in {history_dir}")

    relationships_list = []
    errors = []
    cve_reconstruction_warnings = []

    for history_path in history_files:
        try:
            with history_path.open("r", encoding="utf-8") as file:
                history = json.load(file)

            relationships = reconstruct_relationships(history, snapshot_at)
            relationships_list.append(relationships)

            if relationships.warnings:
                cve_reconstruction_warnings.append(
                    {
                        "cve_id": relationships.cve_id,
                        "warnings": list(relationships.warnings),
                    }
                )

        except (OSError, json.JSONDecodeError, ValueError) as error:
            errors.append(
                {
                    "history_file": str(history_path),
                    "error": str(error),
                }
            )

    if not relationships_list:
        raise ValueError(
            f"No valid history files could be reconstructed; errors: {errors}"
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

    graph_summary = {
        node_type: sum(
            1
            for _, data in graph.nodes(data=True)
            if data.get("node_type") == node_type
        )
        for node_type in ("vendor", "product", "cve", "cwe")
    }

    metadata = {
        "snapshot_at": snapshot_at.isoformat(),
        "history_directory": str(history_dir),
        "history_files_found": len(history_files),
        "history_files_reconstructed": len(relationships_list),
        "history_files_failed": len(errors),
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
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
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
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))

    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
