"""Build and export graph features from reconstructed NVD history."""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vesper.components.c_graph.historical import (
    build_historical_graph,
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


def run_historical_pipeline(
    history_path: Path,
    output_path: Path,
    snapshot_at: datetime,
) -> dict[str, Any]:
    """Reconstruct one CVE, calculate graph features, and export evidence."""
    history_path = Path(history_path)
    output_path = Path(output_path)

    if snapshot_at.tzinfo is None:
        raise ValueError("snapshot_at must be timezone-aware")

    snapshot_at = snapshot_at.astimezone(UTC)

    with history_path.open("r", encoding="utf-8") as file:
        history = json.load(file)

    if not isinstance(history, dict):
        raise ValueError("History file must contain a JSON object")

    relationships = reconstruct_relationships(history, snapshot_at)
    graph = build_historical_graph(relationships)
    features = calculate_graph_features(graph)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_suffix(output_path.suffix + ".tmp")

    try:
        features.to_csv(temporary_path, index=False)
        temporary_path.replace(output_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    metadata = {
        "cve_id": relationships.cve_id,
        "snapshot_at": snapshot_at.isoformat(),
        "history_file": str(history_path),
        "history_available": relationships.history_available,
        "history_complete": relationships.history_complete,
        "warnings": list(relationships.warnings),
        "reconstructed_affected": [
            {"vendor": vendor, "product": product} for vendor, product in relationships.affected
        ],
        "reconstructed_cwe_ids": list(relationships.cwe_ids),
        "graph_nodes": graph.number_of_nodes(),
        "graph_edges": graph.number_of_edges(),
        "feature_rows": len(features),
        "output_csv": str(output_path),
        "generated_at_utc": datetime.now(UTC).isoformat(),
    }

    metadata_path = output_path.with_suffix(".metadata.json")
    _write_json_atomically(metadata_path, metadata)

    return metadata


def main() -> None:
    """Run historical feature export from the command line."""
    parser = argparse.ArgumentParser(description="Export Component C features from NVD history.")
    parser.add_argument(
        "--history",
        type=Path,
        required=True,
        help="Path to one CVE history JSON file.",
    )
    parser.add_argument(
        "--snapshot-at",
        required=True,
        help="Historical cutoff timestamp, for example 2025-01-01T00:00:00Z.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("outputs/c_graph_historical_features.csv"),
        help="Output CSV path.",
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

    metadata = run_historical_pipeline(
        history_path=args.history,
        output_path=args.output,
        snapshot_at=snapshot_at,
    )
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
