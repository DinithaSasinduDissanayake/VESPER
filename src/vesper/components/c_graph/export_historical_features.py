
"""Export graph features from explicitly reconstructed NVD history."""

import argparse
import gzip
import json
from collections import Counter
from datetime import date, datetime
from pathlib import Path
from typing import Any

from vesper.components.c_graph.graph import KnowledgeGraph
from vesper.components.c_graph.history_reconstruction import (
    reconstruct_relationships,
)
from vesper.components.c_graph.scoring import calculate_cve_features
from vesper.contracts.vulnerability import Vulnerability


def load_history_file(path: Path) -> dict[str, Any]:
    """Load and validate a saved NVD CVE history API response."""
    with path.open("r", encoding="utf-8") as file:
        history = json.load(file)

    if not isinstance(history, dict):
        raise ValueError(
            f"Invalid history response in {path}: expected a JSON object"
        )

    if "cveChanges" not in history:
        raise ValueError(
            f"Invalid history response in {path}: missing cveChanges"
        )

    if not isinstance(history["cveChanges"], list):
        raise ValueError(
            f"Invalid history response in {path}: cveChanges must be a list"
        )

    return history


def export_historical_features(
    input_path: Path,
    history_dir: Path,
    output_path: Path,
    snapshot_date: date,
) -> None:
    """Export graph features using saved NVD history responses.

    History files must be named <CVE-ID>.json in history_dir.

    The export stops before writing output if history is missing, malformed,
    structurally invalid, or insufficient to reconstruct relationships.
    """
    with gzip.open(input_path, "rt", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Invalid NVD input: expected a JSON object")

    records = data.get("vulnerabilities")

    if not isinstance(records, list):
        raise ValueError(
            "Invalid NVD input: vulnerabilities must be a list"
        )

    graph = KnowledgeGraph()
    missing_history: list[str] = []
    unresolved_relationships: list[str] = []
    evidence_counts: Counter[str] = Counter()

    for record in records:
        if not isinstance(record, dict) or not isinstance(
            record.get("cve"), dict
        ):
            raise ValueError(
                "Invalid NVD input: each record must contain a cve object"
            )

        cve_id = record["cve"].get("id")

        if not isinstance(cve_id, str) or not cve_id:
            raise ValueError("Invalid NVD input: a record has no CVE ID")

        history_path = history_dir / f"{cve_id}.json"

        if not history_path.is_file():
            missing_history.append(cve_id)
            continue

        try:
            history = load_history_file(history_path)
        except json.JSONDecodeError:
            # Preserve the JSON parsing exception for existing callers/tests.
            raise
        except (ValueError, OSError) as exc:
            raise ValueError(
                f"Invalid history for {cve_id} at {history_path}: {exc}"
            ) from exc

        reconstructed = reconstruct_relationships(
            cve_id,
            history,
            snapshot_date,
        )

        if not reconstructed.cwe_ids and not reconstructed.affected:
            unresolved_relationships.append(cve_id)
            continue

        evidence_counts["records_with_relationships"] += 1
        evidence_counts["evidence_events"] += reconstructed.evidence_events

        vulnerability = _make_relationship_only_vulnerability(
            record,
            reconstructed.cwe_ids,
            reconstructed.affected,
            snapshot_date,
        )
        graph.add_vulnerability(vulnerability)

    print(f"Records in source: {len(records)}")
    print(
        "Records with reconstructed relationships: "
        f"{evidence_counts['records_with_relationships']}"
    )
    print(
        "Relationship evidence events: "
        f"{evidence_counts['evidence_events']}"
    )
    print(f"Records with missing history files: {len(missing_history)}")
    print(
        "Records with unresolved relationships: "
        f"{len(unresolved_relationships)}"
    )

    if missing_history or unresolved_relationships:
        examples = (missing_history + unresolved_relationships)[:5]

        raise ValueError(
            "Historical export stopped because relationship coverage is "
            "incomplete. No output was written. "
            f"Missing histories: {len(missing_history)}; "
            f"unresolved relationships: {len(unresolved_relationships)}. "
            f"Examples: {examples}"
        )

    features = calculate_cve_features(graph)

    # Write to a temporary file and replace the output only after success.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_suffix(
        output_path.suffix + ".tmp"
    )

    try:
        features.to_csv(temporary_path, index=False)
        temporary_path.replace(output_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    print(f"Graph nodes: {len(graph.nodes)}")
    print(f"Graph edges: {len(graph.edges)}")
    print(f"Feature rows: {len(features)}")
    print(f"Output: {output_path}")


def _make_relationship_only_vulnerability(
    record: dict[str, Any],
    cwe_ids: tuple[str, ...],
    affected: tuple[tuple[str, str], ...],
    snapshot_date: date,
) -> Vulnerability:
    """Build a vulnerability using only reconstructed historical relationships.

    Current CVSS, description, and status are intentionally excluded because
    this exporter does not reconstruct their historical values.
    """
    cve = record["cve"]

    published_value = cve.get("published")

    if not isinstance(published_value, str):
        raise ValueError(
            f"Invalid NVD record for {cve.get('id')}: missing published date"
        )

    try:
        published_at = datetime.fromisoformat(
            published_value.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError(
            f"Invalid published date for {cve.get('id')}: "
            f"{published_value}"
        ) from exc

    return Vulnerability(
        cve_id=cve["id"],
        published_at=published_at,
        last_modified_at=published_at,
        description="",
        cvss_base_score=None,
        cvss_version=None,
        cvss_vector=None,
        cwe_ids=cwe_ids,
        affected=affected,
        nvd_status="Unknown",
        snapshot_date=snapshot_date,
    )


def main() -> None:
    """Run historical graph feature export from saved NVD histories."""
    parser = argparse.ArgumentParser(
        description=(
            "Export graph features from saved NVD change histories."
        )
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--history-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--snapshot-date",
        type=date.fromisoformat,
        required=True,
    )

    args = parser.parse_args()

    export_historical_features(
        input_path=args.input,
        history_dir=args.history_dir,
        output_path=args.output,
        snapshot_date=args.snapshot_date,
    )


if __name__ == "__main__":
    main()
