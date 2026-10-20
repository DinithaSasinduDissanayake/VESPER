"""Run the offline exploratory CPE-only/CWE-only pilot graph comparison."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from vesper.components.c_graph.layered_historical import run_layer_comparison


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--history-dir",
        type=Path,
        default=Path("outputs/c_graph_probability_pilot_2026-10-16/histories"),
    )
    parser.add_argument(
        "--sample-frame",
        type=Path,
        default=Path("outputs/c_graph_probability_pilot_2026-10-16/sample_frame.csv"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("outputs/c_graph_layer_comparison_pilot_2026-10-16"),
    )
    parser.add_argument(
        "--snapshot-at",
        default="2026-10-14T23:59:59.999999+00:00",
        help="Timezone-aware historical cutoff.",
    )
    args = parser.parse_args()
    normalized = args.snapshot_at.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    snapshot_at = datetime.fromisoformat(normalized)
    if snapshot_at.tzinfo is None:
        parser.error("--snapshot-at must include a timezone")

    results = run_layer_comparison(
        args.history_dir, args.sample_frame, args.output_dir, snapshot_at.astimezone(UTC)
    )
    for layer, metadata in results.items():
        print(
            f"{layer}: population={metadata['population_cves']}, "
            f"published={metadata['published_by_cutoff_cves']}, "
            f"not_published={metadata['not_published_at_cutoff_cves']}, "
            f"evidence_eligible={metadata['evidence_eligible_cves']}, "
            f"evidence_ineligible={metadata['evidence_ineligible_cves']}, "
            f"known_empty={metadata['known_empty_relationship_cves']}, "
            f"feature_rows={metadata['feature_rows']}, "
            f"unavailable_published={metadata['feature_unavailable_published_cves']}"
        )
    print(f"Outputs: {args.output_dir}")


if __name__ == "__main__":
    main()
