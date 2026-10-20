"""Export the saved probability pilot as separate historical CPE/CWE cutoff graphs."""

from __future__ import annotations

import argparse
from pathlib import Path

from vesper.components.c_graph.historical_cutoff_export import (
    DEFAULT_CUTOFFS,
    run_historical_cutoff_export,
)


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
        "--manifest",
        type=Path,
        default=Path("data/processed/c_graph/research_population.csv"),
    )
    parser.add_argument(
        "--labels",
        type=Path,
        default=Path(
            "outputs/c_graph_kev_label_readiness_2026-10-16_run2/kev_outcomes_by_cutoff.csv"
        ),
    )
    parser.add_argument(
        "--selection-metadata",
        type=Path,
        default=Path("outputs/c_graph_probability_pilot_2026-10-16/selection_metadata.json"),
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cutoff", action="append", dest="cutoffs")
    args = parser.parse_args()
    result = run_historical_cutoff_export(
        history_dir=args.history_dir,
        sample_frame_path=args.sample_frame,
        manifest_path=args.manifest,
        labels_path=args.labels,
        selection_metadata_path=args.selection_metadata,
        output_dir=args.output_dir,
        cutoffs=tuple(args.cutoffs) if args.cutoffs else DEFAULT_CUTOFFS,
    )
    print(
        f"Exported {result['pilot_sample_size']} sample CVEs across "
        f"{len(result['cutoffs_utc'])} cutoffs."
    )
    print(f"Output: {args.output_dir}")


if __name__ == "__main__":
    main()
