"""Export the confirmed historical C grid with intentional abstentions only."""

import argparse
import json
from datetime import date
from pathlib import Path

from vesper.components.c_graph.historical_panel import export_historical_panel


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--history-dir", dest="history_dirs", type=Path, action="append", required=True
    )
    parser.add_argument(
        "--output-dir", type=Path, required=True, help="New directory; never overwritten"
    )
    parser.add_argument("--start", type=date.fromisoformat, default=date(2023, 1, 1))
    parser.add_argument("--end", type=date.fromisoformat, default=date(2026, 9, 1))
    parser.add_argument("--exclude-date", type=date.fromisoformat, default=date(2024, 12, 1))
    parser.add_argument("--cutoff-time", choices=["00:00:00Z"], default="00:00:00Z")
    parser.add_argument("--horizon-days", type=int, choices=[30], default=30)
    parser.add_argument("--mode", choices=["abstention-only"], default="abstention-only")
    args = parser.parse_args()
    try:
        metadata = export_historical_panel(**vars(args))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                key: metadata[key]
                for key in (
                    "actual_panel_row_count",
                    "available_count",
                    "abstained_count",
                    "output_file",
                    "output_sha256",
                )
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
