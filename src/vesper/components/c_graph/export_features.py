"""Export Component C graph features to CSV."""

import argparse
from pathlib import Path

from vesper.components.c_graph.scoring import calculate_graph_features


def export_features_to_csv(
    graph,
    output_path: Path,
) -> Path:
    """Calculate graph features and atomically export them to CSV."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    features = calculate_graph_features(graph)
    temporary_path = output_path.with_suffix(output_path.suffix + ".tmp")

    try:
        features.to_csv(temporary_path, index=False)
        temporary_path.replace(output_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    return output_path


def main() -> None:
    """Provide a command-line entry point for feature export."""
    parser = argparse.ArgumentParser(
        description="Export graph features from a previously built graph."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="CSV output path (defaults to outputs/c_graph_features.csv).",
    )
    parser.parse_args()

    parser.error(
        "Graph loading is not implemented yet. "
        "The export_features_to_csv() function can be used by the pipeline "
        "once graph construction and input loading are connected."
    )


if __name__ == "__main__":
    main()
