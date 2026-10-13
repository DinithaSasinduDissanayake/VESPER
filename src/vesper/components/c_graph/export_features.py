
"""Build the NVD knowledge graph and export CVE graph features."""

import argparse
import gzip
import json
from datetime import date
from pathlib import Path

from vesper.components.c_graph.graph import KnowledgeGraph
from vesper.components.c_graph.nvd_parser import parse_nvd_record
from vesper.components.c_graph.scoring import calculate_cve_features


def export_features(
    input_path: Path,
    output_path: Path,
    snapshot_date: date,
) -> None:
    """Parse NVD records, calculate graph features, and export them."""
    with gzip.open(input_path, "rt", encoding="utf-8") as file:
        data = json.load(file)

    graph = KnowledgeGraph()

    for record in data["vulnerabilities"]:
        vulnerability = parse_nvd_record(record, snapshot_date)
        graph.add_vulnerability(vulnerability)

    features = calculate_cve_features(graph)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    features.to_csv(output_path, index=False)

    print(f"Records processed: {len(data['vulnerabilities'])}")
    print(f"Graph nodes: {len(graph.nodes)}")
    print(f"Graph edges: {len(graph.edges)}")
    print(f"Feature rows: {len(features)}")
    print(f"Output: {output_path}")


def main() -> None:
    """Run the feature export from the command line."""
    parser = argparse.ArgumentParser(
        description="Export graph features from a compressed NVD dataset."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--snapshot-date", type=date.fromisoformat, required=True)
    args = parser.parse_args()

    export_features(args.input, args.output, args.snapshot_date)


if __name__ == "__main__":
    main()
