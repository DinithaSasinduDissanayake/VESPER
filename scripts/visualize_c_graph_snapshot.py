"""Render a readable schema and scale overview for a full Component C graph."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

NODE_TYPES = ("vendor", "product", "cve", "cwe")
RELATIONSHIPS = ("offers", "affected_by", "has_weakness")
COLORS = {
    "vendor": "#dbeafe",
    "product": "#dcfce7",
    "cve": "#fef3c7",
    "cwe": "#fce7f3",
}


def render_overview(
    graph_metadata_path: Path,
    population_metadata_path: Path,
    output_path: Path,
) -> None:
    """Render a relationship-schema overview annotated with full graph counts."""
    graph_metadata: dict[str, Any] = json.loads(graph_metadata_path.read_text(encoding="utf-8"))
    population_metadata: dict[str, Any] = json.loads(
        population_metadata_path.read_text(encoding="utf-8")
    )
    graph_summary = graph_metadata["graph_summary"]
    snapshot_date = graph_metadata["snapshot_date"]

    fig, ax = plt.subplots(figsize=(15, 8), layout="constrained")
    ax.set_xlim(0, 15)
    ax.set_ylim(0, 8)
    ax.axis("off")
    fig.patch.set_facecolor("#f8fafc")
    ax.set_facecolor("#f8fafc")

    positions = {kind: (0.5 + index * 3.75, 4.1) for index, kind in enumerate(NODE_TYPES)}
    box_w, box_h = 2.55, 1.45
    for kind in NODE_TYPES:
        x, y = positions[kind]
        box = FancyBboxPatch(
            (x, y),
            box_w,
            box_h,
            boxstyle="round,pad=0.08,rounding_size=0.12",
            linewidth=1.5,
            edgecolor="#334155",
            facecolor=COLORS[kind],
        )
        ax.add_patch(box)
        ax.text(
            x + box_w / 2,
            y + 0.95,
            kind.upper(),
            ha="center",
            va="center",
            fontsize=13,
            fontweight="bold",
            color="#0f172a",
        )
        ax.text(
            x + box_w / 2,
            y + 0.43,
            f"{graph_summary[kind]:,} nodes",
            ha="center",
            va="center",
            fontsize=12,
            color="#334155",
        )

    for index, relationship in enumerate(RELATIONSHIPS):
        left_kind, right_kind = NODE_TYPES[index], NODE_TYPES[index + 1]
        left_x = positions[left_kind][0] + box_w + 0.12
        right_x = positions[right_kind][0] - 0.12
        arrow = FancyArrowPatch(
            (left_x, 4.83),
            (right_x, 4.83),
            arrowstyle="-|>",
            mutation_scale=18,
            linewidth=1.7,
            color="#475569",
        )
        ax.add_patch(arrow)
        ax.text(
            (left_x + right_x) / 2,
            5.25,
            relationship,
            ha="center",
            va="center",
            fontsize=10,
            color="#334155",
        )

    ax.text(
        7.5,
        7.25,
        "VESPER Component C — Full NVD Snapshot Graph",
        ha="center",
        va="center",
        fontsize=19,
        fontweight="bold",
        color="#0f172a",
    )
    ax.text(
        7.5,
        6.78,
        f"Snapshot cutoff: {snapshot_date} UTC   |   Total edges: {graph_summary['edges']:,}",
        ha="center",
        va="center",
        fontsize=12,
        color="#334155",
    )

    population = population_metadata["research_population_count"]
    target_features = population_metadata["target_feature_rows"]
    not_eligible = population_metadata["target_rejected_not_eligible"]
    outside_context = population_metadata["out_of_population_graph_feature_rows"]
    ax.text(
        7.5,
        2.75,
        f"Research population: {population:,} CVEs     "
        f"Feature rows: {target_features:,}     "
        f"NVD Rejected / not eligible: {not_eligible:,}",
        ha="center",
        va="center",
        fontsize=12,
        color="#0f172a",
    )
    ax.text(
        7.5,
        2.2,
        f"Graph context also includes {outside_context:,} CVEs outside the research population.",
        ha="center",
        va="center",
        fontsize=11,
        color="#334155",
    )
    ax.text(
        7.5,
        1.35,
        "Schema overview; boxes show node counts, arrows show relationship types. "
        "This is not a node-by-node layout.",
        ha="center",
        va="center",
        fontsize=10,
        color="#475569",
    )
    ax.text(
        7.5,
        0.82,
        "Current NVD record snapshot. Per-CVE historical relationship reconstruction "
        "was not performed.",
        ha="center",
        va="center",
        fontsize=10,
        color="#9f1239",
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=180, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph-metadata", type=Path, required=True)
    parser.add_argument("--population-metadata", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    render_overview(args.graph_metadata, args.population_metadata, args.output)
    print(f"Graph overview saved to: {args.output}")


if __name__ == "__main__":
    main()
