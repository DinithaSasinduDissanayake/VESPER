"""Create a CVSS-severity product/weakness cluster exploration from local NVD data.

This is not a KEV missed-risk analysis. CVSS severity is a vulnerability-impact
measure, and absent EPSS/KEV data remain unavailable.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from collections.abc import Iterable
from datetime import date
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd

from vesper.components.c_graph.nvd_parser import parse_nvd_record
from vesper.components.c_graph.pipeline import discover_monthly_files, read_month

FEATURE_COLUMNS = ["cve_id", "in_degree_centrality", "out_degree_centrality", "pagerank"]
OUTPUT_COLUMNS = [
    "cve_id",
    "published_at",
    "cvss_base_score",
    "cvss_version",
    "cvss_severity",
    "graph_feature_status",
    "graph_exclusion_reason",
    "in_degree_centrality",
    "out_degree_centrality",
    "pagerank",
    "vendor_product_relationships",
    "cwe_relationships",
    "product_evidence_status",
    "weakness_evidence_status",
    "epss_score",
    "epss_status",
    "kev_date_added",
    "kev_status",
]


def _cvss_details(cve: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None, None, None
    candidates: list[tuple[float, str, str | None]] = []
    for key, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key, [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            data = entry.get("cvssData")
            if not isinstance(data, dict):
                continue
            score = data.get("baseScore")
            severity = data.get("baseSeverity")
            if isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 10:
                candidates.append(
                    (float(score), version, severity.upper() if isinstance(severity, str) else None)
                )
    if not candidates:
        return None, None, None
    score, version, severity = max(candidates, key=lambda item: item[0])
    return score, version, severity


def analyze_records(
    records: Iterable[dict[str, Any]],
    feature_rows: pd.DataFrame,
    exclusions: pd.DataFrame,
    target_ids: set[str],
    snapshot_date: date,
) -> tuple[pd.DataFrame, pd.DataFrame, dict[str, int]]:
    """Select explicit HIGH/CRITICAL CVSS records and trace graph evidence.

    Only current NVD records passing the same publication, modification, and
    rejected-status checks as the snapshot pipeline are considered. Candidates
    without graph rows retain blank features and do not contribute cluster edges.
    """
    if list(feature_rows.columns) != FEATURE_COLUMNS:
        raise ValueError(f"Feature columns must be exactly {FEATURE_COLUMNS!r}")
    feature_map = feature_rows.set_index("cve_id").to_dict(orient="index")
    exclusion_map = {}
    if not exclusions.empty:
        required = {"cve_id", "reason", "detail"}
        if not required.issubset(exclusions.columns):
            raise ValueError("Exclusions table is missing required columns")
        exclusion_map = exclusions.set_index("cve_id")["reason"].to_dict()

    counts = defaultdict(int)
    candidates: list[dict[str, Any]] = []
    pair_cves: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    seen: set[str] = set()
    for record in records:
        cve = record.get("cve") if isinstance(record, dict) else None
        if not isinstance(cve, dict):
            continue
        cve_id = cve.get("id")
        if not isinstance(cve_id, str) or cve_id not in target_ids:
            continue
        counts["target_records_seen"] += 1
        if cve_id in seen:
            raise ValueError(f"Duplicate CVE record: {cve_id}")
        seen.add(cve_id)
        vulnerability = parse_nvd_record(record, snapshot_date)
        if vulnerability.published_at.date() > snapshot_date:
            counts["excluded_published_after_cutoff"] += 1
            continue
        if vulnerability.last_modified_at.date() > snapshot_date:
            counts["excluded_modified_after_cutoff"] += 1
            continue
        if vulnerability.nvd_status.strip().casefold() == "rejected":
            counts["excluded_rejected"] += 1
            continue
        score, version, severity = _cvss_details(cve)
        if score is None:
            counts["cvss_unavailable"] += 1
            continue
        if severity is None:
            counts["cvss_severity_unavailable"] += 1
            continue
        if severity not in {"HIGH", "CRITICAL"}:
            counts["below_high_or_critical_severity"] += 1
            continue

        feature = feature_map.get(cve_id)
        feature_status = (
            "available"
            if feature is not None
            else ("not_eligible" if cve_id in exclusion_map else "feature_row_missing")
        )
        products = list(vulnerability.affected)
        cwes = list(vulnerability.cwe_ids)
        row = {
            "cve_id": cve_id,
            "published_at": vulnerability.published_at.isoformat(),
            "cvss_base_score": score,
            "cvss_version": version,
            "cvss_severity": severity,
            "graph_feature_status": feature_status,
            "graph_exclusion_reason": exclusion_map.get(cve_id, ""),
            "in_degree_centrality": feature.get("in_degree_centrality") if feature else None,
            "out_degree_centrality": feature.get("out_degree_centrality") if feature else None,
            "pagerank": feature.get("pagerank") if feature else None,
            "vendor_product_relationships": json.dumps(products, separators=(",", ":")),
            "cwe_relationships": json.dumps(cwes, separators=(",", ":")),
            "product_evidence_status": "present_in_current_nvd_record"
            if products
            else "not_reported_in_current_record",
            "weakness_evidence_status": "present_in_current_nvd_record"
            if cwes
            else "not_reported_in_current_record",
            "epss_score": None,
            "epss_status": "unavailable_source_not_present",
            "kev_date_added": None,
            "kev_status": "unavailable_source_not_present",
        }
        candidates.append(row)
        counts["cvss_high_critical_candidates"] += 1
        if feature is not None:
            counts["candidate_graph_features_available"] += 1
            if products and cwes:
                counts["candidates_with_product_and_cwe_evidence"] += 1
                for vendor, product in products:
                    product_label = f"{vendor}/{product}"
                    for cwe in cwes:
                        pair_cves[(product_label, cwe, cve_id)].add(cve_id)
        else:
            counts["candidate_graph_features_unavailable"] += 1

    candidate_frame = (
        pd.DataFrame(candidates, columns=OUTPUT_COLUMNS).sort_values("cve_id", kind="stable")
        if candidates
        else pd.DataFrame(columns=OUTPUT_COLUMNS)
    )
    edge_counts: dict[tuple[str, str], int] = defaultdict(int)
    edge_members: dict[tuple[str, str], list[str]] = defaultdict(list)
    for product, cwe, cve_id in pair_cves:
        edge_counts[(product, cwe)] += 1
        edge_members[(product, cwe)].append(cve_id)
    edge_rows = [
        {
            "product": product,
            "cwe_id": cwe,
            "cve_count": count,
            "cve_ids": json.dumps(sorted(edge_members[(product, cwe)]), separators=(",", ":")),
        }
        for (product, cwe), count in sorted(
            edge_counts.items(), key=lambda item: (-item[1], item[0])
        )
    ]
    edges = pd.DataFrame(edge_rows, columns=["product", "cwe_id", "cve_count", "cve_ids"])
    counts["product_cwe_cluster_edges"] = len(edges)
    counts["clustered_cves"] = len({cve_id for ids in edge_members.values() for cve_id in ids})
    return candidate_frame, edges, dict(counts)


def build_cluster_graph(
    edges: pd.DataFrame, max_products: int = 12, max_cwes: int = 12
) -> nx.Graph:
    """Build a deterministic bipartite graph from observed CVSS-selected pairs."""
    required = {"product", "cwe_id", "cve_count"}
    if not required.issubset(edges.columns):
        raise ValueError("Cluster edges require product, cwe_id, and cve_count columns")
    graph = nx.Graph()
    if edges.empty:
        return graph
    product_counts = (
        edges.groupby("product")["cve_count"].sum().sort_values(ascending=False, kind="stable")
    )
    cwe_counts = (
        edges.groupby("cwe_id")["cve_count"].sum().sort_values(ascending=False, kind="stable")
    )
    products = set(product_counts.head(max_products).index)
    cwes = set(cwe_counts.head(max_cwes).index)
    selected = edges[edges["product"].isin(products) & edges["cwe_id"].isin(cwes)].sort_values(
        ["cve_count", "product", "cwe_id"], ascending=[False, True, True], kind="stable"
    )
    for row in selected.itertuples(index=False):
        pnode, wnode = f"product:{row.product}", f"cwe:{row.cwe_id}"
        graph.add_node(pnode, kind="product", label=row.product, weight=int(row.cve_count))
        graph.add_node(wnode, kind="cwe", label=row.cwe_id, weight=int(row.cve_count))
        graph.add_edge(
            pnode, wnode, cve_count=int(row.cve_count), cve_ids=getattr(row, "cve_ids", "[]")
        )
    return graph


def build_cluster_matrix(edges: pd.DataFrame) -> pd.DataFrame:
    """Return counts with products on rows and CWEs on columns."""
    graph = build_cluster_graph(edges)
    rows = []
    for left, right, data in graph.edges(data=True):
        product_node, cwe_node = (
            (left, right) if graph.nodes[left]["kind"] == "product" else (right, left)
        )
        rows.append(
            {
                "product": graph.nodes[product_node]["label"],
                "cwe_id": graph.nodes[cwe_node]["label"],
                "cve_count": data["cve_count"],
            }
        )
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows).pivot(index="product", columns="cwe_id", values="cve_count").fillna(0)


def render_cluster_visualization(edges: pd.DataFrame, output_path: Path) -> None:
    """Save a readable heatmap of product/CWE co-occurrence counts."""
    matrix = build_cluster_matrix(edges)
    fig, ax = plt.subplots(figsize=(14, 9), layout="constrained")
    if matrix.empty:
        ax.text(
            0.5,
            0.5,
            "No supported product/CWE co-occurrences in selected records",
            ha="center",
            va="center",
        )
        ax.set_axis_off()
        ax.set_title("CVSS HIGH/CRITICAL product-weakness clusters")
    else:
        image = ax.imshow(matrix.to_numpy(), cmap="YlOrRd", aspect="auto", interpolation="nearest")
        ax.set_xticks(range(len(matrix.columns)), labels=matrix.columns, rotation=45, ha="right")
        ax.set_yticks(range(len(matrix.index)), labels=matrix.index)
        ax.set_xlabel("CWE in current NVD record")
        ax.set_ylabel("Vendor/product in current NVD record")
        for row_index in range(len(matrix.index)):
            for column_index in range(len(matrix.columns)):
                count = matrix.iloc[row_index, column_index]
                if count:
                    ax.text(
                        column_index,
                        row_index,
                        f"{int(count)}",
                        ha="center",
                        va="center",
                        fontsize=8,
                    )
        fig.colorbar(image, ax=ax, label="Distinct eligible CVEs")
        ax.set_title(
            "CVSS HIGH/CRITICAL product-weakness co-occurrence clusters\n"
            "Cell values = distinct eligible CVEs; current NVD snapshot"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=180, bbox_inches="tight")
    plt.close(fig)


def run_analysis(
    nvd_dir: Path,
    graph_features_path: Path,
    exclusions_path: Path,
    manifest_path: Path,
    output_dir: Path,
    snapshot_date: date,
) -> dict[str, Any]:
    """Run the offline CVSS severity exploration; refuse to overwrite output."""
    if output_dir.exists():
        raise FileExistsError(f"Output directory already exists: {output_dir}")
    output_dir.mkdir(parents=True)
    features = pd.read_csv(graph_features_path, usecols=FEATURE_COLUMNS)
    exclusions = pd.read_csv(exclusions_path)
    target_ids = set(pd.read_csv(manifest_path, usecols=["cve_id"])["cve_id"].astype(str))
    records = (record for _, path in discover_monthly_files(nvd_dir) for record in read_month(path))
    candidates, edges, counts = analyze_records(
        records, features, exclusions, target_ids, snapshot_date
    )
    candidates_path = output_dir / "cvss_high_critical_candidates.csv"
    edges_path = output_dir / "product_weakness_cluster_edges.csv"
    candidates.to_csv(candidates_path, index=False)
    edges.to_csv(edges_path, index=False)
    render_cluster_visualization(edges, output_dir / "cvss_product_weakness_clusters.png")
    metadata = {
        "analysis_kind": "exploratory_cvss_severity_clusters_not_missed_risk",
        "snapshot_date": snapshot_date.isoformat(),
        "snapshot_scope": (
            "Current NVD CVE records used by the 2026-10-15 Component C snapshot; "
            "not historical replay."
        ),
        "candidate_rule": (
            "NVD CVSS baseSeverity is HIGH or CRITICAL for the highest available base "
            "score selected in version order 4.0, 3.1, 3.0, 2.0."
        ),
        "risk_interpretation": (
            "CVSS severity is not exploitation probability, KEV membership, or the "
            "proposal's missed-risk label."
        ),
        "epss_source": None,
        "kev_source": None,
        "missing_epss_or_kev_values": "Preserved as unavailable; no values or labels were imputed.",
        "candidate_output": str(candidates_path),
        "cluster_edge_output": str(edges_path),
        "visualization_output": str(output_dir / "cvss_product_weakness_clusters.png"),
        "counts": counts,
    }
    (output_dir / "analysis_metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nvd-dir", type=Path, default=Path("data/raw/nvd"))
    parser.add_argument("--graph-features", type=Path, required=True)
    parser.add_argument("--exclusions", type=Path, required=True)
    parser.add_argument(
        "--manifest", type=Path, default=Path("data/processed/c_graph/research_population.csv")
    )
    parser.add_argument("--snapshot-date", type=date.fromisoformat, default=date(2026, 10, 15))
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            run_analysis(
                args.nvd_dir,
                args.graph_features,
                args.exclusions,
                args.manifest,
                args.output_dir,
                args.snapshot_date,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
