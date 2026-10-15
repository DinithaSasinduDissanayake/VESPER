"""Calculate graph-derived features for Component C CVE nodes."""

import math

import networkx as nx
import pandas as pd

CVE_PREFIX = "cve:"

FEATURE_COLUMNS = [
    "cve_id",
    "in_degree_centrality",
    "out_degree_centrality",
    "pagerank",
]


def calculate_graph_features(graph: nx.DiGraph) -> pd.DataFrame:
    """Calculate centrality and PageRank features for every CVE node.

    These are structural graph features, not exploitation probabilities.

    For graphs with fewer than two nodes, degree centrality is defined as
    zero because the usual normalization denominator is zero.
    """
    cve_nodes = sorted(
        node for node, attributes in graph.nodes(data=True) if attributes.get("node_type") == "cve"
    )

    if not cve_nodes:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    # Degree centrality is normalized by (number of nodes - 1).
    # Define it as zero when that denominator would be zero.
    if graph.number_of_nodes() < 2:
        in_centrality = {node: 0.0 for node in graph.nodes}
        out_centrality = {node: 0.0 for node in graph.nodes}
    else:
        in_centrality = nx.in_degree_centrality(graph)
        out_centrality = nx.out_degree_centrality(graph)

    pagerank = nx.pagerank(graph)

    rows: list[dict[str, str | float]] = []

    for node in cve_nodes:
        cve_id = node.removeprefix(CVE_PREFIX)

        values = (
            float(in_centrality.get(node, 0.0)),
            float(out_centrality.get(node, 0.0)),
            float(pagerank.get(node, 0.0)),
        )

        if not all(math.isfinite(value) for value in values):
            raise ValueError(f"Non-finite graph feature for {cve_id}")

        rows.append(
            {
                "cve_id": cve_id,
                "in_degree_centrality": values[0],
                "out_degree_centrality": values[1],
                "pagerank": values[2],
            }
        )

    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)
