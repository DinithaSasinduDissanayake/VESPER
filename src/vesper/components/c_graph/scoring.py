
"""Calculate graph-based vulnerability features for Component C."""

import networkx as nx
import pandas as pd

from vesper.components.c_graph.graph import KnowledgeGraph


def calculate_cve_features(graph: KnowledgeGraph) -> pd.DataFrame:
    """Calculate graph features for every CVE node."""
    network = nx.DiGraph()
    network.add_nodes_from(graph.nodes)
    network.add_edges_from(graph.edges)

    in_degree_scores = nx.in_degree_centrality(network)
    out_degree_scores = nx.out_degree_centrality(network)
    pagerank_scores = nx.pagerank(network)

    rows = [
        {
            "cve_id": node_id,
            "in_degree_centrality": in_degree_scores[node],
            "out_degree_centrality": out_degree_scores[node],
            "pagerank": pagerank_scores[node],
        }
        for node_type, node_id in graph.nodes
        if node_type == "cve"
        for node in [(node_type, node_id)]
    ]

    return pd.DataFrame(
        rows,
        columns=[
            "cve_id",
            "in_degree_centrality",
            "out_degree_centrality",
            "pagerank",
        ],
    )
