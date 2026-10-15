"""Build the Component C vendor/product/CVE/CWE knowledge graph."""

from collections.abc import Iterable

import networkx as nx

from vesper.contracts.vulnerability import Vulnerability

NODE_TYPE = "node_type"


def build_graph(vulnerabilities: Iterable[Vulnerability]) -> nx.DiGraph:
    """Build a directed knowledge graph from parsed vulnerabilities.

    Node IDs are namespaced to avoid collisions between entity types.
    Duplicate CVE records are rejected so conflicting snapshots cannot be
    silently combined in one graph.
    """
    graph = nx.DiGraph()
    seen_cves: set[str] = set()

    for vulnerability in vulnerabilities:
        cve_id = vulnerability.cve_id

        if cve_id in seen_cves:
            raise ValueError(f"Duplicate CVE record: {cve_id}")
        seen_cves.add(cve_id)

        cve_node = f"cve:{cve_id}"
        graph.add_node(
            cve_node,
            node_type="cve",
            cve_id=cve_id,
            snapshot_date=vulnerability.snapshot_date.isoformat(),
            published_at=vulnerability.published_at.isoformat(),
        )

        for vendor, product in vulnerability.affected:
            vendor_node = f"vendor:{vendor}"
            product_node = f"product:{vendor}:{product}"

            graph.add_node(
                vendor_node,
                node_type="vendor",
                name=vendor,
            )
            graph.add_node(
                product_node,
                node_type="product",
                vendor=vendor,
                name=product,
            )

            graph.add_edge(
                vendor_node,
                product_node,
                relation="offers",
            )
            graph.add_edge(
                product_node,
                cve_node,
                relation="affected_by",
            )

        for cwe_id in vulnerability.cwe_ids:
            cwe_node = f"cwe:{cwe_id}"

            graph.add_node(
                cwe_node,
                node_type="cwe",
                cwe_id=cwe_id,
            )
            graph.add_edge(
                cve_node,
                cwe_node,
                relation="has_weakness",
            )

    return graph


def graph_summary(graph: nx.DiGraph) -> dict[str, int]:
    """Return node counts by entity type and the total edge count."""
    counts = {
        node_type: sum(
            1 for _, attributes in graph.nodes(data=True) if attributes.get(NODE_TYPE) == node_type
        )
        for node_type in ("vendor", "product", "cve", "cwe")
    }
    counts["edges"] = graph.number_of_edges()
    return counts
