
"""Knowledge graph construction for Component C."""

from dataclasses import dataclass, field

from vesper.contracts.vulnerability import Vulnerability


@dataclass
class KnowledgeGraph:
    """Represent vendor, product, CVE, and CWE relationships."""

    nodes: set[tuple[str, str]] = field(default_factory=set)
    edges: set[tuple[tuple[str, str], tuple[str, str]]] = field(
        default_factory=set
    )

    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        """Add one CVE and its known vendor, product, and CWE relationships."""
        cve_node = ("cve", vulnerability.cve_id)
        self.nodes.add(cve_node)

        for vendor, product in vulnerability.affected:
            vendor_node = ("vendor", vendor)
            product_node = ("product", f"{vendor}:{product}")

            self.nodes.add(vendor_node)
            self.nodes.add(product_node)

            self.edges.add((vendor_node, product_node))
            self.edges.add((product_node, cve_node))

        for cwe_id in vulnerability.cwe_ids:
            cwe_node = ("cwe", cwe_id)
            self.nodes.add(cwe_node)
            self.edges.add((cve_node, cwe_node))
