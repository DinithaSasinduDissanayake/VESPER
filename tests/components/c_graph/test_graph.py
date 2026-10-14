
"""Tests for the Component C knowledge graph."""

from datetime import date, datetime, timezone

import pytest

from vesper.components.c_graph.graph import build_graph, graph_summary
from vesper.contracts.vulnerability import Vulnerability


def make_vulnerability(
    cve_id: str = "CVE-2024-12345",
    affected: tuple[tuple[str, str], ...] = (("examplevendor", "exampleproduct"),),
    cwe_ids: tuple[str, ...] = ("CWE-79",),
) -> Vulnerability:
    """Create a valid vulnerability record for graph tests."""
    return Vulnerability(
        cve_id=cve_id,
        published_at=datetime(2024, 1, 10, tzinfo=timezone.utc),
        last_modified_at=datetime(2024, 1, 15, tzinfo=timezone.utc),
        description="Example vulnerability",
        cvss_base_score=7.5,
        cvss_version="3.1",
        cvss_vector=None,
        cwe_ids=cwe_ids,
        affected=affected,
        nvd_status="Analyzed",
        snapshot_date=date(2024, 1, 31),
    )


def test_builds_vendor_product_cve_and_cwe_relationships():
    graph = build_graph([make_vulnerability()])

    assert graph.has_edge("vendor:examplevendor", "product:examplevendor:exampleproduct")
    assert graph.has_edge("product:examplevendor:exampleproduct", "cve:CVE-2024-12345")
    assert graph.has_edge("cve:CVE-2024-12345", "cwe:CWE-79")

    assert graph["vendor:examplevendor"]["product:examplevendor:exampleproduct"]["relation"] == "offers"
    assert graph["product:examplevendor:exampleproduct"]["cve:CVE-2024-12345"]["relation"] == "affected_by"
    assert graph["cve:CVE-2024-12345"]["cwe:CWE-79"]["relation"] == "has_weakness"


def test_summary_counts_node_types_and_edges():
    graph = build_graph([make_vulnerability()])

    assert graph_summary(graph) == {
        "vendor": 1,
        "product": 1,
        "cve": 1,
        "cwe": 1,
        "edges": 3,
    }


def test_cve_without_relationships_is_still_in_graph():
    vulnerability = make_vulnerability(affected=(), cwe_ids=())

    graph = build_graph([vulnerability])

    assert "cve:CVE-2024-12345" in graph
    assert graph_summary(graph) == {
        "vendor": 0,
        "product": 0,
        "cve": 1,
        "cwe": 0,
        "edges": 0,
    }


def test_multiple_cves_can_share_product_and_cwe():
    vulnerabilities = [
        make_vulnerability("CVE-2024-12345"),
        make_vulnerability("CVE-2024-12346"),
    ]

    graph = build_graph(vulnerabilities)

    assert graph_summary(graph) == {
        "vendor": 1,
        "product": 1,
        "cve": 2,
        "cwe": 1,
        "edges": 5,
    }


def test_duplicate_cve_records_are_rejected():
    vulnerability = make_vulnerability()

    with pytest.raises(ValueError, match="Duplicate CVE record"):
        build_graph([vulnerability, vulnerability])
