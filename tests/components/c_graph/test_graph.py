
"""Tests for Component C knowledge graph construction."""

from datetime import UTC, date, datetime

from vesper.components.c_graph.graph import KnowledgeGraph
from vesper.contracts.vulnerability import Vulnerability


def make_vulnerability() -> Vulnerability:
    return Vulnerability(
        cve_id="CVE-2021-44228",
        published_at=datetime(2021, 12, 10, tzinfo=UTC),
        last_modified_at=datetime(2023, 4, 3, tzinfo=UTC),
        description="Example vulnerability.",
        cvss_base_score=10.0,
        cvss_version="3.1",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        cwe_ids=("CWE-502",),
        affected=(("apache", "log4j"),),
        nvd_status="Analyzed",
        snapshot_date=date(2026, 10, 12),
    )


def test_graph_adds_vendor_product_cve_and_cwe():
    graph = KnowledgeGraph()
    graph.add_vulnerability(make_vulnerability())

    vendor = ("vendor", "apache")
    product = ("product", "apache:log4j")
    cve = ("cve", "CVE-2021-44228")
    cwe = ("cwe", "CWE-502")

    assert graph.nodes == {vendor, product, cve, cwe}
    assert graph.edges == {
        (vendor, product),
        (product, cve),
        (cve, cwe),
    }


def test_graph_supports_cves_without_product_or_cwe_links():
    vulnerability = make_vulnerability()
    vulnerability = Vulnerability(
        cve_id=vulnerability.cve_id,
        published_at=vulnerability.published_at,
        last_modified_at=vulnerability.last_modified_at,
        description=vulnerability.description,
        cvss_base_score=None,
        cvss_version=None,
        cvss_vector=None,
        cwe_ids=(),
        affected=(),
        nvd_status="Analyzed",
        snapshot_date=vulnerability.snapshot_date,
    )

    graph = KnowledgeGraph()
    graph.add_vulnerability(vulnerability)

    assert graph.nodes == {("cve", "CVE-2021-44228")}
    assert graph.edges == set()
