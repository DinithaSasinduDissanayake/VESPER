
"""Tests for Component C graph scoring."""

from datetime import date, datetime, timezone

from vesper.components.c_graph.graph import KnowledgeGraph
from vesper.components.c_graph.scoring import calculate_cve_features
from vesper.contracts.vulnerability import Vulnerability


def make_vulnerability(cve_id: str) -> Vulnerability:
    """Create a valid test vulnerability."""
    timestamp = datetime(2024, 1, 15, tzinfo=timezone.utc)

    return Vulnerability(
        cve_id=cve_id,
        published_at=timestamp,
        last_modified_at=timestamp,
        description="Test vulnerability",
        cvss_base_score=7.5,
        cvss_version="3.1",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwe_ids=("CWE-79",),
        affected=(("example-vendor", "example-product"),),
        nvd_status="Analyzed",
        snapshot_date=date(2024, 2, 1),
    )


def test_calculate_cve_features_returns_expected_columns():
    graph = KnowledgeGraph()
    graph.add_vulnerability(make_vulnerability("CVE-2024-0001"))

    features = calculate_cve_features(graph)

    assert list(features.columns) == [
        "cve_id",
        "in_degree_centrality",
        "out_degree_centrality",
        "pagerank",
    ]
    assert len(features) == 1
    assert features.iloc[0]["cve_id"] == "CVE-2024-0001"


def test_calculate_cve_features_has_valid_scores():
    graph = KnowledgeGraph()
    graph.add_vulnerability(make_vulnerability("CVE-2024-0002"))

    features = calculate_cve_features(graph)

    score_columns = [
        "in_degree_centrality",
        "out_degree_centrality",
        "pagerank",
    ]

    assert features[score_columns].notna().all().all()
    assert (features[score_columns] >= 0).all().all()
