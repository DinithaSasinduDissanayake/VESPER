
"""Tests for integrating reconstructed relationships into graph scoring."""

from datetime import date, datetime, timezone

from vesper.components.c_graph.graph import KnowledgeGraph
from vesper.components.c_graph.history_reconstruction import (
    reconstruct_relationships,
)
from vesper.components.c_graph.scoring import calculate_cve_features
from vesper.contracts.vulnerability import Vulnerability


def test_reconstructed_relationships_can_be_scored():
    history = {
        "cveChanges": [
            {
                "change": {
                    "created": "2024-01-08T18:51:23.750",
                    "details": [
                        {
                            "action": "Added",
                            "type": "CWE",
                            "newValue": "NIST CWE-79",
                        },
                        {
                            "action": "Added",
                            "type": "CPE Configuration",
                            "newValue": (
                                "cpe:2.3:a:flycms_project:flycms:"
                                "*:*:*:*:*:*:*:*"
                            ),
                        },
                    ],
                }
            }
        ]
    }

    snapshot = date(2024, 2, 1)
    historical = reconstruct_relationships(
        "CVE-2024-21732",
        history,
        snapshot,
    )

    timestamp = datetime(2024, 1, 1, tzinfo=timezone.utc)
    vulnerability = Vulnerability(
        cve_id=historical.cve_id,
        published_at=timestamp,
        last_modified_at=timestamp,
        description="Historical relationship integration test",
        cvss_base_score=None,
        cvss_version=None,
        cvss_vector=None,
        cwe_ids=historical.cwe_ids,
        affected=historical.affected,
        nvd_status="Unknown",
        snapshot_date=historical.snapshot_date,
    )

    graph = KnowledgeGraph()
    graph.add_vulnerability(vulnerability)
    features = calculate_cve_features(graph)

    assert ("vendor", "flycms_project") in graph.nodes
    assert ("product", "flycms_project:flycms") in graph.nodes
    assert ("cve", "CVE-2024-21732") in graph.nodes
    assert ("cwe", "CWE-79") in graph.nodes
    assert len(features) == 1
    assert features.iloc[0]["cve_id"] == "CVE-2024-21732"
