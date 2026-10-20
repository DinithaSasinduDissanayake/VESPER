from __future__ import annotations

import importlib.util
from pathlib import Path

import networkx as nx
import pandas as pd
import pytest

_script = Path(__file__).resolve().parents[3] / "scripts" / "analyze_c_graph_cvss_clusters.py"
_spec = importlib.util.spec_from_file_location("analyze_c_graph_cvss_clusters", _script)
assert _spec is not None and _spec.loader is not None
_analysis = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_analysis)
FEATURE_COLUMNS = _analysis.FEATURE_COLUMNS
analyze_records = _analysis.analyze_records
build_cluster_graph = _analysis.build_cluster_graph
build_cluster_matrix = _analysis.build_cluster_matrix
render_cluster_visualization = _analysis.render_cluster_visualization


def _record(
    cve_id: str, *, score: float | None, severity: str | None, product: bool = True
) -> dict:
    cve = {
        "id": cve_id,
        "published": "2024-01-01T00:00:00.000",
        "lastModified": "2024-02-01T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [],
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
        "configurations": [],
    }
    if product:
        cve["configurations"] = [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:example:widget:1:*:*:*:*:*:*:*",
                            }
                        ]
                    }
                ]
            }
        ]
    if score is not None:
        cvss_data = {"baseScore": score, "vectorString": "CVSS:3.1/test"}
        if severity is not None:
            cvss_data["baseSeverity"] = severity
        cve["metrics"] = {"cvssMetricV31": [{"cvssData": cvss_data}]}
    return {"cve": cve}


def test_cvss_candidates_keep_graph_evidence_and_missing_baselines_unavailable():
    records = [
        _record("CVE-2024-0001", score=8.8, severity="HIGH"),
        _record("CVE-2024-0002", score=9.1, severity="CRITICAL"),
    ]
    features = pd.DataFrame([["CVE-2024-0001", 0.25, 0.5, 0.125]], columns=FEATURE_COLUMNS)
    exclusions = pd.DataFrame(columns=["cve_id", "reason", "detail"])

    candidates, edges, counts = analyze_records(
        records,
        features,
        exclusions,
        {"CVE-2024-0001", "CVE-2024-0002"},
        pd.Timestamp("2024-12-31").date(),
    )

    row = candidates.iloc[0]
    assert row["pagerank"] == pytest.approx(0.125)
    assert row["graph_feature_status"] == "available"
    assert pd.isna(row["epss_score"])
    assert row["epss_status"] == "unavailable_source_not_present"
    assert row["kev_status"] == "unavailable_source_not_present"
    unavailable = candidates.loc[candidates.cve_id == "CVE-2024-0002"].iloc[0]
    assert unavailable["graph_feature_status"] == "feature_row_missing"
    assert pd.isna(unavailable["pagerank"])
    assert len(edges) == 1
    assert edges.iloc[0]["cve_count"] == 1
    assert counts["cvss_high_critical_candidates"] == 2


def test_missing_cvss_or_severity_is_not_imputed_or_selected():
    records = [
        _record("CVE-2024-0001", score=None, severity=None),
        _record("CVE-2024-0002", score=9.8, severity=None),
    ]
    features = pd.DataFrame(columns=FEATURE_COLUMNS)
    exclusions = pd.DataFrame(columns=["cve_id", "reason", "detail"])

    candidates, edges, counts = analyze_records(
        records,
        features,
        exclusions,
        {"CVE-2024-0001", "CVE-2024-0002"},
        pd.Timestamp("2024-12-31").date(),
    )

    assert candidates.empty
    assert edges.empty
    assert counts["cvss_unavailable"] == 1
    assert counts["cvss_severity_unavailable"] == 1


def test_cluster_visualization_uses_supplied_edges_and_handles_empty_input(tmp_path):
    edges = pd.DataFrame(
        [
            {
                "product": "example/widget",
                "cwe_id": "CWE-79",
                "cve_count": 2,
                "cve_ids": '["CVE-1","CVE-2"]',
            },
            {
                "product": "example/widget",
                "cwe_id": "CWE-89",
                "cve_count": 1,
                "cve_ids": '["CVE-3"]',
            },
        ]
    )
    graph = build_cluster_graph(edges)
    assert isinstance(graph, nx.Graph)
    assert graph.number_of_edges() == 2
    assert graph["product:example/widget"]["cwe:CWE-79"]["cve_count"] == 2
    matrix = build_cluster_matrix(edges)
    assert matrix.loc["example/widget", "CWE-79"] == 2

    empty_graph = build_cluster_graph(pd.DataFrame(columns=["product", "cwe_id", "cve_count"]))
    assert empty_graph.number_of_nodes() == 0
    image_path = tmp_path / "clusters.png"
    render_cluster_visualization(edges, image_path)
    assert image_path.is_file()
