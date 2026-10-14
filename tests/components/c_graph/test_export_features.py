
"""Tests for Component C graph feature exports."""

import pandas as pd
import networkx as nx

from vesper.components.c_graph.export_features import export_features_to_csv
from vesper.components.c_graph.graph import build_graph
from vesper.contracts.vulnerability import Vulnerability

from datetime import date, datetime, timezone


def make_vulnerability() -> Vulnerability:
    return Vulnerability(
        cve_id="CVE-2024-12345",
        published_at=datetime(2024, 1, 10, tzinfo=timezone.utc),
        last_modified_at=datetime(2024, 1, 15, tzinfo=timezone.utc),
        description="Example vulnerability",
        cvss_base_score=7.5,
        cvss_version="3.1",
        cvss_vector=None,
        cwe_ids=("CWE-79",),
        affected=(("examplevendor", "exampleproduct"),),
        nvd_status="Analyzed",
        snapshot_date=date(2024, 1, 31),
    )


def test_exports_features_to_csv(tmp_path):
    graph = build_graph([make_vulnerability()])
    output_path = tmp_path / "features.csv"

    returned_path = export_features_to_csv(graph, output_path)

    assert returned_path == output_path
    assert output_path.exists()

    result = pd.read_csv(output_path)
    assert result["cve_id"].tolist() == ["CVE-2024-12345"]
    assert list(result.columns) == [
        "cve_id",
        "in_degree_centrality",
        "out_degree_centrality",
        "pagerank",
    ]


def test_exports_empty_graph_with_headers(tmp_path):
    output_path = tmp_path / "empty" / "features.csv"

    export_features_to_csv(nx.DiGraph(), output_path)

    result = pd.read_csv(output_path)
    assert result.empty
    assert list(result.columns) == [
        "cve_id",
        "in_degree_centrality",
        "out_degree_centrality",
        "pagerank",
    ]


def test_replaces_existing_output_atomically(tmp_path):
    graph = build_graph([make_vulnerability()])
    output_path = tmp_path / "features.csv"
    output_path.write_text("old,data\n1,2\n", encoding="utf-8")

    export_features_to_csv(graph, output_path)

    result = pd.read_csv(output_path)
    assert result["cve_id"].tolist() == ["CVE-2024-12345"]
    assert not output_path.with_suffix(".csv.tmp").exists()
