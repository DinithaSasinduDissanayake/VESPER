"""Tests for Component C graph-derived features."""

from datetime import UTC, date, datetime

from vesper.components.c_graph.graph import build_graph
from vesper.components.c_graph.scoring import calculate_graph_features
from vesper.contracts.vulnerability import Vulnerability


def make_vulnerability(
    cve_id: str,
    affected: tuple[tuple[str, str], ...] = (("examplevendor", "exampleproduct"),),
    cwe_ids: tuple[str, ...] = ("CWE-79",),
) -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        published_at=datetime(2024, 1, 10, tzinfo=UTC),
        last_modified_at=datetime(2024, 1, 15, tzinfo=UTC),
        description="Example vulnerability",
        cvss_base_score=7.5,
        cvss_version="3.1",
        cvss_vector=None,
        cwe_ids=cwe_ids,
        affected=affected,
        nvd_status="Analyzed",
        snapshot_date=date(2024, 1, 31),
    )


def test_returns_one_row_per_cve():
    graph = build_graph(
        [
            make_vulnerability("CVE-2024-12345"),
            make_vulnerability("CVE-2024-12346"),
        ]
    )

    features = calculate_graph_features(graph)

    assert list(features.columns) == [
        "cve_id",
        "in_degree_centrality",
        "out_degree_centrality",
        "pagerank",
    ]
    assert set(features["cve_id"]) == {"CVE-2024-12345", "CVE-2024-12346"}
    assert len(features) == 2


def test_feature_values_are_finite_and_non_negative():
    graph = build_graph([make_vulnerability("CVE-2024-12345")])

    features = calculate_graph_features(graph)

    numeric = features[["in_degree_centrality", "out_degree_centrality", "pagerank"]]
    assert numeric.notna().all().all()
    assert (numeric >= 0).all().all()


def test_cve_without_relationships_has_zero_centrality():
    graph = build_graph(
        [
            make_vulnerability(
                "CVE-2024-12345",
                affected=(),
                cwe_ids=(),
            )
        ]
    )

    features = calculate_graph_features(graph)
    row = features.iloc[0]

    assert row["in_degree_centrality"] == 0.0
    assert row["out_degree_centrality"] == 0.0


def test_empty_graph_returns_empty_dataframe_with_expected_columns():
    import networkx as nx

    features = calculate_graph_features(nx.DiGraph())

    assert features.empty
    assert list(features.columns) == [
        "cve_id",
        "in_degree_centrality",
        "out_degree_centrality",
        "pagerank",
    ]


def test_features_are_sorted_by_cve_id():
    graph = build_graph(
        [
            make_vulnerability("CVE-2024-12346"),
            make_vulnerability("CVE-2024-12345"),
        ]
    )

    features = calculate_graph_features(graph)

    assert features["cve_id"].tolist() == [
        "CVE-2024-12345",
        "CVE-2024-12346",
    ]


def test_symmetric_three_cve_cycle_has_hand_calculated_centralities():
    import networkx as nx
    import pytest

    cve_ids = ["CVE-2024-12345", "CVE-2024-12346", "CVE-2024-12347"]
    graph = nx.DiGraph()
    nodes = [f"cve:{cve_id}" for cve_id in cve_ids]
    for cve_id, node in zip(cve_ids, nodes, strict=True):
        graph.add_node(node, node_type="cve", cve_id=cve_id)
    graph.add_edges_from((nodes[index], nodes[(index + 1) % 3]) for index in range(3))

    features = calculate_graph_features(graph).set_index("cve_id")

    for cve_id in cve_ids:
        assert features.loc[cve_id, "in_degree_centrality"] == pytest.approx(0.5)
        assert features.loc[cve_id, "out_degree_centrality"] == pytest.approx(0.5)
        assert features.loc[cve_id, "pagerank"] == pytest.approx(1 / 3)
