from datetime import UTC, datetime

import pandas as pd
import pytest

from vesper.components.c_graph.score_export import (
    SCORE_COLUMNS,
    build_graph_scores,
    export_graph_scores,
)
from vesper.contracts.score import Component, Score, ScoreKind, ScoreStatus

AT = datetime(2025, 3, 4, 12, tzinfo=UTC)
FEATURES = pd.DataFrame(
    [["CVE-2024-1234", 0.2, 0.4, 0.125]],
    columns=["cve_id", "in_degree_centrality", "out_degree_centrality", "pagerank"],
)


def test_build_scores_maps_pagerank_and_abstains_for_missing():
    scores = build_graph_scores(
        FEATURES, ["CVE-2024-1234", "CVE-2024-2345"], snapshot_at=AT, horizon_days=30
    )
    assert all(isinstance(score, Score) for score in scores)
    assert scores[0].score == 0.125
    assert scores[0].component is Component.C_GRAPH
    assert scores[0].score_kind is ScoreKind.RANKING_SCORE
    assert scores[0].status is ScoreStatus.AVAILABLE
    assert scores[0].trained_through is None
    assert scores[1].score is None
    assert scores[1].status is ScoreStatus.ABSTAINED
    assert scores[1].reason


def test_snapshot_is_normalized_to_utc():
    local = datetime.fromisoformat("2025-03-04T17:30:00+05:30")
    score = build_graph_scores(FEATURES, ["CVE-2024-1234"], snapshot_at=local, horizon_days=30)[0]
    assert score.decision_time == AT
    assert score.snapshot_date.isoformat() == "2025-03-04"


def test_known_ineligible_cve_has_contract_status_and_reason():
    scores = build_graph_scores(
        FEATURES,
        ["CVE-2024-1234", "CVE-2024-2345"],
        snapshot_at=AT,
        horizon_days=30,
        not_eligible_reasons={"CVE-2024-2345": "NVD marks this CVE as Rejected."},
    )
    assert scores[1].status is ScoreStatus.NOT_ELIGIBLE
    assert scores[1].score is None
    assert scores[1].reason == "NVD marks this CVE as Rejected."


def test_ineligible_cve_cannot_also_have_feature_row():
    with pytest.raises(ValueError, match="must not have feature rows"):
        build_graph_scores(
            FEATURES,
            ["CVE-2024-1234"],
            snapshot_at=AT,
            horizon_days=30,
            not_eligible_reasons={"CVE-2024-1234": "Rejected"},
        )


@pytest.mark.parametrize("horizon", [0, -1, 1.5, True])
def test_horizon_must_be_positive_integer(horizon):
    with pytest.raises(ValueError, match="horizon_days"):
        build_graph_scores(FEATURES, [], snapshot_at=AT, horizon_days=horizon)


@pytest.mark.parametrize(
    "table",
    [
        pd.concat([FEATURES, FEATURES]),
        FEATURES.assign(pagerank=float("nan")),
        FEATURES.assign(pagerank=1.1),
        FEATURES.assign(cve_id="CVE-2020-0001"),
    ],
)
def test_rejects_duplicate_invalid_or_out_of_population_features(table):
    with pytest.raises(ValueError):
        build_graph_scores(table, ["CVE-2024-1234"], snapshot_at=AT, horizon_days=30)


def test_export_writes_contract_schema_and_metadata(tmp_path):
    output = tmp_path / "scores.csv"
    scores = export_graph_scores(
        FEATURES,
        ["CVE-2024-1234", "CVE-2024-2345"],
        output,
        snapshot_at=AT,
        horizon_days=30,
        source_features="features.csv",
    )
    result = pd.read_csv(output)
    assert result.columns.tolist() == SCORE_COLUMNS
    assert result["cve_id"].is_unique
    assert len(scores) == 2
    metadata = output.with_suffix(".csv.metadata.json").read_text(encoding="utf-8")
    assert '"score_kind": "ranking_score"' in metadata
    assert '"available_count": 1' in metadata
    assert "not a probability" in metadata


def test_rejects_naive_snapshot():
    with pytest.raises(ValueError, match="time zone"):
        build_graph_scores(FEATURES, [], snapshot_at=datetime(2025, 1, 1), horizon_days=30)
