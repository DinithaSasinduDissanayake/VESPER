from datetime import UTC, date, datetime
from pathlib import Path

import pandas as pd
import pytest

from vesper.components.c_graph.feature_provider import (
    FEATURE_PROVIDER_COLUMNS,
    build_feature_provider,
)
from vesper.components.c_graph.score_export import SCORE_COLUMNS
from vesper.components.c_graph.scoring import FEATURE_COLUMNS
from vesper.components.c_graph.structural_disagreement import (
    analyze_disagreement,
    annotate_kev,
    build_real_scores,
    concentrations,
    enrichment,
    percentile,
    ranked_candidates,
    sensitivity,
)
from vesper.contracts.score import Component, Score, ScoreKind, ScoreStatus

AT = datetime(2026, 10, 15, tzinfo=UTC)
IDS = [f"CVE-2024-{1000 + i}" for i in range(6)]


@pytest.fixture
def inputs():
    features = pd.DataFrame(
        [
            [IDS[0], 0.1, 0.1, 0.08],
            [IDS[1], 0.3, 0.1, 0.04],
            [IDS[2], 0.3, 0.1, 0.04],
            [IDS[3], 0.1, 0.1, 0.01],
            [IDS[4], 0.2, 0.1, 0.03],
        ],
        columns=FEATURE_COLUMNS,
    )
    scores = pd.DataFrame(
        [
            [
                cve,
                "c_graph",
                AT.isoformat(),
                30,
                features.iloc[i].pagerank if i < 5 else None,
                "ranking_score",
                "available" if i < 5 else "not_eligible",
                None if i < 5 else "Rejected",
                "c_graph-pagerank-structural-0.1",
                None,
                "2026-10-15",
            ]
            for i, cve in enumerate(IDS)
        ],
        columns=SCORE_COLUMNS,
    )
    evidence = {
        cve: {
            "published_at": "2024-01-01T00:00:00Z",
            "last_modified_at": "2024-01-02T00:00:00Z",
            "vendor_product_pairs": (("vendor", "product"),) if i < 5 else (),
            "cwe_ids": ("CWE-79",) if i not in {3, 5} else (),
            "nvd_status": "Analyzed" if i < 5 else "Rejected",
            "source_nvd_file": "nvd_2024-01.json.gz",
        }
        for i, cve in enumerate(IDS)
    }
    provider = build_feature_provider(
        features,
        scores,
        target_cve_ids=IDS,
        evidence_by_id=evidence,
        snapshot_at=AT,
        snapshot_id="nvd-current-snapshot-2026-10-15",
        graph_scope_id="nvd-current-snapshot-2026-10-15-graph-test",
    )
    meta = {
        "reference_timestamp": AT.isoformat(),
        "snapshot_id": "nvd-current-snapshot-2026-10-15",
        "graph_scope_id": "nvd-current-snapshot-2026-10-15-graph-test",
        "feature_schema_version": "1.0.0",
        "horizon_days": 30,
        "historical_reconstruction": "not_performed",
        "feature_provider_columns": FEATURE_PROVIDER_COLUMNS,
    }
    cvss = pd.DataFrame(
        {
            "cve_id": IDS,
            "cvss_base_score": [9.0, 2.0, 8.0, 3.0, None, None],
            "cvss_version": ["3.1"] * 6,
            "cvss_severity": ["HIGH"] * 6,
        }
    )
    return provider, meta, cvss


def test_midrank_ties_singleton_and_constant_values():
    assert percentile(pd.Series([1, 1, 3])).tolist() == [0.25, 0.25, 1.0]
    assert percentile(pd.Series([7, 7, 7])).tolist() == [0.5, 0.5, 0.5]
    assert percentile(pd.Series([2])).tolist() == [0.5]
    with pytest.raises(ValueError, match="finite"):
        percentile(pd.Series([1, None]))


def test_common_population_disagreement_degree_and_permutation_invariance(inputs):
    provider, _, cvss = inputs
    result = analyze_disagreement(provider, cvss, graph_nodes=11)
    other = analyze_disagreement(provider.iloc[::-1], cvss.iloc[::-1], graph_nodes=11)
    pd.testing.assert_frame_equal(result, other)
    observed = result.set_index("cve_id")
    assert observed.at[IDS[1], "degree"] == 4
    assert observed.at[IDS[1], "P_degree"] == 0.75
    assert observed.at[IDS[1], "P_pagerank"] == 0.25
    assert observed.at[IDS[1], "P_cvss"] == 0
    assert observed.at[IDS[1], "pagerank_cvss_disagreement"] == 0.25
    assert ranked_candidates(result).iloc[0].cve_id == IDS[1]
    assert observed.at[IDS[1], "P_degree"] == observed.at[IDS[2], "P_degree"]


def test_primary_tie_breaks_by_cve_and_never_by_kev(inputs):
    p, _, c = inputs
    result = analyze_disagreement(p, c, graph_nodes=11)
    result.loc[result.analysis_status.eq("available"), "pagerank_cvss_disagreement"] = 0
    result["kev_catalog_member"] = result.cve_id.eq(IDS[2])
    assert ranked_candidates(result).cve_id.tolist() == IDS[:3]


def test_missingness_not_eligibility_and_no_zero_fill(inputs):
    p, _, c = inputs
    result = analyze_disagreement(p, c, graph_nodes=11).set_index("cve_id")
    assert result.at[IDS[3], "analysis_status"] == "unavailable"
    assert result.at[IDS[4], "analysis_reason"] == "no_compatible_current_cvss_score"
    assert result.at[IDS[5], "analysis_status"] == "not_eligible"
    assert result.loc[IDS[3:], ["degree", "P_cvss", "P_pagerank"]].isna().all().all()
    assert pd.isna(result.at[IDS[5], "structural_score"])
    assert result.at[IDS[3], "structural_score"] == 0.01  # Real adapter score is separate.


def test_cvss_zero_is_observed_and_missing_cvss_does_not_change_adapter(inputs):
    p, m, c = inputs
    before = build_real_scores(p, m)
    c.loc[1, "cvss_base_score"] = 0
    result = analyze_disagreement(p, c, graph_nodes=11)
    assert result.set_index("cve_id").at[IDS[1], "analysis_status"] == "available"
    pd.testing.assert_frame_equal(before, build_real_scores(p, m))


def test_fixed_threshold_boundaries_and_set_overlap():
    data = pd.DataFrame(
        {
            "cve_id": IDS,
            "analysis_status": ["available"] * 6,
            "P_degree": [0.90, 0.75, 0.75, 0.90, 0.74, 0.90],
            "P_pagerank": [0.90, 0.75, 0.75, 0.90, 0.74, 0.90],
            "P_cvss": [0.49, 0.249, 0.25, 0.50, 0.1, 0.1],
        }
    )
    counts, overlap, sets = sensitivity(data)
    assert sets["degree_A"] == {IDS[0], IDS[5]}
    assert sets["degree_B"] == {IDS[0], IDS[1], IDS[2], IDS[5]}
    assert sets["degree_C"] == {IDS[1], IDS[5]}
    assert sets["degree_A"] <= sets["degree_B"]
    assert sets["degree_C"] <= sets["degree_B"]
    row = overlap[(overlap.left == "degree_A") & (overlap.right == "degree_B")].iloc[0]
    assert row.jaccard == 0.5
    assert counts.candidate_count.tolist() == [2, 4, 2, 2, 4, 2]


def catalog(cve):
    return {
        "dateReleased": "2026-10-15T17:00:00Z",
        "count": 1,
        "vulnerabilities": [{"cveID": cve, "dateAdded": "2026-01-01"}],
    }


def test_kev_is_only_post_selection_annotation_and_enrichment(inputs):
    p, m, c = inputs
    original = analyze_disagreement(p, c, graph_nodes=11)
    candidate = ranked_candidates(original).head(1).cve_id.tolist()
    first, _ = annotate_kev(original, catalog(IDS[1]))
    second, _ = annotate_kev(original, catalog(IDS[0]))
    pd.testing.assert_frame_equal(first[original.columns], second[original.columns])
    assert ranked_candidates(first).cve_id.tolist() == ranked_candidates(second).cve_id.tolist()
    result = enrichment(first, {"top1": set(candidate)}).iloc[0]
    assert result.candidate_kev_prevalence == 1
    assert result.eligible_population_kev_prevalence == pytest.approx(1 / 3)
    assert result.descriptive_enrichment_ratio == 3
    assert result.interpretation.startswith("CURRENT-SNAPSHOT DESCRIPTIVE")
    assert build_real_scores(p, m).score.iloc[:5].tolist() == [1.0, 0.625, 0.625, 0.0, 0.25]


def test_empty_cohort_enrichment_is_undefined_not_zero(inputs):
    p, _, c = inputs
    data, _ = annotate_kev(analyze_disagreement(p, c, graph_nodes=11), catalog(IDS[1]))
    row = enrichment(data, {"empty": set()}).iloc[0]
    assert pd.isna(row.candidate_kev_prevalence)
    assert pd.isna(row.descriptive_enrichment_ratio)


def test_exact_shared_score_contract_roundtrip_and_structural_bounds(inputs, tmp_path):
    p, m, _ = inputs
    scores = build_real_scores(p, m)
    assert scores.columns.tolist() == SCORE_COLUMNS
    assert scores.loc[scores.status.eq("available"), "score"].between(0, 1).all()
    assert scores.loc[scores.status.ne("available"), "score"].isna().all()
    path = tmp_path / "c_scores.csv"
    scores.to_csv(path, index=False)
    loaded = pd.read_csv(path)
    for row in loaded.to_dict(orient="records"):
        row.update(
            component=Component(row["component"]),
            score_kind=ScoreKind(row["score_kind"]),
            status=ScoreStatus(row["status"]),
            decision_time=datetime.fromisoformat(row["decision_time"]),
            snapshot_date=date.fromisoformat(row["snapshot_date"]),
            trained_through=None,
            reason=None if pd.isna(row["reason"]) else row["reason"],
            score=None if pd.isna(row["score"]) else row["score"],
        )
        actual = Score(**row)
        assert actual.component is Component.C_GRAPH
    assert len(
        loaded.merge(
            p[["cve_id", "decision_time"]], on=["cve_id", "decision_time"], validate="one_to_one"
        )
    ) == len(p)


@pytest.mark.parametrize(
    "field,value",
    [
        ("reference_timestamp", "2026-10-14T00:00:00Z"),
        ("snapshot_id", "another-snapshot"),
        ("graph_scope_id", "another-graph"),
        ("horizon_days", 90),
        ("feature_schema_version", "99"),
        ("historical_reconstruction", "performed"),
    ],
)
def test_snapshot_scope_horizon_mismatch_rejected(inputs, field, value):
    p, m, _ = inputs
    with pytest.raises(ValueError):
        build_real_scores(p, {**m, field: value})


def test_wrong_graph_normalization_and_invalid_cvss_rejected(inputs):
    p, _, c = inputs
    with pytest.raises(ValueError, match="normalization"):
        analyze_disagreement(p, c, graph_nodes=12)
    with pytest.raises(ValueError, match="CVSS"):
        analyze_disagreement(p, c.assign(cvss_base_score=11), graph_nodes=11)


def test_explanations_count_unique_cves_and_preserve_evidence(inputs):
    p, _, c = inputs
    result = analyze_disagreement(p, c, graph_nodes=11)
    rows = concentrations(result, {"top": {IDS[0], IDS[1]}}, "product")
    assert rows.iloc[0].entity == "vendor/product"
    assert rows.iloc[0].cve_count == 2
    assert rows.iloc[0].candidate_share == 1


def test_duplicate_kev_and_post_release_dates_are_rejected(inputs):
    p, _, c = inputs
    data = analyze_disagreement(p, c, graph_nodes=11)
    duplicate = catalog(IDS[0])
    duplicate["vulnerabilities"] *= 2
    duplicate["count"] = 2
    with pytest.raises(ValueError, match="Duplicate"):
        annotate_kev(data, duplicate)
    future = catalog(IDS[0])
    future["vulnerabilities"][0]["dateAdded"] = "2026-10-16"
    with pytest.raises(ValueError, match="post-release"):
        annotate_kev(data, future)


def test_analysis_refuses_existing_output_before_reading_inputs(tmp_path):
    import importlib.util

    script = Path(__file__).resolve().parents[3] / "scripts"
    spec = importlib.util.spec_from_file_location(
        "structural_disagreement_runner", script / "analyze_c_graph_structural_disagreement.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sentinel = tmp_path / "preserved.txt"
    sentinel.write_text("preserve existing work", encoding="utf-8")
    with pytest.raises(FileExistsError):
        module.run(Path("missing.csv"), Path("missing"), Path("missing.json"), tmp_path)
    assert sentinel.read_text(encoding="utf-8") == "preserve existing work"


def test_adapter_percentile_population_ties_monotonicity_and_provider_unchanged(inputs):
    provider, meta, _ = inputs
    original = provider.copy(deep=True)
    scores = build_real_scores(provider, meta)
    assert scores.score.iloc[:5].tolist() == [1.0, 0.625, 0.625, 0.0, 0.25]
    assert pd.isna(scores.score.iloc[5])
    assert scores.model_version.eq("c_graph-pagerank-percentile-structural-0.2").all()
    ordered = scores.merge(provider[["cve_id", "pagerank"]], on="cve_id")
    assert ordered.dropna(subset=["score"]).sort_values("pagerank").score.is_monotonic_increasing
    pd.testing.assert_frame_equal(provider, original)
    pd.testing.assert_frame_equal(scores, build_real_scores(provider.iloc[::-1], meta))
