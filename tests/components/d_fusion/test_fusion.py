from datetime import date

import pandas as pd

from vesper.components.d_fusion.fusion import build_fused_dummy_dataset

CVE_IDS = ("CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003")
DECISION_TIME = "2026-10-11T23:59:59+00:00"
SNAPSHOT_DATE = "2026-10-11"


def _baseline() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "cve_id": CVE_IDS,
            "snapshot_date": [date(2026, 10, 11)] * 3,
            "cvss_base_score": [8.0, 6.0, 10.0],
            "cvss_version": ["3.1"] * 3,
            "cvss_vector": ["CVSS:3.1/test"] * 3,
            "epss_score": [0.2, 0.4, 0.0],
            "percentile": [0.8, 0.7, 0.0],
            "epss_date": [date(2026, 10, 1)] * 3,
            "epss_model_version": ["v5"] * 3,
        }
    )


def _component_scores(component: str, scores: list[float | None]) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "cve_id": CVE_IDS,
            "component": [component] * 3,
            "decision_time": [DECISION_TIME] * 3,
            "horizon_days": [30] * 3,
            "score": scores,
            "score_kind": ["ranking_score"] * 3,
            "status": ["available", "abstained" if scores[1] is None else "available", "available"],
            "reason": [None, "No signal" if scores[1] is None else None, None],
            "model_version": [f"synthetic-{component}-test"] * 3,
            "trained_through": [None] * 3,
            "snapshot_date": [SNAPSHOT_DATE] * 3,
        }
    )


def _write_inputs(tmp_path):
    baseline_path = tmp_path / "baseline.parquet"
    _baseline().to_parquet(baseline_path, index=False)

    dummy_dir = tmp_path / "dummy_inputs"
    dummy_dir.mkdir()
    for component, scores in (
        ("a_text", [0.6, 0.5, 0.0]),
        ("b_survival", [0.4, None, 1.0]),
        ("c_graph", [0.8, 0.5, 1.0]),
    ):
        name = {
            "a_text": "a_text_scores.csv",
            "b_survival": "b_exploit_timing_scores.csv",
            "c_graph": "c_graph_scores.csv",
        }[component]
        _component_scores(component, scores).to_csv(dummy_dir / name, index=False)
    return baseline_path, dummy_dir


def test_build_fused_dummy_dataset_keeps_one_row_per_cve(tmp_path):
    baseline_path, dummy_dir = _write_inputs(tmp_path)

    fused = build_fused_dummy_dataset(baseline_path, dummy_dir)

    assert len(fused) == len(CVE_IDS)
    assert fused["cve_id"].is_unique


def test_fusion_scores_stay_between_zero_and_one(tmp_path):
    baseline_path, dummy_dir = _write_inputs(tmp_path)

    fused = build_fused_dummy_dataset(baseline_path, dummy_dir)

    assert fused["fusion_score"].between(0.0, 1.0).all()


def test_missing_signal_is_omitted_from_mean_not_counted_as_zero(tmp_path):
    baseline_path, dummy_dir = _write_inputs(tmp_path)

    fused = build_fused_dummy_dataset(baseline_path, dummy_dir)

    row = fused.set_index("cve_id").loc["CVE-2023-0002"]
    # (CVSS 0.6 + EPSS 0.4 + A 0.5 + C 0.5) / 4 = 0.5.
    # Treating B's abstention as zero and dividing by five would give 0.4.
    assert pd.isna(row["score_b"])
    assert row["signals_used"] == 4
    assert row["fusion_score"] == 0.5
