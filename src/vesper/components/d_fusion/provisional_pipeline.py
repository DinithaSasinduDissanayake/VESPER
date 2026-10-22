"""Build the current five-signal demo ranking and exploratory historical A/B panel."""

from __future__ import annotations

import argparse
import csv
import json
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

from vesper.components.d_fusion.ensemble import _group_metrics
from vesper.components.d_fusion.ensemble_models import (
    feature_frame,
    fit_gradient_boosting,
    fit_logistic,
    score_gradient_boosting,
    score_logistic,
    score_model,
)
from vesper.config import load_settings

CURRENT_DECISION = "2026-10-01"
CURRENT_AS_OF = "2026-10-15"
HISTORICAL_DATES = ("2025-10-01", "2026-01-01", "2026-04-01")
HISTORICAL_FEATURES = ("epss_score", "cvss_normalized", "score_a", "score_b")
COMPONENT_COLUMNS = (
    "cve_id",
    "component",
    "decision_time",
    "horizon_days",
    "score",
    "score_kind",
    "status",
    "reason",
    "model_version",
    "trained_through",
    "snapshot_date",
)


def _member(zip_file: zipfile.ZipFile, suffix: str) -> str:
    matches = [name for name in zip_file.namelist() if name.endswith(suffix)]
    if len(matches) != 1:
        raise ValueError(f"Expected one {suffix!r} member in A/B archive; found {len(matches)}")
    return matches[0]


def _ab_frames(zip_file: zipfile.ZipFile, decision_date: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    a_name = _member(zip_file, f"a_text_scores_{decision_date}.csv")
    b_name = _member(zip_file, f"b_survival_scores_{decision_date}.csv")
    with zip_file.open(a_name) as source:
        a = pd.read_csv(source, dtype={"cve_id": "string"})
    with zip_file.open(b_name) as source:
        b = pd.read_csv(source, dtype={"cve_id": "string"})
    for label, frame in (("A", a), ("B", b)):
        missing = set(COMPONENT_COLUMNS).difference(frame.columns)
        if missing:
            raise ValueError(
                f"Component {label} {decision_date} is missing columns {sorted(missing)}"
            )
        frame["cve_id"] = frame["cve_id"].astype("string").str.strip().str.upper()
        if frame["cve_id"].isna().any():
            raise ValueError(f"Component {label} has an empty CVE ID")
    if a["cve_id"].duplicated().any():
        raise ValueError(f"Component A has duplicate CVEs on {decision_date}")
    b = b.loc[pd.to_numeric(b["horizon_days"], errors="coerce").eq(30)].copy()
    if b["cve_id"].duplicated().any():
        raise ValueError(f"Component B has duplicate 30-day CVEs on {decision_date}")
    return a, b


def _rename_component(frame: pd.DataFrame, suffix: str) -> pd.DataFrame:
    rename = {
        "component": f"component_{suffix}",
        "decision_time": f"decision_time_{suffix}",
        "horizon_days": f"horizon_days_{suffix}",
        "score": f"score_{suffix}",
        "score_kind": f"score_kind_{suffix}",
        "status": f"status_{suffix}",
        "reason": f"reason_{suffix}",
        "model_version": f"model_version_{suffix}",
        "trained_through": f"trained_through_{suffix}",
        "snapshot_date": f"snapshot_date_{suffix}",
    }
    return frame[list(rename) + ["cve_id"]].rename(columns=rename)


def _percentile_score(values: pd.Series) -> pd.Series:
    numeric = pd.to_numeric(values, errors="coerce")
    count = int(numeric.notna().sum())
    if count == 0:
        return pd.Series(np.nan, index=values.index, dtype=float)
    if count == 1:
        return numeric.notna().astype(float)
    ranks = numeric.rank(method="average", ascending=True)
    return ((ranks - 1.0) / (count - 1.0)).where(numeric.notna())


def _estimated_patch_hours(cvss: pd.Series) -> tuple[pd.Series, pd.Series, pd.Series]:
    score = pd.to_numeric(cvss, errors="coerce")
    hours = pd.Series(np.nan, index=score.index, dtype=float)
    tier = pd.Series(pd.NA, index=score.index, dtype="string")
    bands = (
        (0.1, 4.0, "Low", 2.0),
        (4.0, 7.0, "Medium", 4.0),
        (7.0, 9.0, "High", 8.0),
        (9.0, 10.1, "Critical", 16.0),
    )
    for lower, upper, name, estimate in bands:
        selected = score.ge(lower) & score.lt(upper)
        hours.loc[selected] = estimate
        tier.loc[selected] = name
    kind = pd.Series(
        "CVSS severity tier heuristic; estimated, not measured",
        index=score.index,
        dtype="string",
    ).where(hours.notna(), "missing CVSS; effort estimate unavailable")
    return hours, tier, kind


def build_current_fused_dataset(
    ab_archive: Path,
    current_baseline_csv: Path,
    current_c_csv: Path,
) -> tuple[pd.DataFrame, dict[str, object]]:
    """Join latest supplied A/B outputs with current C and CVSS/EPSS values."""

    with zipfile.ZipFile(ab_archive) as archive:
        a, b = _ab_frames(archive, CURRENT_DECISION)
    baseline_columns = [
        "cve_id",
        "cvss_base_score",
        "cvss_version",
        "cvss_vector",
        "epss_score",
        "percentile",
        "epss_date",
        "epss_model_version",
    ]
    if current_baseline_csv.suffix.lower() == ".parquet":
        baseline = pd.read_parquet(current_baseline_csv)
        if "baseline_snapshot_date" not in baseline and "snapshot_date" in baseline:
            baseline = baseline.rename(columns={"snapshot_date": "baseline_snapshot_date"})
        baseline = baseline[baseline_columns + ["baseline_snapshot_date"]]
    else:
        baseline = pd.read_csv(
            current_baseline_csv,
            usecols=baseline_columns + ["baseline_snapshot_date"],
            dtype={"cve_id": "string"},
        )
    c = pd.read_csv(current_c_csv, dtype={"cve_id": "string"})
    if not set(COMPONENT_COLUMNS).issubset(c.columns):
        raise ValueError("Current Component C file does not match the shared Score contract")
    for name, frame in (("CVSS/EPSS", baseline), ("current C", c)):
        frame["cve_id"] = frame["cve_id"].astype("string").str.strip().str.upper()
        if frame["cve_id"].duplicated().any():
            raise ValueError(f"{name} contains duplicate CVE IDs")

    a = _rename_component(a, "a")
    b = _rename_component(b, "b")
    c = _rename_component(c, "c")
    shared_ab = a.merge(b, on="cve_id", how="inner", validate="one_to_one")
    result = shared_ab.merge(baseline, on="cve_id", how="inner", validate="one_to_one")
    result = result.merge(c, on="cve_id", how="inner", validate="one_to_one")
    if result.empty:
        raise ValueError("The latest A/B, current C, and CVSS/EPSS sources have no shared CVEs")

    result["cvss_normalized"] = pd.to_numeric(result["cvss_base_score"], errors="coerce") / 10.0
    result["epss_score"] = pd.to_numeric(result["epss_score"], errors="coerce")
    for column in ("score_a", "score_b", "score_c"):
        result[column] = pd.to_numeric(result[column], errors="coerce")
        available = result[f"status_{column[-1]}"] == "available"
        if result.loc[available, column].isna().any():
            raise ValueError(f"{column} is blank for a row marked available")
        if not result.loc[available, column].between(0.0, 1.0).all():
            raise ValueError(f"{column} must be in [0, 1]")

    source_columns = {
        "score_a": "rankpct_a",
        "score_b": "rankpct_b",
        "score_c": "rankpct_c",
        "cvss_normalized": "rankpct_cvss",
        "epss_score": "rankpct_epss",
    }
    for source, target in source_columns.items():
        result[target] = _percentile_score(result[source])
    normalized = result[list(source_columns.values())]
    result["signals_used"] = normalized.notna().sum(axis=1)
    result["signal_coverage"] = result["signals_used"] / len(source_columns)
    result["fusion_score"] = normalized.mean(axis=1)
    result["risk_score"] = result["fusion_score"]
    result["fusion_method"] = "within_cohort_percentile_equal_weight_available_signals_v1"
    result["ranking_model"] = "normalized_equal_weight_composite"
    result["model_selection_status"] = "provisional_not_trained_or_validated"
    result["data_origin"] = "first_version_component_outputs_mixed_snapshot"
    result["data_as_of"] = CURRENT_AS_OF
    result["decision_time"] = f"{CURRENT_AS_OF}T00:00:00Z"
    result["horizon_days"] = 30
    result["patch_hours"], result["patch_severity_tier"], result["patch_hours_method"] = (
        _estimated_patch_hours(result["cvss_base_score"])
    )
    result["patch_hours_ownership"] = (
        "Component D demo heuristic; replace with measured organizational effort"
    )
    result = result.sort_values(["risk_score", "cve_id"], ascending=[False, True], kind="stable")
    result["risk_rank"] = np.arange(1, len(result) + 1)
    result = result.reset_index(drop=True)

    metadata: dict[str, object] = {
        "ranking_model": "normalized_equal_weight_composite",
        "model_selection_status": "provisional_not_trained_or_validated",
        "fusion_method": result["fusion_method"].iloc[0],
        "data_as_of": CURRENT_AS_OF,
        "candidate_count": len(result),
        "unique_cves": int(result["cve_id"].nunique()),
        "source_snapshot_dates": {
            "component_a_snapshot": sorted(result["snapshot_date_a"].dropna().unique().tolist()),
            "component_a_decision": sorted(result["decision_time_a"].dropna().unique().tolist()),
            "component_b_snapshot": sorted(result["snapshot_date_b"].dropna().unique().tolist()),
            "component_b_decision": sorted(result["decision_time_b"].dropna().unique().tolist()),
            "component_c_snapshot": sorted(result["snapshot_date_c"].dropna().unique().tolist()),
            "cvss_snapshot": sorted(result["baseline_snapshot_date"].dropna().unique().tolist()),
            "epss_snapshot": sorted(result["epss_date"].dropna().unique().tolist()),
        },
        "score_availability": {
            column: int(result[column].notna().sum())
            for column in ("score_a", "score_b", "score_c", "cvss_normalized", "epss_score")
        },
        "status_counts": {
            column: result[column].value_counts(dropna=False).astype(int).to_dict()
            for column in ("status_a", "status_b", "status_c")
        },
        "missing_scores_are_excluded_from_mean": True,
        "normalization": (
            "Average within-cohort percentile rank across available signals; ties use average rank."
        ),
        "research_caveats": [
            (
                "Component snapshots are mixed from 2026-10-01 through 2026-10-15; "
                "this is not a strict common-time snapshot."
            ),
            (
                "A uses a later NVD text snapshot than its historical decision_time, "
                "as documented in the handoff."
            ),
            "B score is a ranking score and is not a calibrated probability.",
            (
                "CVSS, EPSS, exploit timing, and graph structural importance represent "
                "different concepts; equal weights are a transparent demo heuristic."
            ),
            "Patch hours are a CVSS severity-tier heuristic, not measured remediation effort.",
        ],
    }
    return result, metadata


def _historical_ab_keys(ab_archive: Path) -> tuple[dict[str, set[str]], dict[str, pd.DataFrame]]:
    ids_by_date: dict[str, set[str]] = {}
    frames: dict[str, pd.DataFrame] = {}
    with zipfile.ZipFile(ab_archive) as archive:
        for decision_date in HISTORICAL_DATES:
            a, b = _ab_frames(archive, decision_date)
            common = set(a["cve_id"]) & set(b["cve_id"])
            ids_by_date[decision_date] = common
            merged = _rename_component(a, "a").merge(
                _rename_component(b, "b"), on="cve_id", how="inner", validate="one_to_one"
            )
            merged["decision_date"] = decision_date
            frames[decision_date] = merged
    return ids_by_date, frames


def extract_aligned_historical_c(
    ab_archive: Path, c_source: Path, output_path: Path
) -> pd.DataFrame:
    """Keep only C's abstention records matching the mature A/B snapshot keys."""

    if not c_source.is_file():
        raise FileNotFoundError(f"Historical C source CSV not found: {c_source}")
    ids_by_date, _ = _historical_ab_keys(ab_archive)
    wanted = {
        (cve_id, decision_date) for decision_date, ids in ids_by_date.items() for cve_id in ids
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    selected: list[dict[str, str]] = []
    with c_source.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or not set(COMPONENT_COLUMNS).issubset(reader.fieldnames):
            raise ValueError("Historical C file does not match the shared Score contract")
        for row in reader:
            cve_id = (row.get("cve_id") or "").strip().upper()
            decision_date = (row.get("decision_time") or "")[:10]
            if (cve_id, decision_date) in wanted:
                if (row.get("status") or "").strip() != "abstained" or (
                    row.get("score") or ""
                ).strip():
                    raise ValueError("Historical C handoff must preserve blank abstained scores")
                selected.append({column: row.get(column, "") for column in COMPONENT_COLUMNS})
    selected_frame = pd.DataFrame(selected, columns=COMPONENT_COLUMNS)
    if selected_frame.duplicated(["cve_id", "decision_time"]).any():
        raise ValueError("Filtered historical C panel has duplicate CVE/date keys")
    expected = len(wanted)
    if len(selected_frame) != expected:
        raise ValueError(
            f"Historical C matched {len(selected_frame):,} of {expected:,} requested A/B keys"
        )
    selected_frame.to_csv(output_path, index=False)
    return selected_frame


def build_historical_fused_dataset(
    ab_archive: Path,
    c_panel_path: Path,
    historical_labels_path: Path,
) -> tuple[pd.DataFrame, dict[str, object]]:
    """Build a time-aligned four-signal feature panel with C abstention provenance."""

    _, ab_frames = _historical_ab_keys(ab_archive)
    ab = pd.concat(ab_frames.values(), ignore_index=True)
    c = pd.read_csv(c_panel_path, dtype={"cve_id": "string"})
    c["cve_id"] = c["cve_id"].astype("string").str.strip().str.upper()
    c["decision_date"] = pd.to_datetime(c["decision_time"], utc=True).dt.strftime("%Y-%m-%d")
    if c.duplicated(["cve_id", "decision_date"]).any():
        raise ValueError("Historical C handoff has duplicate CVE/date keys")
    c_columns = [
        "cve_id",
        "decision_date",
        "decision_time",
        "horizon_days",
        "score_kind",
        "score",
        "status",
        "reason",
        "trained_through",
        "snapshot_date",
        "model_version",
    ]
    c = c[c_columns].rename(
        columns={
            "score": "score_c",
            "decision_time": "decision_time_c",
            "horizon_days": "horizon_days_c",
            "score_kind": "score_kind_c",
            "status": "status_c",
            "reason": "reason_c",
            "trained_through": "trained_through_c",
            "snapshot_date": "snapshot_date_c",
            "model_version": "model_version_c",
        }
    )
    labels = pd.read_parquet(
        historical_labels_path,
        columns=[
            "cve_id",
            "decision_time",
            "label_matured_at",
            "horizon_days",
            "kev_within_horizon",
            "epss_score",
            "epss_date",
            "epss_model_version",
            "cvss_base_score",
            "cvss_version",
            "cvss_vector",
            "cvss_normalized",
        ],
    )
    labels["cve_id"] = labels["cve_id"].astype("string").str.strip().str.upper()
    labels["decision_date"] = pd.to_datetime(labels["decision_time"], utc=True).dt.strftime(
        "%Y-%m-%d"
    )
    labels = labels.loc[
        labels["decision_date"].isin(HISTORICAL_DATES)
        & pd.to_numeric(labels["horizon_days"], errors="coerce").eq(30)
    ].copy()
    joined = ab.merge(labels, on=["cve_id", "decision_date"], how="inner", validate="one_to_one")
    joined = joined.merge(c, on=["cve_id", "decision_date"], how="left", validate="one_to_one")
    if joined["status_c"].isna().any():
        raise ValueError("Some historical A/B rows have no matching C status/provenance row")
    if joined["score_c"].notna().any() or not joined["status_c"].eq("abstained").all():
        raise ValueError("Historical C must remain abstained and excluded as a numeric feature")
    joined["cvss_normalized"] = pd.to_numeric(joined["cvss_normalized"], errors="coerce").fillna(
        pd.to_numeric(joined["cvss_base_score"], errors="coerce") / 10.0
    )
    joined["score_a"] = pd.to_numeric(joined["score_a"], errors="coerce")
    joined["score_b"] = pd.to_numeric(joined["score_b"], errors="coerce")
    joined["score_c"] = np.nan
    joined["data_origin"] = "first_version_historical_ab_cvss_epss_c_abstained"
    joined["feature_set"] = "four_signal_a_b_cvss_epss"
    joined["c_used_as_feature"] = False
    joined["label_matured_at"] = pd.to_datetime(joined["label_matured_at"], utc=True).dt.strftime(
        "%Y-%m-%d"
    )
    expected_maturity = (
        pd.to_datetime(joined["decision_date"], utc=True)
        + pd.to_timedelta(pd.to_numeric(joined["horizon_days"], errors="raise"), unit="D")
    ).dt.strftime("%Y-%m-%d")
    if (joined["label_matured_at"] < expected_maturity).any():
        raise ValueError("A KEV label matured before its 30-day outcome window ended")
    joined["kev_within_horizon"] = pd.to_numeric(
        joined["kev_within_horizon"], errors="raise"
    ).astype(int)
    joined["decision_time"] = joined["decision_date"]
    joined = joined.sort_values(["decision_time", "cve_id"], kind="stable").reset_index(drop=True)
    summary = {
        "rows": len(joined),
        "decision_dates": sorted(joined["decision_time"].unique().tolist()),
        "rows_by_date": joined.groupby("decision_time").size().astype(int).to_dict(),
        "positive_labels_by_date": joined.groupby("decision_time")["kev_within_horizon"]
        .sum()
        .astype(int)
        .to_dict(),
        "rows_with_cvss_and_epss": int(
            joined["cvss_base_score"].notna().mul(joined["epss_score"].notna()).sum()
        ),
        "c_status_counts": joined["status_c"].value_counts().astype(int).to_dict(),
        "c_numeric_scores": int(joined["score_c"].notna().sum()),
        "feature_columns": list(HISTORICAL_FEATURES),
        "label_horizon_days": 30,
        "caveats": [
            "Only three matched A/B/C and CVSS/EPSS historical dates are available.",
            "A's historical score files use 2026-10-11 text snapshots for older decision dates.",
            "B's historical handoff documents current NVD CVSS/CWE values for older scores.",
            (
                "The handoff has only a small number of positive outcomes at each date; "
                "metrics are exploratory."
            ),
            "Component C is retained for provenance only and is not a numerical feature.",
        ],
    }
    return joined, summary


def run_exploratory_historical_experiment(
    panel: pd.DataFrame, output_dir: Path
) -> dict[str, object]:
    """Train two light models on early snapshots and report the last mature date once."""

    data = panel.loc[panel["cvss_normalized"].notna() & panel["epss_score"].notna()].copy()
    dates = sorted(data["decision_time"].unique().tolist())
    if len(dates) != 3:
        raise ValueError(f"Expected three mature historical dates; found {len(dates)}")
    train = data.loc[data["decision_time"].isin(dates[:2])].copy()
    test = data.loc[data["decision_time"].eq(dates[2])].copy()
    train_features = feature_frame(train)
    test_features = feature_frame(test)
    labels = train["kev_within_horizon"].astype(int)
    lr = fit_logistic(train_features, labels, HISTORICAL_FEATURES)
    gb = fit_gradient_boosting(train_features, labels, feature_columns=HISTORICAL_FEATURES)
    predictions = {
        "logistic_regression": score_logistic(test_features, lr),
        "gradient_boosting": score_gradient_boosting(test_features, gb),
        "epss_baseline": score_model("epss", test_features),
        "cvss_baseline": score_model("cvss", test_features),
    }
    metrics: dict[str, dict[str, float]] = {}
    rankings: list[pd.DataFrame] = []
    for name, scores in predictions.items():
        metrics[name] = _group_metrics(test, scores)
        ranked = test[["cve_id", "decision_time", "kev_within_horizon"]].copy()
        ranked["risk_score"] = scores.to_numpy()
        ranked = ranked.sort_values(
            ["risk_score", "cve_id"], ascending=[False, True], kind="stable"
        )
        ranked["risk_rank"] = np.arange(1, len(ranked) + 1)
        ranked["ranking_method"] = name
        rankings.append(ranked)
    output_dir.mkdir(parents=True, exist_ok=True)
    pd.concat(rankings, ignore_index=True).to_csv(
        output_dir / "heldout_test_rankings.csv", index=False
    )
    report: dict[str, object] = {
        "experiment_status": "exploratory_not_final_model_selection",
        "feature_set": "four-signal historically evaluable model (A + B + CVSS + EPSS)",
        "feature_columns": list(HISTORICAL_FEATURES),
        "component_c_feature_used": False,
        "train_dates": dates[:2],
        "test_date": dates[2],
        "train_rows": len(train),
        "test_rows": len(test),
        "train_positives": int(labels.sum()),
        "test_positives": int(test["kev_within_horizon"].sum()),
        "metrics_on_one_heldout_snapshot": metrics,
        "metric_definitions": {
            "average_precision": (
                "Area under the precision-recall curve, computed from ranked labels."
            ),
            "precision_at_20": "Share of the top 20 ranked CVEs that enter KEV within 30 days.",
            "recall_at_20": "Share of test-set KEV positives present in the top 20.",
            "ndcg_at_20": "Discounted gain in the top 20, normalized by ideal ordering.",
        },
        "models": {
            "logistic_regression": {"feature_columns": lr.feature_names, "model": lr.__dict__},
            "gradient_boosting": {"feature_columns": gb.feature_names, "model": gb.__dict__},
        },
        "warning": (
            "One test date with nine KEV positives and no validation date is not "
            "sufficient to select a winner. "
            "Component A/B source documentation also identifies later NVD feature-snapshot leakage."
        ),
    }
    (output_dir / "exploratory_metrics.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    return report


def run_pipeline(
    project_root: Path,
    historical_c_source: Path | None = None,
    include_historical: bool = True,
) -> None:
    archive = project_root / "data/raw/component_a_b/VESPER_A_B_scores_full_historical.zip"
    current_baseline_csv = (
        project_root / "outputs/d_fusion/first_version/fused_first_version_dataset.csv"
    )
    current_baseline_parquet = project_root / "data/processed/d_fusion_baselines.parquet"
    current_baseline = (
        current_baseline_csv if current_baseline_csv.is_file() else current_baseline_parquet
    )
    current_c = project_root / "data/processed/component_c/c_graph_scores.csv"
    current_dir = project_root / "outputs/d_fusion/current_provisional"
    current_dir.mkdir(parents=True, exist_ok=True)
    current, current_report = build_current_fused_dataset(archive, current_baseline, current_c)
    processed_dir = project_root / "data/processed/d_fusion"
    processed_dir.mkdir(parents=True, exist_ok=True)
    current.to_parquet(processed_dir / "current_five_signal_fused.parquet", index=False)
    ranked = current.copy()
    ranked.to_csv(current_dir / "ranked_current_five_signal.csv", index=False)
    (current_dir / "source_and_methodology.json").write_text(
        json.dumps(current_report, indent=2), encoding="utf-8"
    )
    print(f"Current fused rows: {len(current):,}")
    print(f"Current ranking: {current_dir / 'ranked_current_five_signal.csv'}")

    if not include_historical:
        return
    c_panel_path = (
        project_root / "data/processed/component_c/c_graph_historical_scores_ab_panel.csv"
    )
    if not c_panel_path.is_file():
        if historical_c_source is None:
            raise FileNotFoundError(
                "Provide --historical-c-source once to create the compact aligned C "
                "abstention panel."
            )
        c_panel = extract_aligned_historical_c(archive, historical_c_source, c_panel_path)
    else:
        c_panel = pd.read_csv(c_panel_path, dtype={"cve_id": "string"})
    labels_path = project_root / "data/processed/d_fusion/historical_cvss_epss_labeled.parquet"
    historical, historical_report = build_historical_fused_dataset(
        archive, c_panel_path, labels_path
    )
    historical.to_parquet(
        processed_dir / "historical_first_version_four_signal.parquet", index=False
    )
    historical.to_csv(processed_dir / "historical_first_version_four_signal.csv", index=False)
    historical_report["filtered_c_rows"] = len(c_panel)
    (processed_dir / "historical_first_version_summary.json").write_text(
        json.dumps(historical_report, indent=2), encoding="utf-8"
    )
    metrics = run_exploratory_historical_experiment(
        historical, project_root / "outputs/d_fusion/historical_ab_exploratory"
    )
    print(f"Historical four-signal rows: {len(historical):,}")
    print(f"Exploratory held-out metrics: {metrics['metrics_on_one_heldout_snapshot']}")


def main() -> None:
    settings = load_settings()
    parser = argparse.ArgumentParser(
        description="Build the provisional current ranking and historical A/B experiment"
    )
    parser.add_argument(
        "--historical-c-source",
        type=Path,
        default=Path(r"D:\Downloads\c_graph_historical_scores.csv"),
        help="Original abstention-only C panel; it is reduced to A/B matched keys locally.",
    )
    parser.add_argument("--skip-historical", action="store_true")
    args = parser.parse_args()
    run_pipeline(settings.project_root, args.historical_c_source, not args.skip_historical)


if __name__ == "__main__":
    main()
