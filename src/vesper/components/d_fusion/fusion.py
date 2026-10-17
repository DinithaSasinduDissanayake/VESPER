"""Fuse the current CVSS/EPSS baselines with synthetic A/B/C score inputs."""

import argparse
from pathlib import Path

import pandas as pd

from vesper.config import load_settings

COMPONENT_FILES = {
    "a": "a_text_scores.csv",
    "b": "b_exploit_timing_scores.csv",
    "c": "c_graph_scores.csv",
}
FUSION_METHOD = "equal_weight_mean_available_inputs_v1"
SCORE_COLUMNS = (
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


def _read_component(path: Path, component: str) -> pd.DataFrame:
    frame = pd.read_csv(path, dtype={"cve_id": "string"})
    missing = set(SCORE_COLUMNS).difference(frame.columns)
    if missing:
        raise ValueError(f"{path.name} is missing Score columns: {sorted(missing)}")
    if frame["cve_id"].isna().any() or frame["cve_id"].duplicated().any():
        raise ValueError(f"{path.name} must have one non-empty row per CVE ID")
    if set(frame["component"].dropna()) != {component}:
        raise ValueError(f"{path.name} must contain only component {component!r}")
    if set(frame["score_kind"].dropna()) != {"ranking_score"}:
        raise ValueError(f"{path.name} must use ranking_score values")

    frame["score"] = pd.to_numeric(frame["score"], errors="raise")
    available = frame["status"] == "available"
    if frame.loc[available, "score"].isna().any():
        raise ValueError(f"Available scores in {path.name} cannot be empty")
    if frame.loc[~available, "score"].notna().any():
        raise ValueError(f"Unavailable scores in {path.name} must be empty")
    if not frame.loc[available, "score"].between(0.0, 1.0).all():
        raise ValueError(f"Available ranking scores in {path.name} must be between 0 and 1")
    if not frame["status"].isin(
        {"available", "abstained", "already_exploited", "not_eligible"}
    ).all():
        raise ValueError(f"{path.name} contains an unknown score status")
    return frame


def build_fused_dummy_dataset(
    baseline_path: Path,
    dummy_dir: Path,
) -> pd.DataFrame:
    """Join the baseline and component scores by CVE ID and calculate an index.

    CVSS is divided by 10 to put its 0-10 base score on a 0-1 scale. EPSS is
    already a 0-1 probability. The three synthetic component scores are
    expected to be 0-1 ranking scores. The fusion index is the arithmetic mean
    of the available normalized inputs; unavailable inputs are omitted and
    signal coverage is reported separately.
    """

    if not baseline_path.is_file():
        raise FileNotFoundError(f"CVSS/EPSS baseline not found: {baseline_path}")
    baseline = pd.read_parquet(baseline_path)
    baseline_columns = {
        "cve_id",
        "snapshot_date",
        "cvss_base_score",
        "cvss_version",
        "cvss_vector",
        "epss_score",
        "percentile",
        "epss_date",
        "epss_model_version",
    }
    missing = baseline_columns.difference(baseline.columns)
    if missing:
        raise ValueError(f"CVSS/EPSS baseline is missing columns: {sorted(missing)}")
    if baseline["cve_id"].duplicated().any():
        raise ValueError("CVSS/EPSS baseline must have one row per CVE ID")
    baseline["cve_id"] = baseline["cve_id"].astype("string")

    components = {
        key: _read_component(dummy_dir / filename, f"{key}_" + {
            "a": "text",
            "b": "survival",
            "c": "graph",
        }[key])
        for key, filename in COMPONENT_FILES.items()
    }
    reference = (
        components["a"][
            ["cve_id", "decision_time", "horizon_days", "snapshot_date"]
        ]
        .sort_values("cve_id", kind="stable")
        .reset_index(drop=True)
    )
    for key, frame in components.items():
        context = (
            frame[["cve_id", "decision_time", "horizon_days", "snapshot_date"]]
            .sort_values("cve_id", kind="stable")
            .reset_index(drop=True)
        )
        if not context.equals(reference):
            raise ValueError(f"Component {key.upper()} rows do not share the same decision context")

    cve_ids = set().union(*(set(frame["cve_id"]) for frame in components.values()))
    missing_baseline = cve_ids.difference(set(baseline["cve_id"]))
    if missing_baseline:
        raise ValueError(
            "Component CVE IDs are missing from the CVSS/EPSS baseline: "
            f"{sorted(missing_baseline)}"
        )
    result = baseline.loc[baseline["cve_id"].isin(cve_ids)].copy()

    for key, frame in components.items():
        columns = frame[["cve_id", "score", "status", "reason", "model_version"]].rename(
            columns={
                "score": f"score_{key}",
                "status": f"status_{key}",
                "reason": f"reason_{key}",
                "model_version": f"model_version_{key}",
            }
        )
        result = result.merge(columns, on="cve_id", how="left", validate="one_to_one")

    result["cvss_normalized"] = pd.to_numeric(
        result["cvss_base_score"], errors="coerce"
    ).div(10.0).round(6)
    result["epss_score"] = pd.to_numeric(result["epss_score"], errors="coerce")
    if not result["cvss_normalized"].dropna().between(0.0, 1.0).all():
        raise ValueError("CVSS base scores must be between 0 and 10")
    if not result["epss_score"].dropna().between(0.0, 1.0).all():
        raise ValueError("EPSS scores must be between 0 and 1")

    signals = pd.DataFrame(
        {
            "cvss_normalized": result["cvss_normalized"],
            "epss_score": result["epss_score"],
            "score_a": result["score_a"],
            "score_b": result["score_b"],
            "score_c": result["score_c"],
        }
    )
    result["signals_used"] = signals.notna().sum(axis=1)
    result["signal_coverage"] = result["signals_used"] / len(signals.columns)
    result["fusion_score"] = signals.mean(axis=1).round(6)
    result["fusion_method"] = FUSION_METHOD
    result["data_origin"] = "synthetic"
    result["decision_time"] = reference["decision_time"].iloc[0]
    result["horizon_days"] = int(reference["horizon_days"].iloc[0])

    output_columns = [
        "cve_id",
        "decision_time",
        "horizon_days",
        "snapshot_date",
        "epss_date",
        "epss_model_version",
        "cvss_base_score",
        "cvss_version",
        "cvss_vector",
        "epss_score",
        "percentile",
        "score_a",
        "status_a",
        "reason_a",
        "model_version_a",
        "score_b",
        "status_b",
        "reason_b",
        "model_version_b",
        "score_c",
        "status_c",
        "reason_c",
        "model_version_c",
        "cvss_normalized",
        "fusion_score",
        "signals_used",
        "signal_coverage",
        "fusion_method",
        "data_origin",
    ]
    return result[output_columns].sort_values("cve_id", kind="stable").reset_index(drop=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fuse the CVSS/EPSS baseline with A/B/C synthetic score inputs"
    )
    parser.parse_args()

    settings = load_settings()
    module_dir = Path(__file__).resolve().parent
    dummy_dir = module_dir / "dummy_inputs"
    baseline_path = settings.data_processed / "d_fusion_baselines.parquet"
    output_path = dummy_dir / "fused_dummy_dataset.csv"
    result = build_fused_dummy_dataset(baseline_path, dummy_dir)
    result.to_csv(output_path, index=False)
    print(f"Saved {len(result)} CVEs to {output_path}")
    print(f"Fusion method: {FUSION_METHOD}")
    print(f"Rows with all five signals: {(result['signals_used'] == 5).sum()}")
    print(f"Rows with fewer than five signals: {(result['signals_used'] < 5).sum()}")


if __name__ == "__main__":
    main()
