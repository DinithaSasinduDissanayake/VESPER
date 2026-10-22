"""Fuse CVSS/EPSS baselines with Component A/B/C score handoffs."""

import argparse
import hashlib
import json
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
    decision_times = pd.to_datetime(frame["decision_time"], utc=True, errors="coerce")
    if decision_times.isna().any():
        raise ValueError(f"{path.name} must have valid decision_time values")
    snapshots = pd.to_datetime(frame["snapshot_date"], utc=True, errors="coerce")
    if snapshots.isna().any():
        raise ValueError(f"{path.name} must have valid snapshot_date values")
    horizons = pd.to_numeric(frame["horizon_days"], errors="coerce")
    if (
        horizons.isna().any()
        or (horizons <= 0).any()
        or (horizons % 1 != 0).any()
    ):
        raise ValueError(f"{path.name} must have positive integer horizon_days values")
    return frame


def _shared_component_context(
    result: pd.DataFrame, keys: tuple[str, ...], field: str
) -> pd.Series:
    """Return one shared snapshot context and reject mixed component metadata."""

    columns = [f"{field}_{key}" for key in keys]
    if field == "decision_time":
        values = pd.concat(
            [pd.to_datetime(result[column], utc=True, errors="coerce") for column in columns],
            axis=1,
        )
    elif field == "snapshot_date":
        values = pd.concat(
            [
                pd.to_datetime(result[column], utc=True, errors="coerce").dt.normalize()
                for column in columns
            ],
            axis=1,
        )
    else:
        values = pd.concat(
            [pd.to_numeric(result[column], errors="coerce") for column in columns],
            axis=1,
        )

    component_values: list[object] = []
    for index, key in enumerate(keys):
        unique_values = values.iloc[:, index].dropna().unique()
        if len(unique_values) > 1:
            raise ValueError(
                f"Component {field} values do not match within component {key.upper()}; "
                "provide one compatible snapshot context per component file"
            )
        if len(unique_values) == 1:
            component_values.append(unique_values[0])

    if component_values and any(value != component_values[0] for value in component_values[1:]):
        raise ValueError(
            f"Component {field} values do not match across files; "
            "refusing to fuse incompatible decision contexts"
        )

    mismatch = values.nunique(axis=1, dropna=True) > 1
    if mismatch.any():
        cve_id = result.loc[mismatch, "cve_id"].iloc[0]
        raise ValueError(
            f"Component {field} values do not match for CVE {cve_id}; "
            "refusing to fuse incompatible decision contexts"
        )
    return values.bfill(axis=1).iloc[:, 0]


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


def build_fused_dataset(
    baseline_path: Path,
    component_paths: dict[str, Path],
    patch_hours_path: Path | None = None,
) -> tuple[pd.DataFrame, dict[str, int]]:
    """Fuse a baseline cohort with sparse component handoffs using CVE ID.

    The CVSS/EPSS baseline defines the CVE population. Component rows outside
    that population are ignored, while baseline CVEs with no component row or
    an unavailable component score retain a missing score rather than zero.
    Source dates and statuses are kept for provenance.
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
    baseline["cve_id"] = baseline["cve_id"].astype("string").str.upper()
    if baseline["cve_id"].isna().any() or baseline["cve_id"].duplicated().any():
        raise ValueError("CVSS/EPSS baseline must have one non-empty row per CVE ID")

    result = baseline.copy()
    coverage: dict[str, int] = {}
    component_keys = ("a", "b", "c")
    baseline_ids = set(result["cve_id"])

    for key, component in (("a", "a_text"), ("b", "b_survival"), ("c", "c_graph")):
        path = component_paths[key]
        frame = _read_component(path, component)
        frame["cve_id"] = frame["cve_id"].astype("string").str.upper()
        matching = frame["cve_id"].isin(baseline_ids)
        coverage[key] = int(matching.sum())
        frame = frame.loc[matching].copy()
        suffix_columns = {
            "score": f"score_{key}",
            "status": f"status_{key}",
            "reason": f"reason_{key}",
            "model_version": f"model_version_{key}",
            "decision_time": f"decision_time_{key}",
            "snapshot_date": f"snapshot_date_{key}",
            "horizon_days": f"horizon_days_{key}",
        }
        frame = frame[list(suffix_columns) + ["cve_id"]].rename(
            columns=suffix_columns
        )
        result = result.merge(frame, on="cve_id", how="left", validate="one_to_one")
    result["cvss_normalized"] = pd.to_numeric(
        result["cvss_base_score"], errors="coerce"
    ).div(10.0)
    result["epss_score"] = pd.to_numeric(result["epss_score"], errors="coerce")
    if not result["cvss_normalized"].dropna().between(0.0, 1.0).all():
        raise ValueError("CVSS base scores must be between 0 and 10")
    if not result["epss_score"].dropna().between(0.0, 1.0).all():
        raise ValueError("EPSS scores must be between 0 and 1")

    signal_columns = ["cvss_normalized", "epss_score", "score_a", "score_b", "score_c"]
    signals = result[signal_columns]
    result["signals_used"] = signals.notna().sum(axis=1)
    result["signal_coverage"] = result["signals_used"] / len(signal_columns)
    result["fusion_score"] = signals.mean(axis=1).round(6)
    result["fusion_method"] = FUSION_METHOD

    if patch_hours_path is not None:
        if not patch_hours_path.is_file():
            raise FileNotFoundError(f"Patch effort estimates not found: {patch_hours_path}")
        effort = pd.read_csv(patch_hours_path, dtype={"cve_id": "string"})
        effort_columns = {
            "cve_id",
            "cvss_base_score",
            "severity_tier",
            "est_patch_hours",
            "method",
            "ownership",
        }
        missing_effort = effort_columns.difference(effort.columns)
        if missing_effort:
            raise ValueError(
                f"Patch effort file is missing columns: {sorted(missing_effort)}"
            )
        effort["cve_id"] = effort["cve_id"].astype("string").str.strip().str.upper()
        if effort["cve_id"].isna().any() or effort["cve_id"].duplicated().any():
            raise ValueError("Patch effort file must have one non-empty row per CVE ID")
        effort["est_patch_hours"] = pd.to_numeric(
            effort["est_patch_hours"], errors="raise"
        )
        if effort["est_patch_hours"].isna().any() or (effort["est_patch_hours"] <= 0).any():
            raise ValueError("Estimated patch hours must be positive numeric values")
        baseline_cvss = result.set_index("cve_id")["cvss_base_score"]
        effort_cvss = effort.set_index("cve_id")["cvss_base_score"]
        common_ids = baseline_cvss.index.intersection(effort_cvss.index)
        baseline_values = pd.to_numeric(baseline_cvss.loc[common_ids], errors="coerce")
        effort_values = pd.to_numeric(effort_cvss.loc[common_ids], errors="coerce")
        comparable = baseline_values.notna() & effort_values.notna()
        if not baseline_values[comparable].reset_index(drop=True).equals(
            effort_values[comparable].reset_index(drop=True)
        ):
            raise ValueError("Patch effort CVSS values do not match the baseline by CVE ID")
        effort = effort[
            ["cve_id", "est_patch_hours", "severity_tier", "method", "ownership"]
        ].rename(
            columns={
                "est_patch_hours": "patch_hours",
                "severity_tier": "patch_severity_tier",
                "method": "patch_hours_method",
                "ownership": "patch_hours_ownership",
            }
        )
        result = result.merge(effort, on="cve_id", how="left", validate="one_to_one")
    else:
        result["patch_hours"] = pd.NA
        result["patch_severity_tier"] = pd.NA
        result["patch_hours_method"] = pd.NA
        result["patch_hours_ownership"] = pd.NA

    baseline_snapshots = pd.to_datetime(result["snapshot_date"], utc=True, errors="coerce")
    result["baseline_snapshot_date"] = baseline_snapshots.dt.strftime("%Y-%m-%d").astype(
        "string"
    )
    shared_decision_times = _shared_component_context(
        result, component_keys, "decision_time"
    )
    shared_snapshots = _shared_component_context(result, component_keys, "snapshot_date")
    shared_horizons = _shared_component_context(result, component_keys, "horizon_days")
    # Keep component context distinct from the baseline snapshot. Use the
    # baseline as-of time only for CVEs with no component context; never choose
    # a later timestamp by taking a maximum across sources.
    result["decision_time"] = shared_decision_times.fillna(baseline_snapshots).dt.strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    result["snapshot_date"] = shared_snapshots.fillna(baseline_snapshots).dt.strftime(
        "%Y-%m-%d"
    )
    result["horizon_days"] = shared_horizons.astype("Int64")
    versions = result[["model_version_a", "model_version_b", "model_version_c"]]
    has_synthetic = versions.astype("string").apply(
        lambda column: column.str.contains("synthetic", case=False, na=False)
    ).any().any()
    result["data_origin"] = (
        "mixed_synthetic_and_handoff" if has_synthetic else "first_version_components"
    )
    output_columns = [
        "cve_id", "decision_time", "horizon_days", "snapshot_date",
        "baseline_snapshot_date",
        "epss_date", "epss_model_version", "cvss_base_score", "cvss_version",
        "cvss_vector", "epss_score", "percentile",
        "score_a", "status_a", "reason_a", "model_version_a",
        "decision_time_a", "snapshot_date_a", "horizon_days_a",
        "score_b", "status_b", "reason_b", "model_version_b",
        "decision_time_b", "snapshot_date_b", "horizon_days_b",
        "score_c", "status_c", "reason_c", "model_version_c",
        "decision_time_c", "snapshot_date_c", "horizon_days_c",
        "cvss_normalized", "fusion_score", "signals_used", "signal_coverage",
        "fusion_method", "data_origin", "patch_hours", "patch_severity_tier",
        "patch_hours_method", "patch_hours_ownership",
    ]
    return (
        result[output_columns].sort_values("cve_id", kind="stable").reset_index(drop=True),
        coverage,
    )


def main() -> None:
    settings = load_settings()
    module_dir = Path(__file__).resolve().parent
    dummy_dir = module_dir / "dummy_inputs"
    parser = argparse.ArgumentParser(
        description="Fuse the CVSS/EPSS baseline with Component A/B/C scores"
    )
    parser.add_argument(
        "--component-a",
        type=Path,
        default=dummy_dir / COMPONENT_FILES["a"],
        help="Component A shared Score handoff CSV",
    )
    parser.add_argument(
        "--component-b",
        type=Path,
        default=dummy_dir / COMPONENT_FILES["b"],
        help="Component B shared Score handoff CSV",
    )
    parser.add_argument(
        "--component-c",
        type=Path,
        default=settings.data_processed / "component_c" / "c_graph_scores.csv",
        help="Component C shared Score handoff CSV",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=settings.outputs / "d_fusion" / "fused_dataset.csv",
        help="Destination fused CSV",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=settings.data_processed / "d_fusion_baselines.parquet",
    )
    parser.add_argument(
        "--patch-hours",
        type=Path,
        default=settings.data_processed / "component_a_b" / "patch_hours_estimate.csv",
        help="Optional per-CVE patch effort estimates; kept separate from risk features",
    )
    args = parser.parse_args()
    metadata_path = args.component_c.with_suffix(args.component_c.suffix + ".metadata.json")
    metadata = (
        json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata_path.is_file()
        else {}
    )
    expected_hash = metadata.get("output_sha256")
    if expected_hash:
        with args.component_c.open("rb") as component_file:
            actual_hash = hashlib.file_digest(component_file, "sha256").hexdigest()
        if actual_hash.lower() != expected_hash.lower():
            raise ValueError(
                "Component C CSV checksum does not match its metadata JSON: "
                f"expected {expected_hash}, got {actual_hash}"
            )
    component_paths = {
        "a": args.component_a,
        "b": args.component_b,
        "c": args.component_c,
    }
    result, coverage = build_fused_dataset(
        args.baseline, component_paths, args.patch_hours
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.output, index=False)
    print(f"Saved {len(result)} CVEs to {args.output}")
    print(f"Fusion method: {FUSION_METHOD}")
    print(
        "Component rows matching baseline CVEs: "
        f"A={coverage['a']}, B={coverage['b']}, C={coverage['c']}"
    )
    print(f"Component C available scores after join: {(result['status_c'] == 'available').sum()}")
    print(
        "Component C not-eligible scores after join: "
        f"{(result['status_c'] == 'not_eligible').sum()}"
    )
    print(f"Component C rows without a matching CVE: {result['status_c'].isna().sum()}")
    print(f"Component C metadata snapshot: {metadata.get('snapshot_id', 'not supplied')}")
    if expected_hash:
        print(f"Component C metadata checksum: verified ({actual_hash})")
    print(f"Rows with all five signals: {(result['signals_used'] == 5).sum()}")
    print(f"Rows with fewer than five signals: {(result['signals_used'] < 5).sum()}")
    print(f"Rows with patch-hour estimates: {result['patch_hours'].notna().sum()}")


if __name__ == "__main__":
    main()
