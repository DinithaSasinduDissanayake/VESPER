"""Rank CVEs and compare Component D ensemble candidates chronologically.

The current dummy snapshot can produce a provisional ranking. Model selection
requires historical, point-in-time feature rows and future KEV labels; it will
refuse to select a model from the synthetic fixture.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd

from vesper.components.d_fusion.ensemble_models import (
    FEATURES,
    MODEL_NAMES,
    LogisticModel,
    feature_frame,
    fit_logistic,
    score_model,
)
from vesper.config import load_settings

LABEL_COLUMN = "kev_within_horizon"
PRIMARY_METRIC = "average_precision"
TOP_K = 20
MODEL_FILE = "selected_ensemble_model.json"
REPORT_FILE = "ensemble_model_comparison.json"


def _average_precision(labels: np.ndarray, scores: np.ndarray) -> float:
    positives = int(labels.sum())
    if positives == 0:
        return float("nan")
    order = np.argsort(-scores, kind="stable")
    ranked = labels[order]
    precisions = np.cumsum(ranked) / np.arange(1, len(ranked) + 1)
    return float((precisions * ranked).sum() / positives)


def _group_metrics(frame: pd.DataFrame, scores: pd.Series) -> dict[str, float]:
    values = frame[["decision_time", "cve_id", LABEL_COLUMN]].copy()
    values["score"] = scores
    values = values.dropna(subset=["score"])
    per_date = []
    for _, group in values.groupby("decision_time", sort=True):
        labels = group[LABEL_COLUMN].astype(int).to_numpy()
        predictions = group["score"].to_numpy(dtype=float)
        if labels.sum() == 0:
            continue
        order = np.argsort(-predictions, kind="stable")
        ordered_labels = labels[order]
        k = min(TOP_K, len(group))
        precision = float(ordered_labels[:k].mean())
        recall = float(ordered_labels[:k].sum() / labels.sum())
        discounts = 1.0 / np.log2(np.arange(2, k + 2))
        dcg = float((ordered_labels[:k] * discounts).sum())
        ideal = np.sort(labels)[::-1][:k]
        idcg = float((ideal * discounts).sum())
        per_date.append(
            {
                "average_precision": _average_precision(labels, predictions),
                "precision_at_20": precision,
                "recall_at_20": recall,
                "ndcg_at_20": dcg / idcg if idcg else 0.0,
            }
        )
    if not per_date:
        raise ValueError("Evaluation dates must each contain at least one positive KEV outcome")
    return {
        metric: float(np.nanmean([row[metric] for row in per_date]))
        for metric in per_date[0]
    }


def _temporal_partitions(
    frame: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    dates = sorted(frame["decision_time"].dropna().unique())
    if len(dates) < 5:
        raise ValueError(
            "Model selection needs at least five distinct decision_time snapshots; "
            "the current dummy data has only one and cannot support a temporal evaluation."
        )
    train_end = max(1, int(len(dates) * 0.6))
    validation_end = max(train_end + 1, int(len(dates) * 0.8))
    validation_end = min(validation_end, len(dates) - 1)
    train_dates = set(dates[:train_end])
    validation_dates = set(dates[train_end:validation_end])
    test_dates = set(dates[validation_end:])
    return (
        frame[frame["decision_time"].isin(train_dates)].copy(),
        frame[frame["decision_time"].isin(validation_dates)].copy(),
        frame[frame["decision_time"].isin(test_dates)].copy(),
    )


def _fit_candidate(name: str, frame: pd.DataFrame) -> LogisticModel | None:
    if name != "logistic_regression":
        return None
    return fit_logistic(feature_frame(frame), frame[LABEL_COLUMN])


def _scores(name: str, frame: pd.DataFrame, model: LogisticModel | None) -> pd.Series:
    return score_model(name, feature_frame(frame), model)


def select_model(
    labeled_path: Path,
    model_path: Path,
    report_path: Path,
    evaluation_as_of: str,
) -> dict:
    """Select by validation average precision and report the later holdout."""

    data = pd.read_csv(labeled_path, dtype={"cve_id": "string"})
    required = {
        "cve_id",
        "decision_time",
        "data_origin",
        "label_matured_at",
        "horizon_days",
        LABEL_COLUMN,
        "epss_score",
        "score_a",
        "score_b",
        "score_c",
        "cvss_base_score",
    }
    missing = required.difference(data.columns)
    if missing:
        raise ValueError(f"Labeled feature table is missing columns: {sorted(missing)}")
    origins = data["data_origin"].astype("string").str.strip().str.lower()
    if origins.isna().any() or set(origins) != {"real"}:
        raise ValueError(
            "Model selection accepts only rows marked data_origin=real; "
            "synthetic fixtures are for pipeline checks, not model selection."
        )
    version_columns = [
        column for column in data.columns if column.startswith("model_version_")
    ]
    for column in version_columns:
        synthetic = data[column].astype("string").str.contains(
            "synthetic", case=False, na=False
        )
        if synthetic.any():
            raise ValueError(
                f"{column} identifies synthetic component scores; "
                "they cannot be used to select the research model."
            )
    if data["cve_id"].isna().any() or data["decision_time"].isna().any():
        raise ValueError("cve_id and decision_time must be present on every row")
    data["decision_time"] = pd.to_datetime(data["decision_time"], utc=True).dt.strftime(
        "%Y-%m-%d"
    )
    if data.duplicated(["cve_id", "decision_time"]).any():
        raise ValueError("Each decision snapshot may contain only one row per CVE")
    data["label_matured_at"] = pd.to_datetime(
        data["label_matured_at"], utc=True, errors="raise"
    ).dt.strftime("%Y-%m-%d")
    if data["label_matured_at"].isna().any():
        raise ValueError("label_matured_at must be present for every row")
    data = data.loc[data["epss_score"].notna() & data["cvss_base_score"].notna()].copy()
    if data.empty:
        raise ValueError("No labeled rows have both EPSS and CVSS for common-model comparison")
    evaluation_as_of = pd.Timestamp(evaluation_as_of, tz="UTC").strftime("%Y-%m-%d")
    horizons = pd.to_numeric(data["horizon_days"], errors="raise")
    if (horizons <= 0).any():
        raise ValueError("horizon_days must be positive")
    labels = pd.to_numeric(data[LABEL_COLUMN], errors="raise")
    if not labels.isin([0, 1]).all():
        raise ValueError(f"{LABEL_COLUMN} must contain only 0/1 labels")
    data[LABEL_COLUMN] = labels.astype(int)
    train, validation, test = _temporal_partitions(data)
    validation_start = validation["decision_time"].min()
    test_start = test["decision_time"].min()
    expected_maturity = (
        pd.to_datetime(data["decision_time"], utc=True)
        + pd.to_timedelta(horizons, unit="D")
    ).dt.strftime("%Y-%m-%d")
    if (data["label_matured_at"] < expected_maturity).any():
        raise ValueError("label_matured_at cannot precede the end of its prediction horizon")
    train = train[train["label_matured_at"] <= validation_start].copy()
    validation = validation[validation["label_matured_at"] <= test_start].copy()
    test = test[test["label_matured_at"] <= evaluation_as_of].copy()
    if train.empty or validation.empty or test.empty:
        raise ValueError("Label-maturity purging left an empty train, validation, or test period")
    if train[LABEL_COLUMN].nunique() < 2:
        raise ValueError(
            "Matured training period must contain positive and negative outcomes"
        )
    if validation[LABEL_COLUMN].nunique() < 2 or test[LABEL_COLUMN].sum() == 0:
        raise ValueError(
            "Validation and test periods need positive outcomes; "
            "validation also needs negatives"
        )

    validation_results = {}
    for name in MODEL_NAMES:
        fitted = _fit_candidate(name, train)
        validation_results[name] = _group_metrics(
            validation, _scores(name, validation, fitted)
        )
    selected_name = max(
        MODEL_NAMES,
        key=lambda name: (
            validation_results[name][PRIMARY_METRIC],
            validation_results[name]["ndcg_at_20"],
            name == "epss",
        ),
    )

    pretest = pd.concat([train, validation], ignore_index=True)
    final_model = _fit_candidate(selected_name, pretest)
    test_metrics = _group_metrics(test, _scores(selected_name, test, final_model))
    artifact = {
        "model_name": selected_name,
        "selection_metric": PRIMARY_METRIC,
        "validation_metrics": validation_results[selected_name],
        "test_metrics": test_metrics,
        "train_through": str(max(pretest["decision_time"])),
        "test_dates": sorted(test["decision_time"].unique()),
        "features": list(FEATURES),
        "trained_at": datetime.now(UTC).isoformat(),
        "is_dummy_data": False,
    }
    if final_model is not None:
        artifact["logistic_model"] = final_model.__dict__
    model_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    model_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    report_path.write_text(
        json.dumps(
            {
                "selection_rule": (
                    "Highest validation macro average precision; tie-break by "
                    "NDCG@20, then EPSS baseline"
                ),
                "validation_metrics_by_model": validation_results,
                "selected_model": selected_name,
                "held_out_test_metrics": test_metrics,
                "split_counts": {
                    "train_rows": len(train),
                    "validation_rows": len(validation),
                    "test_rows": len(test),
                },
                "note": (
                    "The final test period is reported once and is not used "
                    "to select the model."
                ),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return artifact


def rank_file(
    input_path: Path,
    output_path: Path,
    model_path: Path | None,
    model_name: str,
) -> pd.DataFrame:
    """Create a high-to-low CVE ranking from a fused score table."""

    frame = pd.read_csv(input_path, dtype={"cve_id": "string"})
    if "cve_id" not in frame or frame["cve_id"].isna().any():
        raise ValueError("Input must have a non-empty cve_id column")
    if frame["cve_id"].duplicated().any():
        raise ValueError("Input must have one row per CVE ID")
    artifact = None
    if model_path is not None and model_path.is_file():
        artifact = json.loads(model_path.read_text(encoding="utf-8"))
        model_name = artifact["model_name"]
    fitted = (
        LogisticModel(**artifact["logistic_model"])
        if artifact and "logistic_model" in artifact
        else None
    )
    scores = score_model(model_name, feature_frame(frame), fitted)
    ranked = frame.copy()
    ranked["risk_score"] = scores
    ranked = ranked.sort_values(
        ["risk_score", "cve_id"],
        ascending=[False, True],
        kind="stable",
        na_position="last",
    ).reset_index(drop=True)
    ranked["risk_rank"] = np.arange(1, len(ranked) + 1)
    ranked["ranking_model"] = model_name
    ranked["model_selection_status"] = (
        "selected_on_temporal_validation" if artifact else "provisional_pipeline_baseline"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    ranked.to_csv(output_path, index=False)
    return ranked


def main() -> None:
    settings = load_settings()
    module_dir = Path(__file__).resolve().parent
    default_input = module_dir / "dummy_inputs" / "fused_dummy_dataset.csv"
    default_model = settings.data_processed / "d_fusion" / MODEL_FILE
    default_report = settings.outputs / "d_fusion" / REPORT_FILE
    parser = argparse.ArgumentParser(
        description="Compare ensemble candidates or rank CVEs high to low"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    rank_parser = subparsers.add_parser("rank", help="Write a descending CVE ranking")
    rank_parser.add_argument("--input", type=Path, default=default_input)
    rank_parser.add_argument(
        "--output",
        type=Path,
        default=settings.outputs / "d_fusion" / "ranked_vulnerabilities.csv",
    )
    rank_parser.add_argument("--model", choices=MODEL_NAMES)
    rank_parser.add_argument("--model-file", type=Path, default=default_model)

    select_parser = subparsers.add_parser(
        "select", help="Compare models on labeled historical snapshots"
    )
    select_parser.add_argument("--labeled-data", type=Path, required=True)
    select_parser.add_argument(
        "--evaluation-as-of",
        required=True,
        help="Date through which all held-out test labels are known (YYYY-MM-DD)",
    )
    select_parser.add_argument("--model-output", type=Path, default=default_model)
    select_parser.add_argument("--report-output", type=Path, default=default_report)
    args = parser.parse_args()

    if args.command == "rank":
        selected_model_file = (
            args.model_file
            if args.model is None and args.model_file.is_file()
            else None
        )
        model_name = args.model or "equal_weight"
        ranked = rank_file(args.input, args.output, selected_model_file, model_name)
        print(f"Saved {len(ranked)} CVEs to {args.output}")
        print(
            "Ranking model: "
            f"{ranked['ranking_model'].iloc[0] if len(ranked) else model_name}"
        )
        if selected_model_file is None:
            print(
                "Model status: provisional baseline; no validation-based model "
                "selection is available yet"
            )
        print("Order: highest risk score first")
    else:
        artifact = select_model(
            args.labeled_data,
            args.model_output,
            args.report_output,
            args.evaluation_as_of,
        )
        print(f"Selected model: {artifact['model_name']}")
        print(f"Validation {PRIMARY_METRIC}: {artifact['validation_metrics'][PRIMARY_METRIC]:.4f}")
        print(f"Held-out test metrics: {artifact['test_metrics']}")
        print(f"Model artifact: {args.model_output}")
        print(f"Comparison report: {args.report_output}")


if __name__ == "__main__":
    main()
