"""Reconstruct dated NVD CVSS 3.x states and evaluate historical risk models.

This is an EPSS+CVSS historical baseline. It deliberately does not train on
single-snapshot A/B/C handoffs, because those values cannot be made point-in-time.
"""

from __future__ import annotations

import argparse
import gzip
import json
import math
import re
import time
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from datetime import time as day_time
from pathlib import Path

import numpy as np
import pandas as pd
import requests

from vesper.components.d_fusion.ensemble import _average_precision
from vesper.components.d_fusion.ensemble_models import (
    MODEL_NAMES,
    GradientBoostedStumpModel,
    LogisticModel,
    feature_frame,
    fit_gradient_boosting,
    fit_logistic,
    score_model,
)
from vesper.config import load_settings

NVD_HISTORY_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"
CVSS_HISTORY_DIR_NAME = "nvd_history_cvss"
FEATURE_DIR_NAME = "historical_cvss_epss"
CVSS_FEATURES = ("epss_score", "cvss_normalized")
LABEL_COLUMN = "kev_within_horizon"
HISTORY_PAGE_SIZE = 5000
NVD_MAX_RETRIES = 5
NVD_ANALYSIS_EVENTS = ("Initial Analysis", "Modified Analysis")


def _parse_utc(value: str | datetime | pd.Timestamp) -> pd.Timestamp:
    timestamp = pd.Timestamp(value)
    return timestamp.tz_localize("UTC") if timestamp.tzinfo is None else timestamp.tz_convert("UTC")


def _month_ranges(first: date, last: date):
    cursor = pd.Timestamp(first).to_period("M")
    final = pd.Timestamp(last).to_period("M")
    while cursor <= final:
        start = max(first, cursor.start_time.date())
        end = min(last, cursor.end_time.date())
        yield start, end
        cursor += 1


def _history_path(history_dir: Path, month: date, event_name: str) -> Path:
    event_key = event_name.lower().replace(" ", "_")
    return history_dir / f"cve_history_{event_key}_{month:%Y-%m}.jsonl.gz"


def download_history(start_date: date, end_date: date, history_dir: Path) -> int:
    """Cache NVD CVE-change records in monthly compressed JSONL files."""

    settings = load_settings()
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    session = requests.Session()
    history_dir.mkdir(parents=True, exist_ok=True)
    total_events = 0

    for range_start, range_end in _month_ranges(start_date, end_date):
        for event_name in NVD_ANALYSIS_EVENTS:
            output = _history_path(history_dir, range_start, event_name)
            if output.is_file():
                with gzip.open(output, "rt", encoding="utf-8") as stream:
                    total_events += sum(1 for _ in stream)
                continue

            start_time = datetime.combine(range_start, day_time.min, tzinfo=UTC)
            end_time = datetime.combine(range_end, day_time.max, tzinfo=UTC)
            base_params = {
                "changeStartDate": start_time.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "changeEndDate": end_time.strftime("%Y-%m-%dT%H:%M:%S.999"),
                "eventName": event_name,
                "resultsPerPage": HISTORY_PAGE_SIZE,
            }
            start_index = 0
            expected = None
            month_events = 0
            temp_path = output.with_suffix(output.suffix + ".part")
            try:
                with gzip.open(temp_path, "wt", encoding="utf-8") as stream:
                    while expected is None or start_index < expected:
                        params = {**base_params, "startIndex": start_index}
                        response = None
                        for attempt in range(NVD_MAX_RETRIES):
                            try:
                                response = session.get(
                                    NVD_HISTORY_URL,
                                    params=params,
                                    headers=headers,
                                    timeout=60,
                                )
                                response.raise_for_status()
                                break
                            except requests.RequestException:
                                if attempt + 1 == NVD_MAX_RETRIES:
                                    raise
                                time.sleep(min(10 * (attempt + 1), 60))
                        payload = response.json()
                        expected = int(payload.get("totalResults", 0))
                        rows = payload.get("cveChanges", [])
                        for row in rows:
                            stream.write(json.dumps(row, separators=(",", ":")) + "\n")
                        month_events += len(rows)
                        start_index += len(rows)
                        if not rows and start_index < expected:
                            raise RuntimeError(
                                f"NVD returned an empty page at {start_index} of {expected}"
                            )
                        time.sleep(0.65 if settings.nvd_api_key else 6.2)
                temp_path.replace(output)
            except Exception:
                temp_path.unlink(missing_ok=True)
                raise
            total_events += month_events
            print(
                f"Downloaded {month_events:,} NVD {event_name} events for {range_start:%Y-%m}",
                flush=True,
            )
    return total_events


def _chosen_metric(metrics: dict, metric_key: str) -> dict | None:
    entries = metrics.get(metric_key) or []
    return next(
        (entry for entry in entries if entry.get("type") == "Primary"),
        entries[0] if entries else None,
    )


def _current_nvd_states(raw_nvd_path: Path) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    states: dict[str, dict[str, str]] = {}
    published: dict[str, str] = {}
    version_keys = {"3.1": "cvssMetricV31", "3.0": "cvssMetricV30"}
    with gzip.open(raw_nvd_path, "rt", encoding="utf-8") as stream:
        for line in stream:
            record = json.loads(line)
            cve_id = str(record.get("id", "")).upper()
            if not cve_id:
                continue
            published[cve_id] = str(record.get("published", ""))
            metrics = record.get("metrics") or {}
            states[cve_id] = {}
            for version, key in version_keys.items():
                metric = _chosen_metric(metrics, key)
                vector = (metric or {}).get("cvssData", {}).get("vectorString")
                if vector:
                    states[cve_id][version] = vector
    return states, published


def _parse_history_vector(value: str | None, version: str) -> str | None:
    if not value:
        return None
    match = re.search(r"(?:^|\s)(AV:[^\s]+)", value.strip())
    if not match:
        return None
    vector = match.group(1)
    return f"CVSS:{version}/{vector}"


def _metric_version(metric_type: str) -> str | None:
    return {"CVSS V3.1": "3.1", "CVSS V3": "3.0"}.get(metric_type)


def _cvss31_score(vector: str) -> float:
    """Calculate CVSS 3.0/3.1 base score from the official base metrics."""

    parts = dict(piece.split(":", 1) for piece in vector.split("/") if ":" in piece)
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if any(key not in parts for key in required):
        raise ValueError(f"Incomplete CVSS 3.x vector: {vector}")
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[parts["AV"]]
    ac = {"L": 0.77, "H": 0.44}[parts["AC"]]
    pr_values = (
        {"N": 0.85, "L": 0.62, "H": 0.27}
        if parts["S"] == "U"
        else {"N": 0.85, "L": 0.68, "H": 0.50}
    )
    pr = pr_values[parts["PR"]]
    ui = {"N": 0.85, "R": 0.62}[parts["UI"]]
    impact_values = {"N": 0.0, "L": 0.22, "H": 0.56}
    confidentiality = impact_values[parts["C"]]
    integrity = impact_values[parts["I"]]
    availability = impact_values[parts["A"]]
    impact_subscore = 1.0 - (1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability)
    if parts["S"] == "U":
        impact = 6.42 * impact_subscore
    else:
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * (impact_subscore - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    total = (
        min(impact + exploitability, 10.0)
        if parts["S"] == "U"
        else min(1.08 * (impact + exploitability), 10.0)
    )
    return math.ceil(total * 10.0 - 1e-10) / 10.0


def _read_cvss_events(history_dir: Path) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for path in sorted(history_dir.glob("cve_history_*.jsonl.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            for line in stream:
                wrapper = json.loads(line)
                change = wrapper.get("change", {})
                cve_id = str(change.get("cveId", "")).upper()
                created = change.get("created")
                if not cve_id or not created:
                    continue
                details = [
                    detail
                    for detail in change.get("details", [])
                    if _metric_version(str(detail.get("type", "")))
                    and (
                        str(detail.get("newValue", "")).startswith("NIST ")
                        or str(detail.get("oldValue", "")).startswith("NIST ")
                    )
                ]
                if details:
                    grouped[cve_id].append(
                        {"created": _parse_utc(created), "details": details}
                    )
    for events in grouped.values():
        events.sort(key=lambda event: event["created"], reverse=True)
    return grouped


def reconstruct_cvss(
    snapshot_cves: dict[date, set[str]],
    current_states: dict[str, dict[str, str]],
    published: dict[str, str],
    events_by_cve: dict[str, list[dict]],
    last_modified: dict[str, str],
) -> pd.DataFrame:
    """Walk CVSS changes backward and emit one dated record per known CVE."""

    rows = []
    ordered_dates = sorted(snapshot_cves, reverse=True)
    cohort = set().union(*snapshot_cves.values())
    states = {cve_id: dict(current_states.get(cve_id, {})) for cve_id in cohort}
    event_indexes = dict.fromkeys(cohort, 0)
    modified_cutoffs = {
        cve_id: _parse_utc(last_modified[cve_id])
        if last_modified.get(cve_id)
        else pd.Timestamp.max.tz_localize("UTC")
        for cve_id in cohort
    }
    event_lists = {
        cve_id: [
            event
            for event in events_by_cve.get(cve_id, [])
            if event["created"] <= modified_cutoffs[cve_id]
        ]
        for cve_id in cohort
    }
    for snapshot_day in ordered_dates:
        cutoff = pd.Timestamp(datetime.combine(snapshot_day, day_time.max, tzinfo=UTC))
        for cve_id in snapshot_cves[snapshot_day]:
            state = states[cve_id]
            events = event_lists[cve_id]
            index = event_indexes[cve_id]
            while (
                index < len(events) and events[index]["created"] > cutoff
            ):
                for detail in reversed(events[index]["details"]):
                    version = _metric_version(str(detail.get("type", "")))
                    if not version:
                        continue
                    action = str(detail.get("action", ""))
                    if action == "Added":
                        state.pop(version, None)
                    elif action in {"Changed", "Removed"}:
                        old_vector = _parse_history_vector(detail.get("oldValue"), version)
                        if old_vector:
                            state[version] = old_vector
                        else:
                            state.pop(version, None)
                index += 1
            event_indexes[cve_id] = index
            vector = state.get("3.1") or state.get("3.0")
            version = "3.1" if state.get("3.1") else "3.0" if state.get("3.0") else None
            rows.append(
                {
                    "cve_id": cve_id,
                    "snapshot_date": snapshot_day.isoformat(),
                    "cvss_version": version,
                    "cvss_vector": vector,
                    "cvss_base_score": _cvss31_score(vector) if vector and version else None,
                    "published_at": published.get(cve_id),
                }
            )
    return pd.DataFrame(rows)


def _macro_metrics(frame: pd.DataFrame, probabilities: pd.Series) -> dict[str, float]:
    values = frame[["decision_time", "cve_id", LABEL_COLUMN]].copy()
    values["score"] = probabilities.to_numpy()
    date_metrics = []
    for _, group in values.groupby("decision_time", sort=True):
        labels = group[LABEL_COLUMN].astype(int).to_numpy()
        scores = group["score"].to_numpy(dtype=float)
        if not labels.sum():
            continue
        order = np.argsort(-scores, kind="stable")
        ordered = labels[order]
        k = min(20, len(group))
        discounts = 1.0 / np.log2(np.arange(2, k + 2))
        dcg = float((ordered[:k] * discounts).sum())
        ideal = np.sort(labels)[::-1][:k]
        idcg = float((ideal * discounts).sum())
        date_metrics.append(
            {
                "average_precision": _average_precision(labels, scores),
                "precision_at_20": float(ordered[:k].mean()),
                "recall_at_20": float(ordered[:k].sum() / labels.sum()),
                "ndcg_at_20": dcg / idcg if idcg else 0.0,
            }
        )
    if not date_metrics:
        raise ValueError("This evaluation period contains no positive KEV outcomes")
    return {
        name: float(np.mean([row[name] for row in date_metrics]))
        for name in date_metrics[0]
    }


def _split_dates(frame: pd.DataFrame):
    dates = sorted(frame["decision_time"].unique())
    if len(dates) < 12:
        raise ValueError(
            "At least 12 mature monthly snapshots are needed for train/validation/test"
        )
    train_end = int(len(dates) * 0.6)
    validation_end = int(len(dates) * 0.8)
    train_dates = dates[:train_end]
    validation_dates = dates[train_end:validation_end]
    test_dates = dates[validation_end:]
    validation_start = pd.Timestamp(validation_dates[0], tz="UTC")
    test_start = pd.Timestamp(test_dates[0], tz="UTC")
    train = frame[frame.decision_time.isin(train_dates)].copy()
    validation = frame[frame.decision_time.isin(validation_dates)].copy()
    test = frame[frame.decision_time.isin(test_dates)].copy()
    train = train[pd.to_datetime(train.label_matured_at, utc=True) <= validation_start]
    validation = validation[
        pd.to_datetime(validation.label_matured_at, utc=True) <= test_start
    ]
    if train.empty or validation.empty or test.empty:
        raise ValueError("Maturity purging left an empty chronological partition")
    return train, validation, test


def _sample_training(frame: pd.DataFrame, cap_per_date: int = 10000) -> pd.DataFrame:
    parts = []
    for _, group in frame.groupby("decision_time", sort=True):
        positives = group[group[LABEL_COLUMN] == 1]
        negatives = group[group[LABEL_COLUMN] == 0]
        negative_cap = max(cap_per_date - len(positives), 0)
        if len(negatives) > negative_cap:
            negatives = negatives.sample(n=negative_cap, random_state=42)
        parts.append(pd.concat([positives, negatives], ignore_index=False))
    return pd.concat(parts, ignore_index=True).sort_values(
        ["decision_time", "cve_id"], kind="stable"
    )


def build_labeled_panel(
    epss_path: Path,
    kev_path: Path,
    cvss_path: Path,
    vulnerabilities_path: Path,
    output_path: Path,
    horizon_days: int,
    evaluation_as_of: date,
) -> pd.DataFrame:
    epss = pd.read_parquet(epss_path)
    kev = pd.read_parquet(kev_path)
    cvss = pd.read_parquet(cvss_path)
    vulnerabilities = pd.read_parquet(vulnerabilities_path)
    epss["cve_id"] = epss.cve_id.astype("string").str.upper()
    kev["cve_id"] = kev.cve_id.astype("string").str.upper()
    vulnerabilities["cve_id"] = vulnerabilities.cve_id.astype("string").str.upper()
    epss["epss_date"] = pd.to_datetime(epss.epss_date, utc=True).dt.date
    kev["kev_added_on"] = pd.to_datetime(kev.kev_added_on, errors="coerce").dt.date
    cvss["snapshot_date"] = pd.to_datetime(cvss.snapshot_date).dt.date
    published = vulnerabilities[["cve_id", "published_at"]].drop_duplicates("cve_id")
    published["published_day"] = pd.to_datetime(published.published_at, utc=True).dt.date
    kev_dates = kev.set_index("cve_id")["kev_added_on"].to_dict()
    cvss_lookup = cvss.set_index(["snapshot_date", "cve_id"]).sort_index()
    epss_dates = sorted(
        day
        for day in epss.epss_date.unique()
        if day + timedelta(days=horizon_days) <= evaluation_as_of
    )
    panels = []
    for day in epss_dates:
        rows = epss.loc[epss.epss_date.eq(day)].copy()
        rows = rows.merge(published[["cve_id", "published_day"]], on="cve_id", how="inner")
        rows = rows.loc[rows.published_day.le(day)].copy()
        rows["kev_added_on"] = rows.cve_id.map(kev_dates)
        rows = rows.loc[rows.kev_added_on.isna() | rows.kev_added_on.gt(day)].copy()
        horizon_end = day + timedelta(days=horizon_days)
        rows[LABEL_COLUMN] = rows.kev_added_on.map(
            lambda added, snapshot_day=day, mature_day=horizon_end: (
                int(snapshot_day < added <= mature_day) if pd.notna(added) else 0
            )
        )
        rows["decision_time"] = day.isoformat()
        rows["label_matured_at"] = horizon_end.isoformat()
        rows["horizon_days"] = horizon_days
        date_cvss = cvss_lookup.loc[day].reset_index()
        rows = rows.merge(
            date_cvss[["cve_id", "cvss_base_score", "cvss_version", "cvss_vector"]],
            on="cve_id",
            how="left",
            validate="one_to_one",
        )
        rows["cvss_normalized"] = pd.to_numeric(rows.cvss_base_score, errors="coerce").div(10.0)
        rows["data_origin"] = "historical_nvd_epss_kev"
        panels.append(rows)
    if not panels:
        raise ValueError("No EPSS snapshots have fully matured outcome windows")
    panel = pd.concat(panels, ignore_index=True)
    panel = panel.sort_values(["decision_time", "cve_id"], kind="stable").reset_index(drop=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    panel.to_parquet(output_path, index=False)
    return panel


def train_and_evaluate(panel: pd.DataFrame, output_dir: Path) -> dict:
    data = panel.copy()
    data["decision_time"] = pd.to_datetime(data.decision_time, utc=True).dt.strftime("%Y-%m-%d")
    data[LABEL_COLUMN] = pd.to_numeric(data[LABEL_COLUMN], errors="raise").astype(int)
    train, validation, test = _split_dates(data)
    sampled_train = _sample_training(train)
    train_features = feature_frame(sampled_train)
    validation_features = feature_frame(validation)
    test_features = feature_frame(test)
    models: dict[str, LogisticModel | GradientBoostedStumpModel | None] = {}
    for name in MODEL_NAMES:
        if name == "logistic_regression":
            models[name] = fit_logistic(
                train_features,
                sampled_train[LABEL_COLUMN],
                feature_columns=CVSS_FEATURES,
            )
        elif name == "gradient_boosting":
            models[name] = fit_gradient_boosting(
                train_features,
                sampled_train[LABEL_COLUMN],
                feature_columns=CVSS_FEATURES,
                min_leaf=100,
            )
        else:
            models[name] = None
    validation_metrics = {
        name: _macro_metrics(validation, score_model(name, validation_features, model))
        for name, model in models.items()
    }
    selected = max(
        MODEL_NAMES,
        key=lambda name: (
            validation_metrics[name]["average_precision"],
            validation_metrics[name]["ndcg_at_20"],
            name == "epss",
        ),
    )
    pretest = pd.concat([train, validation], ignore_index=True)
    final_fit_rows = _sample_training(pretest)
    final_features = feature_frame(final_fit_rows)
    if selected == "logistic_regression":
        final_model = fit_logistic(
            final_features,
            final_fit_rows[LABEL_COLUMN],
            feature_columns=CVSS_FEATURES,
        )
    elif selected == "gradient_boosting":
        final_model = fit_gradient_boosting(
            final_features,
            final_fit_rows[LABEL_COLUMN],
            feature_columns=CVSS_FEATURES,
            min_leaf=100,
        )
    else:
        final_model = None
    test_scores = score_model(selected, test_features, final_model)
    test_metrics = _macro_metrics(test, test_scores)
    ranking_columns = [
        "cve_id",
        "decision_time",
        LABEL_COLUMN,
        "epss_score",
        "cvss_base_score",
    ]
    test_rankings = test[ranking_columns].copy()
    test_rankings["risk_score"] = test_scores.to_numpy()
    test_rankings = test_rankings.sort_values(
        ["decision_time", "risk_score", "cve_id"],
        ascending=[True, False, True],
        kind="stable",
    )
    test_rankings["risk_rank"] = test_rankings.groupby("decision_time").cumcount() + 1
    test_rankings["ranking_model"] = selected
    output_dir.mkdir(parents=True, exist_ok=True)
    test_rankings.to_csv(output_dir / "heldout_test_rankings.csv", index=False)
    artifact = {
        "model_name": selected,
        "features": list(CVSS_FEATURES),
        "selection_metric": "macro_average_precision",
        "validation_metrics": validation_metrics[selected],
        "held_out_test_metrics": test_metrics,
        "train_dates": sorted(train.decision_time.unique()),
        "validation_dates": sorted(validation.decision_time.unique()),
        "test_dates": sorted(test.decision_time.unique()),
        "training_rows_before_sampling": len(train),
        "training_rows_after_sampling": len(sampled_train),
        "training_positive_labels": int(train[LABEL_COLUMN].sum()),
        "validation_rows": len(validation),
        "validation_positive_labels": int(validation[LABEL_COLUMN].sum()),
        "test_rows": len(test),
        "test_positive_labels": int(test[LABEL_COLUMN].sum()),
        "training_sampling": "all positives plus up to 10000 rows per decision date",
        "prediction_horizon_days": int(data.horizon_days.iloc[0]),
        "label_definition": (
            "CVE first added to KEV after snapshot and within the prediction "
            "horizon; already-listed KEVs excluded"
        ),
        "epss_model_versions": {
            "train": sorted(train.epss_model_version.dropna().astype(str).unique()),
            "validation": sorted(validation.epss_model_version.dropna().astype(str).unique()),
            "test": sorted(test.epss_model_version.dropna().astype(str).unique()),
        },
        "epss_version_note": (
            "EPSS versions were not explicit model features; score distribution "
            "changes across versions may affect temporal generalization."
        ),
        "model_scope": "historical EPSS and reconstructed NVD CVSS 3.x only; no A/B/C history",
        "is_validated_full_component_d_model": False,
    }
    if isinstance(final_model, LogisticModel):
        artifact["logistic_model"] = final_model.__dict__
    elif isinstance(final_model, GradientBoostedStumpModel):
        artifact["gradient_boosting_model"] = final_model.__dict__
    (output_dir / "selected_model.json").write_text(
        json.dumps(artifact, indent=2), encoding="utf-8"
    )
    report = {
        "selection_rule": (
            "Highest validation macro average precision; tie-break by "
            "NDCG@20, then EPSS baseline"
        ),
        "validation_metrics_by_model": validation_metrics,
        "selected_model": selected,
        "held_out_test_metrics": test_metrics,
        "test_rank_rows": len(test_rankings),
        "prediction_horizon_days": int(data.horizon_days.iloc[0]),
        "matured_snapshot_dates": sorted(data.decision_time.unique()),
        "positive_labels": int(data[LABEL_COLUMN].sum()),
        "epss_model_versions_by_split": {
            "train": sorted(train.epss_model_version.dropna().astype(str).unique()),
            "validation": sorted(validation.epss_model_version.dropna().astype(str).unique()),
            "test": sorted(test.epss_model_version.dropna().astype(str).unique()),
        },
        "train_validation_test_positive_counts": {
            "train": int(train[LABEL_COLUMN].sum()),
            "validation": int(validation[LABEL_COLUMN].sum()),
            "test": int(test[LABEL_COLUMN].sum()),
        },
        "warning": (
            "Historical A/B/C outputs are unavailable, so this is not the "
            "final five-signal Component D model evaluation. EPSS versions "
            "also change across the time split and were not explicit model features."
        ),
    }
    (output_dir / "model_evaluation.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    return report


def _read_last_modified(path: Path) -> dict[str, str]:
    data = pd.read_parquet(path, columns=["cve_id", "last_modified_at"])
    return dict(
        zip(
            data.cve_id.astype("string").str.upper(),
            data.last_modified_at.astype(str),
            strict=False,
        )
    )


def prepare_history(args) -> tuple[pd.DataFrame, int]:
    settings = load_settings()
    raw_nvd = next(settings.data_raw.joinpath("nvd").glob("*.jsonl.gz"), None)
    if raw_nvd is None:
        raise FileNotFoundError("Expected a raw NVD *.jsonl.gz current-state snapshot")
    vulnerabilities_path = settings.data_processed / "vulnerabilities.parquet"
    epss_path = settings.data_processed / "epss_snapshots.parquet"
    snapshots = pd.read_parquet(epss_path, columns=["cve_id", "epss_date"])
    snapshots["cve_id"] = snapshots.cve_id.astype("string").str.upper()
    snapshots["epss_date"] = pd.to_datetime(snapshots.epss_date, utc=True).dt.date
    snapshot_cves = {
        day: set(group.cve_id)
        for day, group in snapshots.groupby("epss_date", sort=False)
    }
    modified = pd.read_parquet(vulnerabilities_path, columns=["last_modified_at"])
    latest_modified = pd.to_datetime(modified.last_modified_at, utc=True).max().date()
    snapshot_cves[latest_modified] = set(snapshots.cve_id.unique())
    first_day = min(snapshot_cves)
    history_dir = settings.data_raw / CVSS_HISTORY_DIR_NAME
    event_count = download_history(first_day, latest_modified, history_dir)
    current_states, published = _current_nvd_states(raw_nvd)
    events_by_cve = _read_cvss_events(history_dir)
    modified_by_cve = _read_last_modified(vulnerabilities_path)
    cvss = reconstruct_cvss(
        snapshot_cves, current_states, published, events_by_cve, modified_by_cve
    )
    output_path = settings.data_processed / "d_fusion" / "historical_cvss_snapshots.parquet"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cvss.to_parquet(output_path, index=False)
    current_match = cvss.loc[cvss.snapshot_date.eq(latest_modified.isoformat())].copy()
    return current_match, event_count


def main() -> None:
    settings = load_settings()
    parser = argparse.ArgumentParser(
        description="Reconstruct historical CVSS 3.x and train EPSS+CVSS baselines"
    )
    parser.add_argument("--horizon-days", type=int, default=30)
    parser.add_argument("--evaluation-as-of", type=date.fromisoformat, default=date.today())
    args = parser.parse_args()
    current_match, event_count = prepare_history(args)
    if current_match.empty:
        raise ValueError("Could not create a current-date CVSS validation slice")
    baseline_cvss = pd.read_parquet(
        settings.data_processed / "vulnerabilities.parquet",
        columns=["cve_id", "cvss_base_score", "cvss_version", "cvss_vector"],
    )
    baseline_cvss["cve_id"] = baseline_cvss.cve_id.astype("string").str.upper()
    validation = current_match.merge(
        baseline_cvss,
        on="cve_id",
        how="inner",
        suffixes=("_reconstructed", "_current"),
    )
    validation = validation.loc[
        validation.cvss_version_current.astype("string").isin(["3.0", "3.1"])
        & validation.cvss_vector_reconstructed.eq(validation.cvss_vector_current)
    ].copy()
    score_delta = (
        pd.to_numeric(validation.cvss_base_score_reconstructed, errors="coerce")
        - pd.to_numeric(validation.cvss_base_score_current, errors="coerce")
    ).abs()
    mismatches = int(score_delta.gt(0.05).sum())
    checked = len(validation)
    if checked < 1000 or mismatches:
        raise ValueError(
            "Historical CVSS reconstruction did not validate against the current NVD snapshot: "
            f"matched={checked}, score mismatches={mismatches}"
        )
    print(f"NVD history events cached: {event_count:,}")
    print(f"Current NVD CVSS vector/score matches: {checked:,}; mismatches: 0")
    panel_path = settings.data_processed / "d_fusion" / "historical_cvss_epss_labeled.parquet"
    panel = build_labeled_panel(
        settings.data_processed / "epss_snapshots.parquet",
        settings.data_processed / "kev.parquet",
        settings.data_processed / "d_fusion" / "historical_cvss_snapshots.parquet",
        settings.data_processed / "vulnerabilities.parquet",
        panel_path,
        args.horizon_days,
        args.evaluation_as_of,
    )
    output_dir = settings.outputs / "d_fusion" / FEATURE_DIR_NAME
    report = train_and_evaluate(panel, output_dir)
    cvss_path = settings.data_processed / "d_fusion" / "historical_cvss_snapshots.parquet"
    print(f"Historical CVSS snapshots: {cvss_path}")
    print(f"Labeled training panel: {panel_path} ({len(panel):,} rows)")
    print(f"Selected historical baseline: {report['selected_model']}")
    print(f"Held-out metrics: {report['held_out_test_metrics']}")
    print(f"Outputs: {output_dir}")


if __name__ == "__main__":
    main()
