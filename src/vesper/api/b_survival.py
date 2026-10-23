"""FastAPI endpoints for Component B: live exploit-timing estimates from the Cox model."""

from __future__ import annotations

import re
import threading
import time

import numpy as np
import pandas as pd
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from vesper.config import load_settings

router = APIRouter(prefix="/api/b", tags=["Component B"])

CURVE_DAYS = 365  # the curve runs from publication day 0 to day 365
CURVE_STEP = 5  # one point every 5 days
REPORT_DAYS = (30, 90, 365)
TOP_DRIVERS = 5
NOTE = (
    "Model-based estimate of being added to CISA KEV (a public record of exploitation), "
    "not a certainty. Checked as a ranking, not yet as a calibrated probability."
)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
_state: dict = {}  # filled once: the fitted model and the CVE table
_load_lock = threading.Lock()  # a request waits for a load already in progress


# ---------------------------------------------------------------------------
# Loading: fit the Cox model once (about 15 s) and keep it in memory
# ---------------------------------------------------------------------------


def _get_state() -> dict:
    if not _state:
        with _load_lock:
            if not _state:
                _state.update(_load())
    return _state


def _load() -> dict:
    """Read the survival table and fit B's scoring model, as score_export does."""
    from vesper.components.b_survival.score_export import fit_scoring_model, start_of_day
    from vesper.components.b_survival.split_data import load_survival_table
    from vesper.components.b_survival.study_design import PROCESSED_SUBFOLDER, SNAPSHOT_DATE

    path = load_settings().data_processed / PROCESSED_SUBFOLDER / "survival_table.csv"
    if not path.is_file():
        raise HTTPException(
            status_code=503,
            detail=f"Component B data not found at {path}. Build it with "
            "`python -m vesper.components.b_survival.survival_table`.",
        )
    started = time.perf_counter()
    table = load_survival_table(path)
    trained_through = start_of_day(SNAPSHOT_DATE)
    model = fit_scoring_model(table, trained_through)
    state = prepare(table, model, trained_through)
    state["load_seconds"] = round(time.perf_counter() - started, 1)
    return state


def prepare(table, model, trained_through) -> dict:
    """Everything the endpoints need, computed once from the table and the model."""
    from vesper.components.b_survival.features import drop_missing_cvss
    from vesper.components.b_survival.score_export import COHORT
    from vesper.components.b_survival.survival_table import filter_cohort

    cohort, _ = drop_missing_cvss(filter_cohort(table, COHORT))
    # Training rows: the cohort published before trained_through (the model's own train set)
    train = cohort[cohort["published_at"] < pd.Timestamp(trained_through)]
    days = np.arange(0, CURVE_DAYS + 1, CURVE_STEP)
    return {
        "model": model,
        "table": table.set_index("cve_id"),
        "trained_through": trained_through,
        "feature_means": model.features(train).mean(),
        # Relative risk of every eligible CVE, sorted, for the percentile
        "population_risk": np.sort(model.risk(cohort)),
        "population_curve": _kaplan_meier(cohort[~cohort["already_exploited"]], days),
    }


def _kaplan_meier(rows, days) -> list:
    """Share of the cohort listed in KEV by each day (1 - Kaplan-Meier survival)."""
    from lifelines import KaplanMeierFitter

    fitter = KaplanMeierFitter().fit(rows["duration_days"], rows["event"])
    survival = fitter.survival_function_at_times(days).to_numpy()
    return [[int(d), round(1 - float(s), 6)] for d, s in zip(days, survival, strict=True)]


def warm_up() -> threading.Thread:
    """Fit the model in the background so the first request is fast. Failures are
    ignored here; the next request retries and returns the 503."""

    def load_quietly():
        try:
            _get_state()
        except Exception:  # noqa: BLE001
            pass

    thread = threading.Thread(target=load_quietly, name="b-survival-warm-up", daemon=True)
    thread.start()
    return thread


# ---------------------------------------------------------------------------
# One estimate: curve, 30/90/365 numbers, percentile, band, drivers
# ---------------------------------------------------------------------------


def estimate(state: dict, row: pd.DataFrame) -> dict:
    """Model estimate for one CVE row (a one-row table with the feature columns)."""
    from vesper.components.b_survival.frontend_export import level_of

    model = state["model"]
    risk = float(model.risk(row)[0])  # exp(x·beta): relative risk against the average CVE
    days = np.arange(0, CURVE_DAYS + 1, CURVE_STEP)
    listed = 1 - np.exp(-model.cumulative_baseline(days) * risk)  # 1 - S(t | x)
    by_day = 1 - np.exp(-model.cumulative_baseline(np.array(REPORT_DAYS)) * risk)
    population = state["population_risk"]
    percentile = float(np.searchsorted(population, risk, side="right") / len(population))
    return {
        "curve": [[int(d), round(float(p), 6)] for d, p in zip(days, listed, strict=True)],
        "by_day": {str(d): round(float(p), 6) for d, p in zip(REPORT_DAYS, by_day, strict=True)},
        "relative_risk": round(risk, 4),
        "percentile": round(percentile, 4),
        "band": level_of(percentile),
        "drivers": drivers(state, row),
    }


def drivers(state: dict, row: pd.DataFrame) -> list:
    """Features that move this CVE's risk most against an average train CVE:
    effect = coef x (value - train mean); hazard ratio = exp(coef)."""
    from vesper.components.b_survival.frontend_export import factor_label

    model = state["model"]
    values = model.features(row).iloc[0]
    result = []
    for feature, coef in model.fitter.params_.items():
        value = float(values[feature])
        if feature != "cvss_score_std" and value == 0:
            continue  # a dummy that is off says nothing about this CVE
        effect = float(coef) * (value - float(state["feature_means"][feature]))
        result.append(
            {
                "feature": feature,
                "label": factor_label(feature),
                "value": round(value, 3),
                "coef": round(float(coef), 4),
                "hazard_ratio": round(float(np.exp(coef)), 3),
                "effect": round(effect, 4),
            }
        )
    result.sort(key=lambda driver: -abs(driver["effect"]))
    return result[:TOP_DRIVERS]


# ---------------------------------------------------------------------------
# Looking up a real CVE: eligible, already in KEV, or not eligible (with the reason)
# ---------------------------------------------------------------------------


def lookup(state: dict, cve_id: str) -> dict:
    """Status, reason, dates and features of one CVE, without the estimate."""
    from vesper.components.b_survival.study_design import KEV_START_DATE

    cve_id = cve_id.strip().upper()
    out = {"cve_id": cve_id, "status": "not_eligible", "reason": None, "features": None}
    if not CVE_PATTERN.match(cve_id):
        return out | {"reason": "Not a CVE ID (expected CVE-YYYY-NNNN)."}
    table = state["table"]
    if cve_id not in table.index:
        return out | {"reason": "Not in the NVD snapshot used by the model (2016 to 2026-10-01)."}
    record = table.loc[cve_id]
    published = record["published_at"]
    out["published"] = published.date().isoformat()
    decision_day = pd.Timestamp(state["trained_through"]).normalize()
    out["age_days"] = int((decision_day - published.normalize()).days)
    out["features"] = features_of(record)
    if published < pd.Timestamp(KEV_START_DATE, tz="UTC"):
        return out | {
            "reason": f"Published before the KEV catalogue began ({KEV_START_DATE}): "
            "outside the modelling cohort."
        }
    if pd.isna(record["cvss_base_score"]):
        return out | {"reason": "No CVSS 3.x score: a model input is missing."}
    if record["event"] == 1:
        kev_day = published.normalize() + pd.Timedelta(days=int(record["duration_days"]))
        return out | {
            "status": "already_exploited",
            "reason": f"Already in CISA KEV since {kev_day.date()}: patch it now.",
        }
    return out | {"status": "available"}


def features_of(record) -> dict:
    """The model inputs of one table row, as plain JSON values."""
    score = record["cvss_base_score"]
    return {
        "cvss_base_score": None if pd.isna(score) else float(score),
        "attack_vector": record["cvss_attack_vector"],
        "attack_complexity": record["cvss_attack_complexity"],
        "privileges_required": record["cvss_privileges_required"],
        "user_interaction": record["cvss_user_interaction"],
        "public_exploit_at_publication": bool(record["exploit_at_publication"]),
        "cwe_ids": [c for c in str(record["cwe_ids"]).split(";") if c and c != "nan"],
    }


def model_row(features: dict) -> pd.DataFrame:
    """One-row table in the columns the feature encoder expects."""
    return pd.DataFrame(
        [
            {
                "cvss_base_score": features["cvss_base_score"],
                "cvss_attack_vector": features["attack_vector"],
                "cvss_attack_complexity": features["attack_complexity"],
                "cvss_privileges_required": features["privileges_required"],
                "cvss_user_interaction": features["user_interaction"],
                "exploit_at_publication": features["public_exploit_at_publication"],
                "cwe_ids": ";".join(features["cwe_ids"]),
            }
        ]
    )


def answer(state: dict, info: dict) -> dict:
    """Add the estimate (when the CVE can be scored), the population curve and labels."""
    scored = info["status"] != "not_eligible"
    return info | {
        "estimate": estimate(state, model_row(info["features"])) if scored else None,
        "population": {
            "label": "All eligible CVEs (Kaplan-Meier)",
            "curve": state["population_curve"],
        },
        "trained_through": state["trained_through"].date().isoformat(),
        "note": NOTE,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


class PredictRequest(BaseModel):
    """A what-if CVE: the model's own inputs."""

    model_config = ConfigDict(extra="forbid")

    cvss_base_score: float = Field(ge=0, le=10)
    attack_vector: str = "NETWORK"
    attack_complexity: str = "LOW"
    privileges_required: str = "NONE"
    user_interaction: str = "NONE"
    public_exploit_at_publication: bool = False
    cwe_ids: list[str] = Field(default_factory=list, max_length=10)


class PlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_ids: list[str] = Field(min_length=1, max_length=200)
    deadline_days: int = Field(ge=1, le=365)


@router.get("/model")
def model_info() -> dict:
    """Training summary and the allowed values for the what-if form."""
    state = _get_state()
    model = state["model"]
    return {
        "trained_through": state["trained_through"].date().isoformat(),
        "train_rows": model.train_rows,
        "train_events": model.train_events,
        "load_seconds": state.get("load_seconds"),
        "levels": {
            name.removeprefix("cvss_"): levels for name, levels in model.encoder.levels.items()
        },
        "top_cwes": model.encoder.top_cwes,
    }


@router.get("/cve/{cve_id}")
def check_cve(cve_id: str) -> dict:
    """Estimate for one real CVE. Not eligible is 200 with the reason, not an error."""
    state = _get_state()
    return answer(state, lookup(state, cve_id))


@router.post("/predict")
def predict(request: PredictRequest) -> dict:
    """Estimate for a what-if CVE described by its features."""
    state = _get_state()
    features = request.model_dump()
    for name, levels in state["model"].encoder.levels.items():
        value = features[name.removeprefix("cvss_")]
        if value not in levels:
            raise HTTPException(422, f"{name.removeprefix('cvss_')} must be one of {levels}")
    info = {"cve_id": None, "status": "available", "reason": None, "features": features}
    return answer(state, info)


@router.post("/plan")
def plan(request: PlanRequest) -> dict:
    """Rank CVEs by the model's chance of a KEV listing before the deadline.

    Already-listed CVEs come first, then the highest chance; not eligible ones last.
    """
    state = _get_state()
    rows = []
    for cve_id in dict.fromkeys(i.strip().upper() for i in request.cve_ids if i.strip()):
        info = lookup(state, cve_id)
        row = {"cve_id": info["cve_id"], "status": info["status"], "reason": info["reason"]}
        row |= {"p_before_deadline": None, "band": None, "main_driver": None}
        row["patch_first"] = info["status"] == "already_exploited"
        if info["status"] == "available":
            features = model_row(info["features"])
            # Chance of a listing in the next deadline_days days, given none so far
            chance = state["model"].listed_within_next(
                features, [info["age_days"]], request.deadline_days
            )
            result = estimate(state, features)
            raising = [d for d in result["drivers"] if d["effect"] > 0]
            row |= {
                "p_before_deadline": round(float(chance[0]), 6),
                "band": result["band"],
                "main_driver": raising[0]["label"] if raising else None,
                "patch_first": result["band"] == "High",
            }
        rows.append(row)

    order = {"already_exploited": 0, "available": 1, "not_eligible": 2}
    rows.sort(key=lambda r: (order[r["status"]], -(r["p_before_deadline"] or 0)))
    for rank, row in enumerate(rows, start=1):
        row["rank"] = rank
    return {"deadline_days": request.deadline_days, "rows": rows, "note": NOTE}
