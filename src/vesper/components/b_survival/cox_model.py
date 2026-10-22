"""Cox proportional-hazards model and its baselines for Component B."""

import warnings
from dataclasses import dataclass

import numpy as np
import pandas as pd
from lifelines import CoxPHFitter, KaplanMeierFitter
from lifelines.statistics import proportional_hazard_test

from vesper.components.b_survival.features import (
    NUMERIC_COLUMN,
    FeatureEncoder,
)

PENALIZER = 0.01
HORIZONS = (30, 90, 365)
MODEL_NAMES = ("cox", "cox_breslow", "cvss_cox", "cvss_rank", "km_reference")

# Age bands of the piecewise-constant baseline hazard, in days since publication.
# The last band is open-ended.
BASELINE_BAND_EDGES = (0, 30, 90, 180, 365, 730)
MIN_BAND_EVENTS = 10

# Columns predict_risk() needs in the rows it is given
REQUIRED_COLUMNS = [
    "cve_id",
    "published_at",
    "cvss_base_score",
    "cvss_attack_vector",
    "cvss_attack_complexity",
    "cvss_privileges_required",
    "cvss_user_interaction",
    "exploit_at_publication",
    "cwe_ids",
]


@dataclass
class CoxModel:
    """A fitted Cox model with everything needed to score new rows."""

    name: str
    encoder: FeatureEncoder
    feature_columns: list
    fitter: CoxPHFitter
    train_rows: int
    train_events: int
    train_max_follow_up: int
    # Piecewise baseline: band start days and the hazard per day in each band
    band_starts: np.ndarray
    band_rates: np.ndarray

    def features(self, rows):
        return self.encoder.transform(rows)[self.feature_columns]

    def risk(self, rows):
        """Relative risk exp(x·beta). Higher means listed in KEV sooner."""
        return self.fitter.predict_partial_hazard(self.features(rows)).to_numpy()

    def listed_by(self, rows, horizons=HORIZONS):
        """Model estimate of the share listed in KEV by each horizon: 1 - S(t | x).

        Returns an array with one row per CVE and one column per horizon.
        """
        partial = self.risk(rows)
        cumulative = self.cumulative_baseline(np.asarray(horizons, dtype=float))
        return 1 - np.exp(-np.outer(partial, cumulative))

    def listed_by_breslow(self, rows, horizons=HORIZONS):
        """The same as listed_by, with lifelines' Breslow step baseline (comparison)."""
        survival = self.fitter.predict_survival_function(self.features(rows), times=horizons)
        return 1 - survival.to_numpy().T

    def cumulative_baseline(self, times):
        """Cumulative baseline hazard H0(t) of the piecewise-constant baseline."""
        return cumulative_hazard(self.band_starts, self.band_rates, times)

    def listed_within_next(self, rows, ages, days):
        """Model estimate of "listed in the next `days` days" for CVEs `ages` days old
        and still unlisted: 1 - S(age + days | x) / S(age | x)
                          = 1 - exp(-(H0(age + days) - H0(age)) * exp(x·beta)).

        Uses the piecewise-constant baseline, so it is above 0 for every CVE.
        """
        partial = self.risk(rows)
        ages = np.asarray(ages, dtype=float)
        added = self.cumulative_baseline(ages + days) - self.cumulative_baseline(ages)
        return 1 - np.exp(-added * partial)


def merge_bands(starts, events, min_events=MIN_BAND_EVENTS):
    """Merge neighbouring bands until each has at least min_events events.

    Bands are joined from the youngest age up; a short last band joins the band
    before it. Returns the kept band starts.
    """
    kept, count = [], 0
    for start, band_events in zip(starts, events, strict=True):
        if not kept or count >= min_events:
            kept.append(start)
            count = 0
        count += band_events
    if len(kept) > 1 and count < min_events:
        kept.pop()
    return kept


def exposure_in_bands(durations, starts):
    """Days each row was at risk inside each band: one column per band."""
    durations = np.asarray(durations, dtype=float)[:, None]
    lower = np.asarray(starts, dtype=float)[None, :]
    upper = np.append(np.asarray(starts[1:], dtype=float), np.inf)[None, :]
    return np.clip(np.minimum(durations, upper) - lower, 0, None)


def band_of(times, starts):
    """Index of the band each time falls in."""
    return np.searchsorted(np.asarray(starts, dtype=float), np.asarray(times), side="right") - 1


def piecewise_baseline(durations, events, partial_hazard, edges=BASELINE_BAND_EDGES):
    """Fit the piecewise-constant baseline hazard with the Cox coefficients fixed.

    `partial_hazard` is exp(x·beta) of each train row, centred like lifelines. An
    event on day d of age counts in the band that contains d. Returns the band
    starts and the hazard per day in each band.
    """
    durations = np.asarray(durations, dtype=float)
    events = np.asarray(events, dtype=bool)
    counts = np.bincount(band_of(durations[events], edges), minlength=len(edges))
    starts = np.asarray(merge_bands(edges, counts), dtype=float)
    events_per_band = np.bincount(band_of(durations[events], starts), minlength=len(starts))
    at_risk = (exposure_in_bands(durations, starts) * np.asarray(partial_hazard)[:, None]).sum(0)
    rates = np.divide(events_per_band, at_risk, out=np.zeros(len(starts)), where=at_risk > 0)
    return starts, rates


def cumulative_hazard(starts, rates, times):
    """H0(t) = sum over bands of rate x days of the band before t."""
    return exposure_in_bands(np.asarray(times, dtype=float).ravel(), starts) @ np.asarray(rates)


def fit_cox(train, encoder=None, feature_columns=None, name="cox"):
    """Fit a Cox model on train rows (which must all have a CVSS score)."""
    encoder = encoder or FeatureEncoder().fit(train)
    features = encoder.transform(train)
    columns = feature_columns or list(features.columns)
    data = features[columns].assign(
        duration_days=train["duration_days"].to_numpy(), event=train["event"].to_numpy()
    )
    fitter = CoxPHFitter(penalizer=PENALIZER)
    fitter.fit(data, duration_col="duration_days", event_col="event")
    band_starts, band_rates = piecewise_baseline(
        train["duration_days"],
        train["event"],
        fitter.predict_partial_hazard(features[columns]).to_numpy(),
    )
    return CoxModel(
        name=name,
        encoder=encoder,
        feature_columns=columns,
        fitter=fitter,
        train_rows=len(train),
        train_events=int(train["event"].sum()),
        train_max_follow_up=int(train["duration_days"].max()),
        band_starts=band_starts,
        band_rates=band_rates,
    )


def fit_models(train):
    """Fit the Cox model, the CVSS-only Cox model and the Kaplan-Meier reference."""
    encoder = FeatureEncoder().fit(train)
    cox = fit_cox(train, encoder, name="cox")
    cvss_cox = fit_cox(train, encoder, ["cvss_score_std"], name="cvss_cox")
    km = KaplanMeierFitter().fit(train["duration_days"], train["event"])
    return {"cox": cox, "cvss_cox": cvss_cox, "km_reference": km}


def predictions(models, test, horizons=HORIZONS):
    """Risk scores and "listed by" estimates of every model on the test rows.

    Returns {model name: (risk array, listed-by array or None)}.
    """
    km = models["km_reference"]
    km_listed = 1 - km.survival_function_at_times(list(horizons)).to_numpy()
    return {
        "cox": (models["cox"].risk(test), models["cox"].listed_by(test, horizons)),
        "cox_breslow": (models["cox"].risk(test), models["cox"].listed_by_breslow(test, horizons)),
        "cvss_cox": (models["cvss_cox"].risk(test), models["cvss_cox"].listed_by(test, horizons)),
        "cvss_rank": (test[NUMERIC_COLUMN].to_numpy(dtype=float), None),
        "km_reference": (np.zeros(len(test)), np.tile(km_listed, (len(test), 1))),
    }


# ---------------------------------------------------------------------------
# Hazard ratios and the proportional-hazards check
# ---------------------------------------------------------------------------


def hazard_ratios(model):
    """Hazard ratios with 95% intervals. The CVSS row is per 1 standard deviation;
    a second row gives it per 1 CVSS point, which is easier to read."""
    summary = model.fitter.summary
    table = pd.DataFrame(
        {
            "feature": summary.index,
            "hazard_ratio": summary["exp(coef)"].to_numpy(),
            "ci_lower_95": summary["exp(coef) lower 95%"].to_numpy(),
            "ci_upper_95": summary["exp(coef) upper 95%"].to_numpy(),
            "p_value": summary["p"].to_numpy(),
        }
    )
    if "cvss_score_std" in summary.index:
        row = summary.loc["cvss_score_std"]
        per_point = 1 / model.encoder.score_std
        table.loc[len(table)] = {
            "feature": "cvss_base_score (per 1 point)",
            "hazard_ratio": float(np.exp(row["coef"] * per_point)),
            "ci_lower_95": float(np.exp(row["coef lower 95%"] * per_point)),
            "ci_upper_95": float(np.exp(row["coef upper 95%"] * per_point)),
            "p_value": float(row["p"]),
        }
    return table


def ph_check(model, train):
    """Schoenfeld-residual test of the proportional-hazards assumption, per feature.

    A small p-value means the effect of that feature changes over time. The
    result is reported; a violation does not stop anything.
    """
    data = model.features(train).assign(
        duration_days=train["duration_days"].to_numpy(), event=train["event"].to_numpy()
    )
    result = proportional_hazard_test(model.fitter, data, time_transform="rank")
    summary = result.summary.reset_index().rename(columns={"index": "feature", "p": "p_value"})
    summary["violated_at_0.05"] = summary["p_value"] < 0.05
    return summary[["feature", "test_statistic", "p_value", "violated_at_0.05"]]


# ---------------------------------------------------------------------------
# Scoring new CVEs (for Component D and the user interface)
# ---------------------------------------------------------------------------


def predict_risk(model, rows, decision_time, horizons=HORIZONS):
    """Score CVE rows with a fitted Cox model.

    `rows` needs the columns in REQUIRED_COLUMNS. `decision_time` is the moment
    the scores are made for; a CVE published after it is an error, because its
    data could not exist yet.

    Returns one row per CVE: cve_id, status, reason, risk_score and
    est_listed_by_<t>d for each horizon. A CVE without a CVSS score cannot be
    scored by this model: its status is "not_eligible" and its scores are empty.
    The estimates are ranking scores, not validated probabilities.
    """
    missing_columns = [column for column in REQUIRED_COLUMNS if column not in rows]
    if missing_columns:
        raise ValueError(f"predict_risk: missing column(s) {missing_columns}")

    decision = pd.Timestamp(decision_time)
    decision = decision.tz_localize("UTC") if decision.tzinfo is None else decision
    published = pd.to_datetime(rows["published_at"], format="ISO8601", utc=True)
    future = published > decision
    if future.any():
        examples = list(rows.loc[future, "cve_id"].head(5))
        raise ValueError(
            f"predict_risk: {int(future.sum())} CVE(s) published after the decision time "
            f"{decision.isoformat()}, for example {examples}"
        )

    beyond = [days for days in horizons if days > model.train_max_follow_up]
    if beyond:
        warnings.warn(
            f"horizons {beyond} days are beyond the longest train follow-up "
            f"({model.train_max_follow_up} days); those estimates are extrapolated",
            stacklevel=2,
        )

    result = pd.DataFrame({"cve_id": rows["cve_id"].to_numpy()})
    result["status"] = "available"
    result["reason"] = ""
    result["risk_score"] = np.nan
    for days in horizons:
        result[f"est_listed_by_{days}d"] = np.nan

    has_cvss = rows[NUMERIC_COLUMN].notna().to_numpy()
    result.loc[~has_cvss, "status"] = "not_eligible"
    result.loc[~has_cvss, "reason"] = "no CVSS 3.x score"
    if has_cvss.any():
        eligible = rows[has_cvss]
        result.loc[has_cvss, "risk_score"] = model.risk(eligible)
        listed = model.listed_by(eligible, horizons)
        for column, days in enumerate(horizons):
            result.loc[has_cvss, f"est_listed_by_{days}d"] = listed[:, column]
    return result
