"""Evaluate the Component B models on every test set."""

import math
import os
from concurrent.futures import ProcessPoolExecutor

import numpy as np
import pandas as pd
from lifelines import KaplanMeierFitter
from lifelines.utils import concordance_index

from vesper.components.b_survival.cox_model import (
    HORIZONS,
    MODEL_NAMES,
    fit_models,
    hazard_ratios,
    ph_check,
    predictions,
)
from vesper.components.b_survival.features import drop_missing_cvss
from vesper.components.b_survival.split_data import SPLITS_SUBFOLDER, load_survival_table
from vesper.components.b_survival.study_design import COHORTS, CUTOFF_DATES, PROCESSED_SUBFOLDER
from vesper.config import load_settings

OUTPUT_SUBFOLDER = "models"
TOP_K = 100
LABEL_DAYS = 365  # P@100 counts a CVE as positive if it was listed within this many days
N_BOOTSTRAP = 1000
SEED = 20261001
# Paired c-index differences: (model, compared with)
C_INDEX_PAIRS = (("cox", "cvss_rank"),)

# The proportional-hazards check runs on the latest cut-off of these cohorts.
# lifelines' Schoenfeld test grows with rows x distinct times: about 2.5 minutes
# for post_kev (57,000 train rows) but more than 10 minutes for full (147,000
# rows, 2,721 distinct durations). It runs on the main cohort only.
PH_CHECK_COHORTS = ("post_kev",)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def c_index(time, event, risk):
    """Harrell's c-index with lifelines. A higher risk means an earlier event."""
    return float(concordance_index(time, -np.asarray(risk, dtype=float), event))


def c_index_fast(time, event, risk, chunk=256):
    """Harrell's c-index, the same definition as lifelines, computed event by event.

    lifelines takes about 0.2 s on a test set, too slow for 1,000 bootstrap
    resamples. Events are rare, so comparing each event with every row is fast.
    A pair (i, j) is comparable when i has an event and j was still unlisted
    after i: T_j > T_i, or T_j = T_i with j censored. It is concordant when i
    has the higher risk; a tie in risk counts one half.
    """
    time = np.asarray(time, dtype=float)
    event = np.asarray(event, dtype=bool)
    risk = np.asarray(risk, dtype=float)
    events = np.flatnonzero(event)
    if len(risk) and np.all(risk == risk[0]):
        # Every pair is tied in risk, so every comparable pair counts one half
        return 0.5 if len(events) and len(time) > 1 else float("nan")
    concordant, comparable = 0.0, 0
    for start in range(0, len(events), chunk):
        index = events[start : start + chunk]
        t_i, r_i = time[index, None], risk[index, None]
        pairs = (time[None, :] > t_i) | ((time[None, :] == t_i) & ~event[None, :])
        concordant += np.sum(pairs & (risk[None, :] < r_i))
        concordant += 0.5 * np.sum(pairs & (risk[None, :] == r_i))
        comparable += int(pairs.sum())
    return concordant / comparable if comparable else float("nan")


def censoring_survival(time, event):
    """Kaplan-Meier of the censoring times: G(s) = P(not censored by day s)."""
    return KaplanMeierFitter().fit(time, 1 - np.asarray(event, dtype=int))


def km_value(km, times, just_before=False):
    """Value of a Kaplan-Meier step curve at `times` (or just before them)."""
    timeline = km.survival_function_.index.to_numpy(dtype=float)
    values = km.survival_function_.iloc[:, 0].to_numpy()
    side = "left" if just_before else "right"
    position = np.searchsorted(timeline, np.asarray(times, dtype=float), side=side) - 1
    return np.where(position >= 0, values[np.clip(position, 0, None)], 1.0)


def brier_ipcw(time, event, listed_by_t, t, censoring_km):
    """Brier score at day t with inverse probability of censoring weights (Graf 1999).

    For a CVE listed by day t:   S(t)^2         / G(T_i-)
    For a CVE unlisted at day t: (1 - S(t))^2   / G(t)
    For a CVE censored before t: 0 (its weight is carried by the others)
    where S(t) = 1 - listed_by_t is the model's estimate of "still unlisted".
    """
    time = np.asarray(time, dtype=float)
    event = np.asarray(event, dtype=bool)
    survival = 1 - np.asarray(listed_by_t, dtype=float)
    listed = event & (time <= t)
    unlisted = time > t
    g_at_t = float(km_value(censoring_km, [t])[0])
    g_before = km_value(censoring_km, time, just_before=True)
    if g_at_t <= 0 or np.any(g_before[listed] <= 0):
        raise ValueError(f"Censoring weight is zero at day {t}: the Brier score is undefined")
    scores = np.zeros(len(time))
    scores[listed] = survival[listed] ** 2 / g_before[listed]
    scores[unlisted] = (1 - survival[unlisted]) ** 2 / g_at_t
    return float(scores.mean())


def precision_at_k(risk, positive, k=TOP_K):
    """Share of the k highest-risk CVEs that are positive.

    CVEs tied with the k-th place are shared out evenly: the result is the
    expected precision when tied CVEs are put in a random order.
    """
    risk = np.asarray(risk, dtype=float)
    positive = np.asarray(positive, dtype=bool)
    k = min(k, len(risk))
    if k == 0:
        return float("nan")
    threshold = np.sort(risk)[::-1][k - 1]
    above = risk > threshold
    tied = risk == threshold
    places_left = k - int(above.sum())
    hits = positive[above].sum() + places_left * positive[tied].mean()
    return float(hits / k)


def listed_within(time, event, days=LABEL_DAYS):
    """True for a test CVE listed in KEV within `days` days of publication."""
    return (np.asarray(event) == 1) & (np.asarray(time) <= days)


def all_metrics(time, event, risk, listed_by, horizons=HORIZONS, fast=True, censoring_km=None):
    """Every metric of one model on one (possibly resampled) test set."""
    if censoring_km is None:
        censoring_km = censoring_survival(time, event)
    concordance = c_index_fast(time, event, risk) if fast else c_index(time, event, risk)
    metrics = {"c_index": concordance}
    for column, days in enumerate(horizons):
        metrics[f"brier_{days}d"] = (
            brier_ipcw(time, event, listed_by[:, column], days, censoring_km)
            if listed_by is not None
            else float("nan")
        )
    metrics["p_at_100"] = precision_at_k(risk, listed_within(time, event))
    return metrics


def bootstrap_metrics(time, event, model_predictions, n_resamples=N_BOOTSTRAP, seed=SEED):
    """95% percentile intervals of every metric, for every model.

    The same resamples are used for every model, so models can be compared.
    Returns {model: {metric: (lower, upper)}}.
    """
    rng = np.random.default_rng(seed)
    time, event = np.asarray(time), np.asarray(event)
    samples = {name: [] for name in model_predictions}
    for _ in range(n_resamples):
        rows = rng.integers(0, len(time), len(time))
        # One censoring curve per resample, shared by every model
        censoring_km = censoring_survival(time[rows], event[rows])
        for name, (risk, listed_by) in model_predictions.items():
            resampled = listed_by[rows] if listed_by is not None else None
            samples[name].append(
                all_metrics(
                    time[rows], event[rows], risk[rows], resampled, censoring_km=censoring_km
                )
            )
    intervals = {}
    for name, values in samples.items():
        frame = pd.DataFrame(values)
        intervals[name] = {
            metric: tuple(np.nanpercentile(frame[metric], [2.5, 97.5]))
            if frame[metric].notna().any()
            else (float("nan"), float("nan"))
            for metric in frame
        }
    return intervals


def bootstrap_c_index_difference(time, event, risk_a, risk_b, n_resamples=N_BOOTSTRAP, seed=SEED):
    """c-index(a) - c-index(b), with a 95% percentile interval.

    The resamples are drawn exactly as in bootstrap_metrics (same seed, same
    order), so they are the same resamples as the intervals of each model.
    Returns (difference on the full test set, lower, upper).
    """
    rng = np.random.default_rng(seed)
    time, event = np.asarray(time), np.asarray(event)
    risk_a, risk_b = np.asarray(risk_a, dtype=float), np.asarray(risk_b, dtype=float)
    samples = []
    for _ in range(n_resamples):
        rows = rng.integers(0, len(time), len(time))
        samples.append(
            c_index_fast(time[rows], event[rows], risk_a[rows])
            - c_index_fast(time[rows], event[rows], risk_b[rows])
        )
    point = c_index_fast(time, event, risk_a) - c_index_fast(time, event, risk_b)
    lower, upper = np.nanpercentile(samples, [2.5, 97.5])
    return float(point), float(lower), float(upper)


# ---------------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------------


def evaluate_split(train, test, cohort, cutoff, n_resamples=N_BOOTSTRAP, log=print):
    """Fit the models on one train set, measure them on its test set.

    Returns the metric rows, the fitted models, the train rows used and the rows
    of paired c-index differences.
    """
    train, train_left_out = drop_missing_cvss(train)
    test, test_left_out = drop_missing_cvss(test)
    log(
        f"[{cohort} {cutoff}] left out without CVSS: train {train_left_out['rows']} rows "
        f"({train_left_out['events']} events), test {test_left_out['rows']} rows "
        f"({test_left_out['events']} events)"
    )

    models = fit_models(train)
    model_predictions = predictions(models, test)
    time, event = test["duration_days"].to_numpy(), test["event"].to_numpy()

    # The fast c-index must agree with lifelines on the real test set
    for name, (risk, _) in model_predictions.items():
        slow, quick = c_index(time, event, risk), c_index_fast(time, event, risk)
        if not math.isclose(slow, quick, abs_tol=1e-9):
            raise RuntimeError(f"c-index check failed for {name}: {slow} vs {quick}")

    g_train = float(km_value(censoring_survival(train["duration_days"], train["event"]), [365])[0])
    g_test = float(km_value(censoring_survival(time, event), [365])[0])
    log(f"  censoring G(365): train {g_train:.3f}, test {g_test:.3f} (test is used)")

    intervals = bootstrap_metrics(time, event, model_predictions, n_resamples)
    train_max = int(train["duration_days"].max())
    rows = []
    for name in MODEL_NAMES:
        risk, listed_by = model_predictions[name]
        point = all_metrics(time, event, risk, listed_by, fast=False)
        row = {
            "cohort": cohort,
            "cutoff": cutoff.isoformat(),
            "model": name,
            "train_rows": len(train),
            "train_events": int(train["event"].sum()),
            "train_max_follow_up_days": train_max,
            "test_rows": len(test),
            "test_events": int(event.sum()),
            "test_listed_within_365d": int(listed_within(time, event).sum()),
            "train_left_out_no_cvss": train_left_out["rows"],
            "test_left_out_no_cvss": test_left_out["rows"],
        }
        for metric, value in point.items():
            row[metric] = value
            row[f"{metric}_ci_lower"], row[f"{metric}_ci_upper"] = intervals[name][metric]
        # A horizon after the longest train follow-up is extrapolated by the model
        row["extrapolated_horizons"] = ";".join(
            str(days) for days in HORIZONS if days > train_max and listed_by is not None
        )
        rows.append(row)

    differences = []
    for name_a, name_b in C_INDEX_PAIRS:
        point, lower, upper = bootstrap_c_index_difference(
            time, event, model_predictions[name_a][0], model_predictions[name_b][0], n_resamples
        )
        differences.append(
            {
                "cohort": cohort,
                "cutoff": cutoff.isoformat(),
                "model": name_a,
                "compared_with": name_b,
                "c_index_difference": point,
                "ci_lower": lower,
                "ci_upper": upper,
                "excludes_zero": bool(lower > 0 or upper < 0),
            }
        )
    return rows, models, train, differences


def add_brier_skill(metrics):
    """Brier skill at 365 days: 1 - Brier(model) / Brier(km_reference) of the same split.

    0 means no better than the Kaplan-Meier reference (no features); 1 is perfect.
    With events this rare every Brier score is close to the base rate, so the
    skill shows the difference between models more clearly than the raw score.
    """
    reference = metrics[metrics["model"] == "km_reference"].set_index(["cohort", "cutoff"])
    keys = list(zip(metrics["cohort"], metrics["cutoff"], strict=True))
    reference_brier = [reference.loc[key, "brier_365d"] for key in keys]
    metrics = metrics.copy()
    metrics["brier_skill_365d"] = 1 - metrics["brier_365d"].to_numpy() / reference_brier
    return metrics


def print_metrics(metrics):
    """Print cohort | cut-off | model | c-index (CI) | Brier 30/90/365 | P@100."""
    print()
    header = f"{'cohort':<9}{'cut-off':<12}{'model':<14}{'train ev':>9}  {'c-index (95% CI)':<22}"
    print(header + f"{'Brier 30 / 90 / 365':<31}{'skill 365':>10}  {'P@100 (95% CI)':<20}")
    for row in metrics.itertuples():
        c_text = f"{row.c_index:.3f} ({row.c_index_ci_lower:.3f}-{row.c_index_ci_upper:.3f})"
        if math.isnan(row.brier_30d):
            brier, skill = "n/a (ranking only)", "n/a"
        else:
            brier = f"{row.brier_30d:.5f} / {row.brier_90d:.5f} / {row.brier_365d:.5f}"
            if isinstance(row.extrapolated_horizons, str) and row.extrapolated_horizons:
                brier += " *"
            skill = f"{row.brier_skill_365d:.4f}"
        p_text = f"{row.p_at_100:.2f} ({row.p_at_100_ci_lower:.2f}-{row.p_at_100_ci_upper:.2f})"
        print(
            f"{row.cohort:<9}{row.cutoff:<12}{row.model:<14}{row.train_events:>9}  "
            f"{c_text:<22}{brier:<31}{skill:>10}  {p_text:<20}"
        )
    print("* a horizon is longer than the longest train follow-up: the estimate is extrapolated")


def print_differences(differences):
    """Print the paired c-index differences with their 95% intervals."""
    print()
    print("Paired c-index difference (same bootstrap resamples)")
    for row in differences.itertuples():
        verdict = "excludes 0" if row.excludes_zero else "includes 0"
        print(
            f"  {row.cohort:<9}{row.cutoff:<12}{row.model} - {row.compared_with}: "
            f"{row.c_index_difference:+.3f} ({row.ci_lower:+.3f} to {row.ci_upper:+.3f}), "
            f"{verdict}"
        )


def run_split(splits_dir, cohort, cutoff, latest, n_resamples):
    """Everything for one split; runs in its own process. Returns tables and log lines."""
    lines = []
    train = load_survival_table(splits_dir / cohort / f"train_{cutoff.isoformat()}.csv")
    test = load_survival_table(splits_dir / cohort / f"test_{cutoff.isoformat()}.csv")
    rows, models, train_used, differences = evaluate_split(
        train, test, cohort, cutoff, n_resamples, log=lines.append
    )
    ratio_tables, ph_tables = [], []
    if cutoff == latest:
        # Hazard ratios and the proportional-hazards check: latest cut-off only
        for name in ("cox", "cvss_cox"):
            ratios = hazard_ratios(models[name])
            ratios.insert(0, "model", name)
            ratios.insert(0, "cutoff", cutoff.isoformat())
            ratios.insert(0, "cohort", cohort)
            ratio_tables.append(ratios)
        if cohort in PH_CHECK_COHORTS:
            check = ph_check(models["cox"], train_used)
            check.insert(0, "cutoff", cutoff.isoformat())
            check.insert(0, "cohort", cohort)
            ph_tables.append(check)
        else:
            lines.append(f"  [{cohort} {cutoff}] PH check not run (see PH_CHECK_COHORTS)")
    return rows, ratio_tables, ph_tables, lines, differences


def main(
    settings=None, cohorts=COHORTS, cutoffs=CUTOFF_DATES, n_resamples=N_BOOTSTRAP, workers=None
):
    """Fit and evaluate every model on every split; save metrics, hazard ratios, PH check.

    The splits are independent, so they run in parallel processes (`workers`;
    1 runs them one after another). The results do not depend on the order.
    """
    # Folders come from vesper.config
    settings = settings or load_settings()
    splits_dir = settings.data_processed / PROCESSED_SUBFOLDER / SPLITS_SUBFOLDER
    output_dir = settings.outputs / PROCESSED_SUBFOLDER / OUTPUT_SUBFOLDER
    output_dir.mkdir(parents=True, exist_ok=True)
    latest = max(cutoffs)
    jobs = [
        (splits_dir, cohort, cutoff, latest, n_resamples)
        for cohort in cohorts
        for cutoff in cutoffs
    ]
    workers = workers or min(len(jobs), os.cpu_count() or 1)

    if workers == 1:
        results = [run_split(*job) for job in jobs]
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(run_split, *zip(*jobs, strict=True)))

    metric_rows, ratio_tables, ph_tables, difference_rows = [], [], [], []
    for rows, ratios, checks, lines, differences in results:
        for line in lines:
            print(line)
        metric_rows += rows
        ratio_tables += ratios
        ph_tables += checks
        difference_rows += differences

    metrics = add_brier_skill(pd.DataFrame(metric_rows))
    metrics.to_csv(output_dir / "metrics.csv", index=False)
    pd.concat(ratio_tables).to_csv(output_dir / "hazard_ratios.csv", index=False)
    if ph_tables:
        pd.concat(ph_tables).to_csv(output_dir / "ph_check.csv", index=False)
    differences = pd.DataFrame(difference_rows)
    differences.to_csv(output_dir / "c_index_differences.csv", index=False)
    print_metrics(metrics)
    print_differences(differences)
    print()
    print(
        "Saved metrics.csv, c_index_differences.csv, hazard_ratios.csv and ph_check.csv to:",
        output_dir,
    )
    return output_dir


if __name__ == "__main__":
    main()
