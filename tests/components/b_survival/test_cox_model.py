"""Tests for features, cox_model and evaluate."""

import warnings
from datetime import date

import numpy as np
import pandas as pd
import pytest
from lifelines import KaplanMeierFitter

from vesper.components.b_survival.cox_model import (
    REQUIRED_COLUMNS,
    cumulative_hazard,
    fit_cox,
    fit_models,
    hazard_ratios,
    merge_bands,
    ph_check,
    piecewise_baseline,
    predict_risk,
    predictions,
)
from vesper.components.b_survival.evaluate import (
    add_brier_skill,
    all_metrics,
    bootstrap_metrics,
    brier_ipcw,
    c_index,
    c_index_fast,
    km_value,
    main,
    precision_at_k,
)
from vesper.components.b_survival.features import (
    BANNED_COLUMNS,
    FeatureEncoder,
    drop_missing_cvss,
)
from vesper.components.b_survival.survival_table import OUTPUT_COLUMNS
from vesper.config import load_settings


def cve_rows(n, seed=0, published="2023-03-01", future_cwe=None):
    """Made-up survival rows: higher CVSS and network attacks are listed sooner."""
    rng = np.random.default_rng(seed)
    score = rng.choice([4.3, 5.5, 6.5, 7.5, 8.8, 9.8], n)
    vector = rng.choice(["NETWORK", "NETWORK", "LOCAL", "ADJACENT_NETWORK"], n)
    risk = np.exp(0.9 * (score - 7) + 0.6 * (vector == "NETWORK"))
    time_to_listing = rng.exponential(2000 / risk)
    follow_up = rng.integers(200, 900, n)
    event = (time_to_listing <= follow_up).astype(int)
    duration = np.where(event == 1, np.floor(time_to_listing), follow_up).astype(int)
    cwes = rng.choice(["CWE-79", "CWE-89", "CWE-787;CWE-20", "CWE-20", None], n)
    table = pd.DataFrame(
        {
            "cve_id": [f"CVE-2023-{10000 + i}" for i in range(n)],
            "published_at": pd.to_datetime([published] * n, utc=True),
            "duration_days": duration,
            "event": event,
            "already_exploited": False,
            "kev_launch_group": False,
            "cvss_base_score": score,
            "cvss_attack_vector": vector,
            "cvss_attack_complexity": rng.choice(["LOW", "HIGH"], n),
            "cvss_privileges_required": rng.choice(["NONE", "LOW", "HIGH"], n),
            "cvss_user_interaction": rng.choice(["NONE", "REQUIRED"], n),
            "cvss_missing": False,
            "cvss_is_primary": pd.array([True] * n, dtype="boolean"),
            "cwe_ids": cwes if future_cwe is None else [future_cwe] * n,
            "exploit_at_publication": rng.random(n) < 0.05,
            "exploit_first_date": pd.Series(pd.NaT, index=range(n), dtype="datetime64[ns, UTC]"),
        }
    )
    return table[OUTPUT_COLUMNS]


@pytest.fixture(scope="module")
def train():
    return cve_rows(600, seed=1)


@pytest.fixture(scope="module")
def models(train):
    return fit_models(train)


# --- features.py --------------------------------------------------------------


def test_banned_columns_never_appear_in_the_features(train):
    features = FeatureEncoder().fit(train).transform(train)

    assert not BANNED_COLUMNS & set(features.columns)
    for banned in BANNED_COLUMNS:
        assert not any(banned in column for column in features.columns)


def test_the_encoder_learns_only_from_train(train):
    encoder = FeatureEncoder().fit(train)
    # A test set with a very different CVSS mix and a CWE never seen in train
    test = cve_rows(50, seed=2, future_cwe="CWE-1337")
    test["cvss_base_score"] = 10.0

    features = encoder.transform(test)

    # The scaling is the train scaling, not the test one
    assert encoder.score_mean == pytest.approx(train["cvss_base_score"].mean())
    expected = (10.0 - encoder.score_mean) / encoder.score_std
    assert features["cvss_score_std"].to_numpy() == pytest.approx(np.full(50, expected))
    # The CWE columns come from train; the unknown CWE is "other" (all zeros)
    assert "cwe=CWE-1337" not in features.columns
    cwe_columns = [column for column in features.columns if column.startswith("cwe=")]
    assert features[cwe_columns].to_numpy().sum() == 0


def test_top_cwes_are_chosen_on_train():
    train = cve_rows(100, seed=3, future_cwe="CWE-22")
    test = cve_rows(100, seed=4)  # different CWEs

    encoder = FeatureEncoder(top_cwe_count=3).fit(train)

    assert encoder.top_cwes == ["CWE-22"]
    assert list(encoder.transform(test).columns) == list(encoder.transform(train).columns)


def test_a_feature_constant_in_train_is_dropped():
    train = cve_rows(100, seed=5)
    train["exploit_at_publication"] = False

    encoder = FeatureEncoder().fit(train)

    assert "exploit_at_publication" in encoder.dropped_constant
    assert "exploit_at_publication" not in encoder.transform(train).columns


def test_unknown_attack_vector_uses_the_reference_level_with_a_warning(train):
    encoder = FeatureEncoder().fit(train)
    rows = train.head(3).copy()
    rows["cvss_attack_vector"] = ["SATELLITE", None, "NETWORK"]

    with pytest.warns(UserWarning, match="cvss_attack_vector: unknown value"):
        features = encoder.transform(rows)

    reference = encoder.reference["cvss_attack_vector"]
    vector_columns = [c for c in features.columns if c.startswith("cvss_attack_vector=")]
    # Rows 0 and 1 look exactly like the reference level: all vector dummies 0
    assert features.loc[rows.index[:2], vector_columns].to_numpy().sum() == 0
    assert reference == "NETWORK"


def test_drop_missing_cvss_counts_rows_and_events():
    table = cve_rows(10, seed=6)
    table.loc[[0, 1, 2], "cvss_base_score"] = np.nan
    table.loc[[0, 1, 2], "event"] = [1, 0, 0]

    kept, left_out = drop_missing_cvss(table)

    assert len(kept) == 7
    assert left_out == {"rows": 3, "events": 1}


def test_the_encoder_refuses_train_rows_without_cvss():
    table = cve_rows(10, seed=6)
    table.loc[0, "cvss_base_score"] = np.nan

    with pytest.raises(ValueError, match="drop_missing_cvss"):
        FeatureEncoder().fit(table)


# --- cox_model.py -------------------------------------------------------------


def test_the_cox_model_finds_the_made_up_effects(models):
    ratios = hazard_ratios(models["cox"]).set_index("feature")

    # Made up with exp(0.9) per CVSS point and exp(0.6) for NETWORK
    assert ratios.loc["cvss_base_score (per 1 point)", "hazard_ratio"] > 1.5
    assert ratios.loc["cvss_base_score (per 1 point)", "ci_lower_95"] > 1
    assert ratios.loc["cvss_attack_vector=LOCAL", "hazard_ratio"] < 1  # NETWORK is the reference


def test_the_cvss_only_model_uses_only_the_score(models):
    assert models["cvss_cox"].feature_columns == ["cvss_score_std"]
    assert len(hazard_ratios(models["cvss_cox"])) == 2  # per SD, and per CVSS point


def test_ph_check_returns_one_row_per_feature(models, train):
    kept, _ = drop_missing_cvss(train)

    check = ph_check(models["cox"], kept)

    assert set(check.columns) == {"feature", "test_statistic", "p_value", "violated_at_0.05"}
    assert len(check) == len(models["cox"].feature_columns)
    assert check["p_value"].between(0, 1).all()


def test_predictions_give_risks_and_listed_by_estimates(models):
    test = cve_rows(40, seed=7)

    result = predictions(models, test)

    assert set(result) == {"cox", "cox_breslow", "cvss_cox", "cvss_rank", "km_reference"}
    risk, listed = result["cox"]
    assert risk.shape == (40,) and listed.shape == (40, 3)
    assert np.all((listed >= 0) & (listed <= 1))
    assert np.all(np.diff(listed, axis=1) >= 0)  # more days, more listed
    assert result["cvss_rank"][1] is None


# --- predict_risk -------------------------------------------------------------


def test_predict_risk_returns_scores_for_every_row(models):
    rows = cve_rows(5, seed=8)

    result = predict_risk(models["cox"], rows, decision_time=date(2026, 10, 1))

    assert list(result.columns) == [
        "cve_id",
        "status",
        "reason",
        "risk_score",
        "est_listed_by_30d",
        "est_listed_by_90d",
        "est_listed_by_365d",
    ]
    assert (result["status"] == "available").all()
    assert result["risk_score"].notna().all()


def test_predict_risk_marks_a_cve_without_cvss_as_not_eligible(models):
    rows = cve_rows(3, seed=9)
    rows.loc[1, "cvss_base_score"] = np.nan

    result = predict_risk(models["cox"], rows, decision_time=date(2026, 10, 1))

    assert list(result["status"]) == ["available", "not_eligible", "available"]
    assert pd.isna(result.loc[1, "risk_score"])
    assert result.loc[1, "reason"] == "no CVSS 3.x score"


def test_predict_risk_handles_unknown_cwe_and_attack_vector(models):
    rows = cve_rows(2, seed=10, future_cwe="CWE-99999")
    rows.loc[0, "cvss_attack_vector"] = "SATELLITE"

    with pytest.warns(UserWarning, match="unknown value"):
        result = predict_risk(models["cox"], rows, decision_time=date(2026, 10, 1))

    assert (result["status"] == "available").all()
    assert result["risk_score"].notna().all()


def test_predict_risk_refuses_a_cve_published_after_the_decision_time(models):
    rows = cve_rows(2, seed=11, published="2027-01-05")

    with pytest.raises(ValueError, match="published after the decision time"):
        predict_risk(models["cox"], rows, decision_time="2026-10-01T00:00:00Z")


def test_predict_risk_names_missing_columns(models):
    rows = cve_rows(2, seed=12).drop(columns=["cwe_ids"])

    with pytest.raises(ValueError, match="missing column"):
        predict_risk(models["cox"], rows, decision_time=date(2026, 10, 1))
    assert "cwe_ids" in REQUIRED_COLUMNS


def test_predict_risk_warns_when_a_horizon_is_beyond_the_train_follow_up():
    short = cve_rows(300, seed=13)
    short["duration_days"] = np.minimum(short["duration_days"], 60)
    model = fit_cox(short)

    with pytest.warns(UserWarning, match="beyond the longest train follow-up"):
        predict_risk(model, cve_rows(2, seed=14), decision_time=date(2026, 10, 1))


# --- evaluate.py: c-index -----------------------------------------------------


def test_c_index_of_a_perfect_ranking_is_one():
    time = np.array([5, 10, 20, 40, 80])
    event = np.array([1, 1, 1, 1, 0])
    risk = np.array([5.0, 4.0, 3.0, 2.0, 1.0])  # earlier event, higher risk

    assert c_index(time, event, risk) == 1.0
    assert c_index_fast(time, event, risk) == 1.0
    assert c_index(time, event, -risk) == 0.0


def test_c_index_of_equal_risks_is_one_half():
    time, event = np.array([5, 10, 20]), np.array([1, 1, 0])

    assert c_index_fast(time, event, np.zeros(3)) == 0.5
    assert c_index(time, event, np.zeros(3)) == 0.5


def test_fast_c_index_matches_lifelines_with_ties_in_time_and_risk():
    rng = np.random.default_rng(15)
    for _ in range(20):
        n = 300
        time = rng.integers(0, 40, n)  # many tied times
        event = rng.random(n) < 0.2
        risk = rng.integers(0, 6, n).astype(float)  # many tied risks
        assert c_index_fast(time, event, risk) == pytest.approx(c_index(time, event, risk))


# --- evaluate.py: IPCW Brier --------------------------------------------------


def test_ipcw_brier_matches_a_hand_calculation():
    # Four CVEs, Brier at t = 10.
    #   A: listed on day 4         -> S(10)^2 / G(4-)
    #   B: censored on day 6       -> 0
    #   C: unlisted at day 12      -> (1 - S(10))^2 / G(10)
    #   D: unlisted at day 20      -> (1 - S(10))^2 / G(10)
    # Censoring Kaplan-Meier: only B is censored (day 6), with 3 at risk:
    #   G(s) = 1 before day 6 and 2/3 from day 6, so G(4-) = 1 and G(10) = 2/3.
    time = np.array([4, 6, 12, 20])
    event = np.array([1, 0, 0, 0])
    listed_by_10 = np.array([0.6, 0.5, 0.2, 0.1])  # S(10) = 0.4, 0.5, 0.8, 0.9
    censoring = KaplanMeierFitter().fit(time, 1 - event)

    expected = (0.4**2 / 1 + 0 + 0.2**2 / (2 / 3) + 0.1**2 / (2 / 3)) / 4

    assert brier_ipcw(time, event, listed_by_10, 10, censoring) == pytest.approx(expected)


def test_km_value_reads_the_step_curve_at_and_just_before_a_day():
    km = KaplanMeierFitter().fit([4, 6, 12, 20], [0, 1, 0, 0])  # one "event" on day 6

    assert km_value(km, [6])[0] == pytest.approx(2 / 3)
    assert km_value(km, [6], just_before=True)[0] == pytest.approx(1.0)
    assert km_value(km, [0])[0] == pytest.approx(1.0)


def test_ipcw_brier_without_censoring_is_the_plain_brier():
    time = np.array([3, 8, 30, 50])
    event = np.array([1, 1, 0, 0])
    listed = np.array([0.9, 0.2, 0.3, 0.0])
    censoring = KaplanMeierFitter().fit(time, 1 - event)  # censoring only after day 10

    # Plain Brier at day 10: outcomes 1, 1, 0, 0
    plain = ((1 - 0.9) ** 2 + (1 - 0.2) ** 2 + 0.3**2 + 0**2) / 4

    assert brier_ipcw(time, event, listed, 10, censoring) == pytest.approx(plain)


# --- evaluate.py: P@100 and bootstrap -----------------------------------------


def test_precision_at_k_on_a_toy_set():
    risk = np.arange(10, dtype=float)[::-1]  # CVE 0 has the highest risk
    positive = np.array([1, 1, 0, 1, 0, 0, 0, 0, 0, 1], dtype=bool)

    assert precision_at_k(risk, positive, k=4) == pytest.approx(3 / 4)
    assert precision_at_k(risk, positive, k=1) == 1.0


def test_precision_at_k_shares_out_ties_at_the_last_place():
    # Two clear top CVEs, then four tied CVEs of which 1 is positive, for k = 4
    risk = np.array([9, 8, 5, 5, 5, 5, 1], dtype=float)
    positive = np.array([1, 0, 1, 0, 0, 0, 1], dtype=bool)

    # 1 hit above the tie, plus 2 places among 4 tied CVEs with 1 positive -> 0.5
    assert precision_at_k(risk, positive, k=4) == pytest.approx((1 + 2 * 0.25) / 4)


def test_precision_at_100_with_more_than_100_cves():
    risk = np.arange(250, dtype=float)
    positive = np.zeros(250, dtype=bool)
    positive[-30:] = True  # the 30 highest-risk CVEs are positive

    assert precision_at_k(risk, positive) == pytest.approx(30 / 100)


def test_bootstrap_is_reproducible_with_the_seed():
    rng = np.random.default_rng(16)
    time = rng.integers(1, 500, 200)
    event = (rng.random(200) < 0.2).astype(int)
    preds = {"model": (rng.random(200), rng.random((200, 3)))}

    first = bootstrap_metrics(time, event, preds, n_resamples=30, seed=7)
    second = bootstrap_metrics(time, event, preds, n_resamples=30, seed=7)
    other = bootstrap_metrics(time, event, preds, n_resamples=30, seed=8)

    assert first == second
    assert first != other


def test_all_metrics_has_no_brier_for_a_ranking_only_model():
    time, event = np.array([5, 10, 400, 500]), np.array([1, 0, 0, 1])

    metrics = all_metrics(time, event, np.array([4.0, 3.0, 2.0, 1.0]), None)

    assert np.isnan(metrics["brier_30d"])
    assert metrics["c_index"] == 1.0


# --- The whole run -------------------------------------------------------------


def test_main_writes_metrics_hazard_ratios_and_the_ph_check(tmp_path):
    # A made-up project folder, so the real data and outputs are never touched
    settings = load_settings(tmp_path)
    splits = settings.data_processed / "b_survival" / "splits" / "post_kev"
    splits.mkdir(parents=True)
    train, test = cve_rows(400, seed=17), cve_rows(250, seed=18)
    test["duration_days"] = np.where(test["event"] == 1, test["duration_days"], 900)
    train.loc[0, "cvss_base_score"] = np.nan  # one train CVE without CVSS
    for name, table in (("train", train), ("test", test)):
        out = table.copy()
        out["exploit_first_date"] = ""
        out.to_csv(
            splits / f"{name}_2024-01-01.csv", index=False, date_format="%Y-%m-%dT%H:%M:%S.%fZ"
        )

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # lifelines may warn on tiny made-up data
        output_dir = main(
            settings, cohorts=("post_kev",), cutoffs=(date(2024, 1, 1),), n_resamples=5, workers=1
        )

    assert output_dir == tmp_path / "outputs" / "b_survival" / "models"
    metrics = pd.read_csv(output_dir / "metrics.csv")
    assert list(metrics["model"]) == [
        "cox",
        "cox_breslow",
        "cvss_cox",
        "cvss_rank",
        "km_reference",
    ]
    assert (metrics["train_left_out_no_cvss"] == 1).all()
    assert metrics["c_index"].between(0, 1).all()
    assert metrics.loc[metrics["model"] == "km_reference", "c_index"].iloc[0] == 0.5
    assert metrics.loc[metrics["model"] == "cvss_rank", "brier_30d"].isna().all()
    assert metrics.loc[metrics["model"] == "km_reference", "brier_skill_365d"].iloc[0] == 0
    ratios = pd.read_csv(output_dir / "hazard_ratios.csv")
    assert set(ratios["model"]) == {"cox", "cvss_cox"}
    check = pd.read_csv(output_dir / "ph_check.csv")
    assert len(check) > 0


def test_brier_skill_is_relative_to_the_km_reference_of_the_same_split():
    metrics = pd.DataFrame(
        {
            "cohort": ["a", "a", "a", "b", "b"],
            "cutoff": ["2024-01-01"] * 5,
            "model": ["cox", "km_reference", "cvss_rank", "cox", "km_reference"],
            "brier_365d": [0.008, 0.010, np.nan, 0.02, 0.02],
        }
    )

    skill = add_brier_skill(metrics)["brier_skill_365d"].to_numpy()

    assert skill[0] == pytest.approx(0.2)
    assert skill[1] == 0
    assert np.isnan(skill[2])
    assert skill[3] == 0


# --- Piecewise-constant baseline hazard --------------------------------------


def test_merge_bands_joins_bands_until_each_has_enough_events():
    starts = (0, 30, 90, 180, 365, 730)

    assert merge_bands(starts, [12, 3, 4, 5, 20, 2], min_events=10) == [0, 30, 365]
    assert merge_bands(starts, [10, 10, 10, 10, 10, 10], min_events=10) == list(starts)
    assert merge_bands(starts, [1, 1, 1, 1, 1, 1], min_events=10) == [0]


def test_piecewise_rate_is_events_over_weighted_days_at_risk():
    # Band 0-30: two events (days 10, 20); band 30+: one event (day 40)
    durations = [10, 20, 40, 100]
    events = [1, 1, 1, 0]
    partial = [1.0, 2.0, 1.0, 0.5]

    starts, rates = piecewise_baseline(durations, events, partial, edges=(0, 30))

    # min_events=10 merges both bands into one: 3 events / (10 + 40 + 40 + 50) days
    assert starts.tolist() == [0.0]
    assert rates == pytest.approx([3 / (10 * 1 + 20 * 2 + 40 * 1 + 100 * 0.5)])


def test_cumulative_hazard_adds_up_the_days_in_each_band():
    starts, rates = np.array([0.0, 30.0]), np.array([0.01, 0.002])

    values = cumulative_hazard(starts, rates, [0, 15, 30, 130])

    assert values == pytest.approx([0, 0.15, 0.3, 0.3 + 100 * 0.002])


def test_the_piecewise_baseline_never_gives_exactly_zero(models, train):
    cox = models["cox"]
    ages = np.linspace(0, cox.train_max_follow_up - 30, len(train))

    estimates = cox.listed_within_next(train, ages, 30)

    assert (estimates > 0).all()
    assert (np.diff(cox.band_starts) > 0).all()
    assert (cox.band_rates > 0).all()


def test_cox_breslow_has_the_same_ranking_as_cox(models, train):
    result = predictions(models, train.head(50))

    assert result["cox_breslow"][0] == pytest.approx(result["cox"][0])
    assert result["cox_breslow"][1].shape == result["cox"][1].shape
