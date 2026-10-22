"""Tests for score_export. Small made-up data, no real files.

D's file check (d_fusion.fusion._read_component) is called here, in a test only:
Component B's code never imports another component.
"""

import json
from datetime import UTC, date, datetime

import numpy as np
import pandas as pd
import pytest

from vesper.components.b_survival.cox_model import fit_cox
from vesper.components.b_survival.score_export import (
    HORIZON_DAYS,
    PERCENTILE_SEMANTICS,
    RAW_SEMANTICS,
    SCORE_COLUMNS,
    build_timing_scores,
    export_scores,
    fit_scoring_model,
    main,
    model_version,
    percentile_ranks,
    percentile_scores,
    start_of_day,
)
from vesper.components.b_survival.survival_table import OUTPUT_COLUMNS
from vesper.components.d_fusion.fusion import _read_component
from vesper.config import load_settings
from vesper.contracts.score import ScoreStatus

DECISION = start_of_day(date(2024, 6, 1))


def cve_rows(n, seed=0, start="2022-01-01", days=850):
    """Made-up survival rows published from `start` over `days` days.

    Higher CVSS is listed sooner. Follow-up runs to 2024-06-01 (the decision day).
    """
    rng = np.random.default_rng(seed)
    published = pd.Timestamp(start, tz="UTC") + pd.to_timedelta(rng.integers(0, days, n), "D")
    follow_up = (DECISION.date() - published.date).astype("timedelta64[D]").astype(int)
    score = rng.choice([4.3, 5.5, 6.5, 7.5, 8.8, 9.8], n)
    time_to_listing = np.floor(rng.exponential(3000 / np.exp(0.9 * (score - 7))))
    event = (time_to_listing < follow_up).astype(int)
    table = pd.DataFrame(
        {
            "cve_id": [f"CVE-2022-{10000 + i}" for i in range(n)],
            "published_at": published,
            "duration_days": np.where(event == 1, time_to_listing, follow_up).astype(int),
            "event": event,
            "already_exploited": False,
            "kev_launch_group": False,
            "cvss_base_score": score,
            "cvss_attack_vector": rng.choice(["NETWORK", "LOCAL"], n),
            "cvss_attack_complexity": rng.choice(["LOW", "HIGH"], n),
            "cvss_privileges_required": rng.choice(["NONE", "LOW"], n),
            "cvss_user_interaction": rng.choice(["NONE", "REQUIRED"], n),
            "cvss_missing": False,
            "cvss_is_primary": pd.array([True] * n, dtype="boolean"),
            "cwe_ids": rng.choice(["CWE-79", "CWE-89", None], n),
            "exploit_at_publication": False,
            "exploit_first_date": pd.Series(pd.NaT, index=range(n), dtype="datetime64[ns, UTC]"),
        }
    )
    return table[OUTPUT_COLUMNS]


def add_row(table, cve_id, published, duration, event=0, cvss=7.5, already=False):
    row = table.iloc[[0]].copy()
    row["cve_id"] = cve_id
    row["published_at"] = pd.Timestamp(published, tz="UTC")
    row["duration_days"] = duration
    row["event"] = event
    row["already_exploited"] = already
    row["cvss_base_score"] = cvss
    return pd.concat([table, row], ignore_index=True)


@pytest.fixture(scope="module")
def table():
    table = cve_rows(800, seed=3)
    # Listed in KEV on 2024-03-01, before the decision day
    table = add_row(table, "CVE-2023-0001", "2023-03-01", 366, event=1)
    # Listed exactly on the decision day: not known yet at 00:00
    table = add_row(table, "CVE-2023-0002", "2023-06-01", 366, event=1)
    # Listed before publication
    table = add_row(table, "CVE-2023-0003", "2023-07-01", -10, event=1, already=True)
    # Published before KEV started: outside the post_kev cohort
    table = add_row(table, "CVE-2021-0001", "2021-06-01", 1096)
    # No CVSS score
    table = add_row(table, "CVE-2024-0001", "2024-05-01", 31, cvss=np.nan)
    # Published after the decision time: not scored at all
    table = add_row(table, "CVE-2024-0002", "2024-06-02", 0)
    return table


@pytest.fixture(scope="module")
def model(table):
    return fit_scoring_model(table, DECISION)


@pytest.fixture(scope="module")
def records(table, model):
    return build_timing_scores(table, model, decision_time=DECISION, trained_through=DECISION)


def by_id(records):
    return {record.cve_id: record for record in records}


# --- The conditional estimate ---------------------------------------------------


def test_the_estimate_at_age_zero_is_listed_by_the_horizon(table):
    train = table[table["cvss_base_score"].notna() & ~table["already_exploited"]].head(500)
    cox = fit_cox(train)
    rows = train.head(20)

    conditional = cox.listed_within_next(rows, np.zeros(20), 30)

    assert conditional == pytest.approx(cox.listed_by(rows, (30,))[:, 0], rel=1e-9)


def test_the_estimate_at_an_age_is_one_minus_a_ratio_of_survival(table):
    train = table[table["cvss_base_score"].notna() & ~table["already_exploited"]].head(500)
    cox = fit_cox(train)
    rows = train.head(10)
    survival = 1 - cox.listed_by(rows, (200, 230))

    expected = 1 - survival[:, 1] / survival[:, 0]

    assert cox.listed_within_next(rows, np.full(10, 200.0), 30) == pytest.approx(expected)


# --- Statuses and scores ----------------------------------------------------------


def test_one_row_per_cve_published_before_the_decision_time(table, records):
    ids = [record.cve_id for record in records]

    assert len(ids) == len(set(ids))
    assert "CVE-2024-0002" not in ids
    assert len(ids) == len(table) - 1


def test_each_special_case_gets_its_status(records):
    rows = by_id(records)

    assert rows["CVE-2023-0001"].status is ScoreStatus.ALREADY_EXPLOITED
    assert rows["CVE-2023-0003"].status is ScoreStatus.ALREADY_EXPLOITED
    assert rows["CVE-2023-0002"].status is ScoreStatus.AVAILABLE
    assert rows["CVE-2021-0001"].status is ScoreStatus.NOT_ELIGIBLE
    assert rows["CVE-2024-0001"].status is ScoreStatus.ABSTAINED
    assert "CVSS" in rows["CVE-2024-0001"].reason


def test_status_and_score_agree(records):
    for record in records:
        if record.status is ScoreStatus.AVAILABLE:
            assert 0.0 <= record.score <= 1.0
            assert record.reason is None
        else:
            assert record.score is None
            assert record.reason


def test_a_cve_whose_horizon_passes_the_train_follow_up_abstains(table, model):
    old = add_row(table, "CVE-2021-9999", "2021-11-03", 941)
    late = start_of_day(date(2024, 6, 1))

    rows = by_id(build_timing_scores(old, model, decision_time=late, trained_through=late))

    assert model.train_max_follow_up < 941 + HORIZON_DAYS
    assert rows["CVE-2021-9999"].status is ScoreStatus.ABSTAINED
    assert "follow-up" in rows["CVE-2021-9999"].reason


def test_higher_cvss_gets_a_higher_score_at_the_same_age(table, model):
    # Two CVEs that differ only in their CVSS score
    pair = add_row(table.iloc[:1], "CVE-2024-1001", "2024-05-01", 31, cvss=9.8)
    pair = add_row(pair, "CVE-2024-1002", "2024-05-01", 31, cvss=4.3).iloc[1:]

    rows = by_id(build_timing_scores(pair, model, decision_time=DECISION, trained_through=DECISION))

    assert rows["CVE-2024-1001"].score > rows["CVE-2024-1002"].score


# --- Time rules -------------------------------------------------------------------


def test_every_record_has_aware_times_and_trained_through_not_after_decision(records):
    for record in records:
        assert record.decision_time.tzinfo is not None
        assert record.trained_through.tzinfo is not None
        assert record.trained_through <= record.decision_time
        assert record.horizon_days == HORIZON_DAYS
        assert record.model_version == "b_survival-cox-2024-06-01-0.2"


def test_a_model_trained_after_the_decision_time_is_refused(table, model):
    later = start_of_day(date(2024, 7, 1))

    with pytest.raises(ValueError, match="trained_through"):
        build_timing_scores(table, model, decision_time=DECISION, trained_through=later)


def test_a_naive_decision_time_is_refused(table, model):
    naive = datetime(2024, 6, 1)

    with pytest.raises(ValueError, match="time zone"):
        build_timing_scores(table, model, decision_time=naive, trained_through=DECISION)


def test_the_scoring_model_sees_nothing_from_after_trained_through(table):
    cutoff = start_of_day(date(2023, 1, 1))

    model = fit_scoring_model(table, cutoff)

    before = table[
        (table["published_at"] >= pd.Timestamp("2021-11-03", tz="UTC"))
        & (table["published_at"] < pd.Timestamp(cutoff))
        & ~table["already_exploited"]
        & table["cvss_base_score"].notna()
    ]
    assert model.train_rows == len(before)
    assert model.train_max_follow_up <= (cutoff.date() - date(2021, 11, 3)).days
    assert model_version(cutoff) == "b_survival-cox-2023-01-01-0.2"


# --- Percentile scores ----------------------------------------------------------


def test_percentile_ranks_are_in_zero_one_and_ties_share_the_average_rank():
    ranks = percentile_ranks([0.2, 0.1, 0.2, 0.4])

    assert ranks.tolist() == pytest.approx([0.625, 0.25, 0.625, 1.0])
    assert ranks.min() > 0


def test_percentile_scores_keep_ids_statuses_and_reasons(records):
    ranked = percentile_scores(records, DECISION)

    for raw, new in zip(records, ranked, strict=True):
        assert (new.cve_id, new.status, new.reason) == (raw.cve_id, raw.status, raw.reason)
        assert (new.score is None) == (raw.score is None)
        assert new.model_version == "b_survival-cox-percentile-2024-06-01-0.2"


def test_percentile_order_equals_raw_order(records):
    ranked = percentile_scores(records, DECISION)

    raw = np.array([r.score for r in records if r.score is not None])
    new = np.array([r.score for r in ranked if r.score is not None])
    # Every pair is in the same order, and equal raw values get equal percentiles
    assert (np.sign(raw[:, None] - raw[None, :]) == np.sign(new[:, None] - new[None, :])).all()
    assert new.max() == pytest.approx(1.0)
    assert 0 < new.min()


# --- The files for Component D ----------------------------------------------------


def test_the_file_has_d_columns_and_passes_d_checks(records, model, tmp_path):
    path = tmp_path / "b_exploit_timing_scores.csv"

    counts = export_scores(percentile_scores(records, DECISION), path, model, PERCENTILE_SEMANTICS)

    frame = _read_component(path, "b_survival")
    assert list(pd.read_csv(path).columns) == SCORE_COLUMNS
    assert len(frame) == len(records)
    assert sum(counts.values()) == len(records)
    metadata = json.loads((tmp_path / (path.name + ".metadata.json")).read_text())
    assert metadata["score_kind"] == "ranking_score"
    assert metadata["status_counts"] == counts
    parsed = pd.to_datetime(frame["decision_time"], utc=True)
    assert (parsed == pd.Timestamp(DECISION)).all()


def test_the_raw_file_also_passes_d_checks(records, model, tmp_path):
    path = tmp_path / "b_exploit_timing_probability.csv"

    export_scores(records, path, model, RAW_SEMANTICS)

    assert len(_read_component(path, "b_survival")) == len(records)


def write_table(table, settings):
    folder = settings.data_processed / "b_survival"
    folder.mkdir(parents=True)
    saved = table.copy()
    saved["exploit_first_date"] = saved["exploit_first_date"].dt.strftime("%Y-%m-%d")
    saved.to_csv(folder / "survival_table.csv", index=False, date_format="%Y-%m-%dT%H:%M:%S.%fZ")


def test_main_writes_both_files_with_the_same_cves_and_statuses(table, tmp_path):
    settings = load_settings(tmp_path)
    write_table(table, settings)

    path = main(settings, decision_time=DECISION)

    folder = settings.outputs / "b_survival"
    assert path == folder / "b_exploit_timing_scores.csv"
    ranked = _read_component(path, "b_survival")
    raw = _read_component(folder / "b_exploit_timing_probability.csv", "b_survival")
    assert ranked["cve_id"].tolist() == raw["cve_id"].tolist()
    assert ranked["status"].tolist() == raw["status"].tolist()
    assert ranked["reason"].fillna("").tolist() == raw["reason"].fillna("").tolist()
    assert ranked["trained_through"].iloc[0] == datetime(2024, 6, 1, tzinfo=UTC).isoformat()
    metadata = json.loads((folder / "b_exploit_timing_scores.csv.metadata.json").read_text())
    assert metadata["source_file"] == "b_exploit_timing_probability.csv"
    assert metadata["source_model_version"] == "b_survival-cox-2024-06-01-0.2"
    assert metadata["percentile_population"] == int((raw["status"] == "available").sum())


def test_main_takes_the_decision_time_and_snapshot_date(table, tmp_path):
    settings = load_settings(tmp_path)
    write_table(table, settings)
    late = datetime(2024, 6, 1, 23, 59, 59, tzinfo=UTC)

    frame = _read_component(
        main(settings, decision_time=late, snapshot_date=date(2024, 6, 1)), "b_survival"
    )

    assert set(frame["decision_time"]) == {"2024-06-01T23:59:59+00:00"}
    assert set(frame["snapshot_date"]) == {"2024-06-01"}
    # trained_through is the start of the decision day
    assert set(frame["trained_through"]) == {"2024-06-01T00:00:00+00:00"}
