"""Tests for frontend_export. Small made-up data, no real files."""

import json
from datetime import date

import numpy as np
import pandas as pd
import pytest

from vesper.components.b_survival.frontend_export import (
    BACKTEST_DECISION,
    Scored,
    build_export,
    known,
    level_of,
    listed_in_window,
    main,
    plain_reasons,
    recent_kev,
)
from vesper.components.b_survival.survival_table import OUTPUT_COLUMNS
from vesper.config import load_settings

SNAPSHOT = pd.Timestamp("2026-10-01", tz="UTC")
BACKTEST = pd.Timestamp(BACKTEST_DECISION, tz="UTC")


def cve_rows(n, seed=0):
    """Made-up survival rows published 2021-11 to 2026-08, followed up to the snapshot."""
    rng = np.random.default_rng(seed)
    published = pd.Timestamp("2021-11-03", tz="UTC") + pd.to_timedelta(
        rng.integers(0, 1750, n), "D"
    )
    follow_up = (SNAPSHOT - published).days.to_numpy()
    score = rng.choice([4.3, 5.5, 6.5, 7.5, 8.8, 9.8], n)
    time_to_listing = np.floor(rng.exponential(2500 / np.exp(0.9 * (score - 7))))
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
    # Two CVEs listed in KEV during the back-test window
    for i, listed in ((0, "2026-09-05"), (1, "2026-09-20")):
        table.loc[i, "published_at"] = pd.Timestamp("2025-01-01", tz="UTC")
        table.loc[i, "duration_days"] = (
            pd.Timestamp(listed, tz="UTC") - table.loc[i, "published_at"]
        ).days
        table.loc[i, "event"] = 1
    return table[OUTPUT_COLUMNS]


@pytest.fixture(scope="module")
def table():
    return cve_rows(1200, seed=5)


@pytest.fixture(scope="module")
def exploits(table):
    # One exploit before the back-test decision, one between it and now, one after now
    return pd.DataFrame(
        {
            "exploit_id": [1, 2, 3],
            "cve_id": pd.array([table.loc[0, "cve_id"]] * 3, dtype="string"),
            "date_published": pd.to_datetime(["2025-03-01", "2026-09-10", "2026-10-02"], utc=True),
        }
    )


def write_model_outputs(folder):
    folder.mkdir(parents=True, exist_ok=True)
    rows = []
    for cohort in ("post_kev", "full"):
        for model in ("cox", "cvss_rank"):
            rows.append(
                {
                    "cohort": cohort,
                    "cutoff": "2024-07-01",
                    "model": model,
                    "c_index": 0.77 if model == "cox" else 0.73,
                    "c_index_ci_lower": 0.74,
                    "c_index_ci_upper": 0.80,
                    "p_at_100": 0.03,
                    "p_at_100_ci_lower": 0.01,
                    "p_at_100_ci_upper": 0.05,
                    "train_events": 275,
                    "test_events": 199,
                }
            )
    pd.DataFrame(rows).to_csv(folder / "metrics.csv", index=False)
    pd.DataFrame(
        [
            {
                "cohort": cohort,
                "cutoff": "2024-07-01",
                "model": "cox",
                "compared_with": "cvss_rank",
                "c_index_difference": 0.043,
                "ci_lower": 0.024,
                "ci_upper": 0.063,
                "excludes_zero": True,
            }
            for cohort in ("post_kev", "full")
        ]
    ).to_csv(folder / "c_index_differences.csv", index=False)
    pd.DataFrame(
        [
            {
                "cohort": "post_kev",
                "cutoff": "2024-07-01",
                "model": "cox",
                "feature": "cvss_base_score (per 1 point)",
                "hazard_ratio": 1.11,
                "ci_lower_95": 1.07,
                "ci_upper_95": 1.15,
                "p_value": 0.0001,
            }
        ]
    ).to_csv(folder / "hazard_ratios.csv", index=False)


@pytest.fixture(scope="module")
def document(table, exploits, tmp_path_factory):
    folder = tmp_path_factory.mktemp("models")
    write_model_outputs(folder)
    return build_export(table, exploits, folder, [table.loc[0, "cve_id"], "CVE-2099-0001"])


def test_the_document_has_the_expected_keys(document):
    assert set(document) == {
        "meta",
        "results",
        "levels",
        "top",
        "cves",
        "backtest",
        "recent_kev",
    }
    assert document["meta"]["model_version"].endswith("-0.2")
    assert document["meta"]["horizon_days"] == 30
    assert "current NVD" in document["meta"]["note"]
    assert document["meta"]["sample_queue_missing"] == ["CVE-2099-0001"]
    assert set(document["results"]) >= {
        "main",
        "differences",
        "hazard_ratios",
        "bands",
        "kaplan_meier",
    }
    assert len(document["results"]["kaplan_meier"]["points"]) <= 200
    assert len(document["top"]) == 25
    json.dumps(document)  # every value can be written as JSON


def test_no_evidence_is_dated_on_or_after_the_decision_time(document):
    for context in ("current", "backtest"):
        for detail in document["cves"][context].values():
            decision = detail["decision_time"][:10]
            assert all(item["date"] < decision for item in detail["evidence"])


def test_the_back_test_exploit_after_the_decision_is_not_evidence(table, document):
    detail = document["cves"]["backtest"][table.loc[0, "cve_id"]]

    exploit_days = [e["date"] for e in detail["evidence"] if e["kind"] == "exploit"]
    assert exploit_days == ["2025-03-01"]
    assert detail["kev"] == {"date": "2026-09-05", "after_decision": True}


def test_the_back_test_uses_the_model_trained_before_its_decision_time(table, document):
    for detail in document["cves"]["backtest"].values():
        assert detail["trained_through"] == BACKTEST.isoformat()
        assert detail["model_version"].startswith("b_survival-cox-percentile-2026-09-01")

    # Changing every outcome after the decision time changes no back-test score
    changed = table.copy()
    published_day = changed["published_at"].dt.normalize()
    stop = published_day + pd.to_timedelta(changed["duration_days"], "D")
    after = stop >= BACKTEST
    changed.loc[after, "event"] = 1 - changed.loc[after, "event"]
    before = Scored(table, BACKTEST_DECISION).frame
    again = Scored(changed, BACKTEST_DECISION).frame
    pd.testing.assert_frame_equal(
        before[["raw", "percentile", "rank"]], again[["raw", "percentile", "rank"]]
    )


def test_the_back_test_lists_the_kev_additions_in_the_window(table, document):
    listed = listed_in_window(table, BACKTEST_DECISION)

    assert set(listed) >= {table.loc[0, "cve_id"], table.loc[1, "cve_id"]}
    summary = document["backtest"]
    assert summary["listed"] == len(listed)
    for counts in summary["top_counts"].values():
        assert 0 <= counts["b"] <= summary["scored"]
        assert 0 <= counts["cvss"] <= summary["scored"]


def test_an_available_cve_has_a_curve_that_starts_at_one(document):
    available = [d for d in document["cves"]["current"].values() if d["status"] == "available"]

    assert available
    for detail in available:
        assert detail["survival"][0] == pytest.approx(1.0)
        assert len(detail["survival"]) == 31
        assert detail["raw_30d"] == pytest.approx(1 - detail["survival"][-1], rel=1e-4)
        assert 0 < detail["percentile"] <= 1


def test_main_writes_the_json_in_the_frontend_folder(table, exploits, tmp_path):
    settings = load_settings(tmp_path)
    processed = settings.data_processed / "b_survival"
    processed.mkdir(parents=True)
    saved = table.copy()
    saved["exploit_first_date"] = saved["exploit_first_date"].dt.strftime("%Y-%m-%d")
    saved.to_csv(processed / "survival_table.csv", index=False, date_format="%Y-%m-%dT%H:%M:%S.%fZ")
    exploits.to_csv(processed / "exploitdb_clean.csv", index=False)
    write_model_outputs(settings.outputs / "b_survival" / "models")

    path = main(settings)

    assert path == tmp_path / "frontend" / "public" / "demo" / "exploit_timing.json"
    assert (
        json.loads(path.read_text(encoding="utf-8"))["meta"]["snapshot_date"]
        == date(2026, 10, 1).isoformat()
    )


# --- Plain-language fields -----------------------------------------------------


def test_levels_follow_the_rank_cutoffs():
    assert [level_of(p) for p in (1.0, 0.95, 0.9499, 0.80, 0.7999, 0.01)] == [
        "High",
        "High",
        "Medium",
        "Medium",
        "Low",
        "Low",
    ]
    assert level_of(None) is None


def test_every_cve_has_a_level_and_reasons(document):
    for detail in document["cves"]["current"].values():
        assert detail["reasons"]
        if detail["status"] == "available":
            assert detail["level"] == level_of(detail["percentile"])
            assert detail["reasons"][0].startswith(detail["level"])
        else:
            assert detail["level"] is None
    counts = document["levels"]["counts"]
    total = sum(counts.values())
    assert counts["High"] == pytest.approx(0.05 * total, abs=2)


def test_reasons_follow_the_facts():
    detail = {
        "status": "available",
        "level": "High",
        "percentile": 0.999,
        "rank": 3.0,
        "rank_of": 1000,
        "age_days": 1,
        "cvss": 9.8,
        "evidence": [{"kind": "exploit", "date": "2026-09-20"}],
        "factors": [{"feature": "cwe=CWE-22", "label": "CWE-22", "hazard_ratio": 1.2}],
    }

    reasons = plain_reasons(detail, ratio=8.0)

    assert reasons[0] == "High: #3 of 1,000 vulnerabilities not yet attacked (top 1%)."
    assert reasons[1].startswith("It is new: published 1 day ago.")
    assert "8×" in reasons[1]
    assert "appeared on 2026-09-20" in reasons[2]
    assert "critical (CVSS 9.8)" in reasons[3]
    assert len(reasons) == 4


def test_an_already_exploited_cve_says_patch_now():
    detail = {"status": "already_exploited", "kev": {"date": "2023-02-10"}}

    assert plain_reasons(detail, ratio=8.0) == [
        "Already in the CISA list of attacked vulnerabilities (KEV) since 2023-02-10. Patch it now."
    ]


def test_recent_kev_only_holds_additions_before_the_decision_time():
    records = [
        {"cveID": "CVE-2026-0001", "dateAdded": "2026-08-31"},  # before the window
        {"cveID": "CVE-2026-0002", "dateAdded": "2026-09-01"},
        {"cveID": "CVE-2026-0003", "dateAdded": "2026-09-30"},
        {"cveID": "CVE-2026-0004", "dateAdded": "2026-10-01"},  # on the decision day
    ]

    recent = recent_kev(records, pd.Timestamp("2026-10-01", tz="UTC"))

    assert [item["cve_id"] for item in recent["items"]] == ["CVE-2026-0003", "CVE-2026-0002"]
    assert recent["count"] == 2


def test_known_rejects_placeholder_vendor_names():
    assert known("Apache Software Foundation")
    assert not known("n/a")
    assert not known("")
    assert not known(None)
