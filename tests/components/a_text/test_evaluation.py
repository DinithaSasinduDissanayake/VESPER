import json

import numpy as np
import pandas as pd
import pytest

from vesper.components.a_text import evaluate as e


def utc(day):
    return pd.Timestamp(day, tz="UTC")


def synthetic_cves(end="2023-12-31"):
    """One CVE a day; every 8th says "remote code execution" and enters KEV 10 days later."""
    days = pd.date_range("2021-11-03", end, freq="D", tz="UTC")
    rows = []
    for i, day in enumerate(days):
        exploited = i % 8 == 0
        rows.append(
            {
                "cve_id": f"CVE-{day.year}-{i:05d}",
                "published_date": day,
                "description": f"remote code execution in parser {i % 3}"
                if exploited
                else f"minor display glitch in settings page {i % 5}",
                "kev_date_added": day + pd.Timedelta(days=10) if exploited else pd.NaT,
                "vuln_status": "Analyzed",
                "cvss_base_score": 9.8 if i % 2 == 0 else 5.0,  # ties on purpose
            }
        )
    return pd.DataFrame(rows)


def test_leak_wording_matches_the_experiment_patterns():
    assert e.has_leak_wording("Apple is aware of a report that this issue may have been exploited")
    assert e.has_leak_wording("This flaw was observed in the wild.")
    assert e.has_leak_wording("CISA Known Exploited Vulnerabilities (KEV) Catalog lists it")
    assert e.has_leak_wording("It is being actively targeted")
    # The sanitiser already deletes these, so they are not counted as missed leaks.
    assert not e.has_leak_wording("This was actively exploited in the wild.")
    assert not e.has_leak_wording("Buffer overflow in the parser.")
    assert not e.has_leak_wording(None)


def test_quarters():
    assert e.quarter_start("2024q3") == utc("2024-07-01")
    assert e.quarter_name(utc("2024-07-01")) == "2024Q3"
    frame = synthetic_cves()
    frame["kev_date_added"] = pd.to_datetime(frame.kev_date_added, utc=True)
    # 2023Q3 ends 2023-10-01, its windows close 2023-12-30 <= 2023-12-31; 2023Q4 is open.
    assert [e.quarter_name(q) for q in e.mature_quarters(frame)] == ["2023Q1", "2023Q2", "2023Q3"]


def test_test_cohort_keeps_the_quarter_and_drops_cves_already_in_kev():
    frame = pd.DataFrame(
        {
            "cve_id": ["early", "in", "known", "late_label", "next"],
            "published_date": [
                utc(d)
                for d in ("2023-03-31", "2023-04-01", "2023-05-01", "2023-06-30", "2023-07-01")
            ],
            "kev_date_added": [
                pd.NaT,
                utc("2023-04-20"),
                utc("2023-05-01"),
                utc("2023-10-30"),
                pd.NaT,
            ],
        }
    )
    cohort = e.test_cohort(frame, utc("2023-04-01"))
    assert cohort.cve_id.tolist() == ["in", "late_label"]  # "known" was in KEV at publication
    assert cohort.label.tolist() == [1, 0]  # KEV 122 days after publication is outside 90


def test_top_breaks_ties_by_table_order_and_skips_missing_scores():
    group = pd.DataFrame({"label": [0, 1, 1, 0], "s": [5.0, 5.0, np.nan, 9.0]})
    assert e.top(group, "s", 2).label.tolist() == [0, 0]
    assert e.tie_range(group, "s", 2) == (0, 0.5, 1)  # 1 slot, 2 tied rows, 1 positive


def test_dense_ranks_and_sampled_hits():
    ranks = e.dense_ranks(np.array([3.0, 7.0, 3.0, np.nan]))
    assert ranks.tolist() == [1, 0, 1, -1]
    labels = np.array([1, 0, 0, 1])
    sample = np.array([0, 1, 2, 3])
    # k=2: rank 0 (label 0), then one slot for the tie: the sampled order picks row 0.
    assert e.sampled_hits(labels, ranks, sample, 2) == 1
    assert e.sampled_hits(labels, ranks, np.array([2, 1, 0, 3]), 2) == 0


def test_summarise_counts_hits_and_brackets_the_difference():
    rng = np.random.default_rng(0)
    rows = []
    for quarter in ("2023Q1", "2023Q2"):
        label = (rng.random(300) < 0.1).astype(int)
        rows.append(
            pd.DataFrame(
                {
                    "quarter": quarter,
                    "label": label,
                    "A": label * 2 + rng.random(300),  # A ranks every positive first
                    "CVSS": rng.integers(0, 3, 300).astype(float),
                    "leak_wording": False,
                }
            )
        )
    pred = pd.concat(rows, ignore_index=True)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(e, "HITS_K", 20)
        result = e.summarise(pred, draws=50)
        assert e.summarise(pred, draws=50) == result  # fixed seed: same draws
    positives = [int(g.label.sum()) for _, g in pred.groupby("quarter")]
    a_hits = result["methods"]["A"]["hits@20"]
    assert a_hits["estimate"] == sum(min(20, p) for p in positives)
    diff = result["A_minus_CVSS"]["hits@20"]
    assert diff["lower"] <= diff["estimate"] <= diff["upper"]
    assert result["methods"]["A"]["recall@1000"]["estimate"] == 1.0
    assert [q["quarter"] for q in result["per_quarter"]] == ["2023Q1", "2023Q2"]


def test_main_end_to_end(tmp_path):
    data = tmp_path / "cves.parquet"
    synthetic_cves().to_parquet(data)
    out = tmp_path / "eval"
    result = e.main(
        ["--data", str(data), "--quarters", "2023Q1-2023Q2", "--draws", "20", "--out", str(out)]
    )
    every = result["all_cves"]
    assert every["quarters"] == 2
    assert every["methods"]["A"]["hits@100"]["estimate"] == every["positives"]  # text is perfect
    assert json.loads((out / "evaluation.json").read_text())["seed"] == e.SEED
    table = pd.read_csv(out / "quarters.csv")
    assert set(table.cohort) == {"all_cves", "without_leak_wording"}
    assert (out / "predictions.parquet").exists()


def test_open_quarter_is_refused(tmp_path):
    frame = synthetic_cves()
    frame["kev_date_added"] = pd.to_datetime(frame.kev_date_added, utc=True)
    with pytest.raises(ValueError, match="2023Q4"):
        e.pick_quarters(frame, "2023Q4")
