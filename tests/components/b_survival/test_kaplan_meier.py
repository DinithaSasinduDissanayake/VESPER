"""Tests for kaplan_meier."""

import pandas as pd
import pytest

from vesper.components.b_survival.kaplan_meier import (
    MISSING,
    NOT_REACHED,
    OTHER,
    add_groups,
    analysis_rows,
    cwe_group,
    exploit_comparison,
    fit_km,
    holm_adjust,
    incidence_at,
    incidence_cell,
    logrank_tests,
    main,
    median_days,
    severity_band,
    summarize_group,
    summarize_grouping,
    top_cwe_ids,
)
from vesper.components.b_survival.survival_table import OUTPUT_COLUMNS
from vesper.config import load_settings


def survival_table(rows):
    """A made-up survival table.

    A row is (cve_id, published_at, duration_days, event, already_exploited,
    kev_launch_group, cvss_base_score, cvss_attack_vector, cwe_ids,
    exploit_at_publication). The other columns get fixed values.
    """
    table = pd.DataFrame(
        rows,
        columns=[
            "cve_id",
            "published_at",
            "duration_days",
            "event",
            "already_exploited",
            "kev_launch_group",
            "cvss_base_score",
            "cvss_attack_vector",
            "cwe_ids",
            "exploit_at_publication",
        ],
    )
    table["published_at"] = pd.to_datetime(table["published_at"], format="ISO8601", utc=True)
    table["cvss_attack_complexity"] = "LOW"
    table["cvss_privileges_required"] = "NONE"
    table["cvss_user_interaction"] = "NONE"
    table["cvss_missing"] = table["cvss_base_score"].isna()
    table["cvss_is_primary"] = pd.array([True] * len(table), dtype="boolean")
    table["exploit_first_date"] = pd.Series(pd.NaT, index=table.index, dtype="datetime64[ns, UTC]")
    return table[OUTPUT_COLUMNS]


def row(cve_id, duration, event, already=False, launch=False, score=7.5, vector="NETWORK",
        cwe="CWE-79", exploit=False, published="2022-03-01"):  # fmt: skip
    return (cve_id, published, duration, event, already, launch, score, vector, cwe, exploit)


# A small curve that is easy to work out by hand (n = 8):
#   day 10  event      at risk 8 -> S = 7/8
#   day 20  censored
#   day 50  event      at risk 6 -> S = 7/8 * 5/6 = 35/48
#   day 100 censored
#   day 200 event      at risk 4 -> S = 35/48 * 3/4 = 105/192
#   days 400, 500, 600 censored
HAND_ROWS = [
    row("CVE-A", 10, 1),
    row("CVE-B", 20, 0),
    row("CVE-C", 50, 1),
    row("CVE-D", 100, 0),
    row("CVE-E", 200, 1),
    row("CVE-F", 400, 0),
    row("CVE-G", 500, 0),
    row("CVE-H", 600, 0),
]


# --- Rows used ---------------------------------------------------------------


def test_already_exploited_rows_are_dropped_in_both_analyses():
    table = survival_table(
        [
            row("CVE-A", -5, 1, already=True),
            row("CVE-B", 30, 1),
            row("CVE-C", 600, 1, launch=True),
            row("CVE-D", 100, 0),
        ]
    )

    main_rows = analysis_rows(table, "main")
    sensitivity_rows = analysis_rows(table, "sensitivity")

    assert list(main_rows["cve_id"]) == ["CVE-B", "CVE-C", "CVE-D"]
    assert (main_rows["duration_days"] >= 0).all()
    # The sensitivity analysis also drops the KEV launch group
    assert list(sensitivity_rows["cve_id"]) == ["CVE-B", "CVE-D"]


def test_an_unknown_analysis_is_rejected():
    with pytest.raises(ValueError, match="Unknown analysis"):
        analysis_rows(survival_table(HAND_ROWS), "everything")


# --- Groups ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (0.0, "none"),
        (0.1, "low"),
        (3.9, "low"),
        (4.0, "medium"),
        (6.9, "medium"),
        (7.0, "high"),
        (8.9, "high"),
        (9.0, "critical"),
        (10.0, "critical"),
        (None, MISSING),
        (float("nan"), MISSING),
    ],
)
def test_severity_band_follows_the_cvss_v3_scale_and_has_a_missing_group(score, band):
    assert severity_band(score) == band


def test_top_cwe_ids_counts_each_cve_once_and_breaks_ties_by_id():
    cwe_lists = ["CWE-89", "CWE-79;CWE-89", "CWE-79", "CWE-20", None, "CWE-787;CWE-787"]

    # CWE-79 and CWE-89 are in 2 CVEs each; CWE-20 and CWE-787 in 1 each
    assert top_cwe_ids(cwe_lists, top=3) == ["CWE-79", "CWE-89", "CWE-20"]


def test_cwe_group_uses_the_top_ids_then_other_then_missing():
    top_ids = ["CWE-79", "CWE-89"]

    assert cwe_group("CWE-89", top_ids) == "CWE-89"
    # Several CWEs: the highest-ranked top CWE wins, whatever the order in the list
    assert cwe_group("CWE-89;CWE-79", top_ids) == "CWE-79"
    assert cwe_group("CWE-20;CWE-89", top_ids) == "CWE-89"
    assert cwe_group("CWE-20", top_ids) == OTHER
    assert cwe_group(None, top_ids) == MISSING
    assert cwe_group(float("nan"), top_ids) == MISSING
    assert cwe_group("", top_ids) == MISSING


def test_add_groups_puts_every_cve_in_exactly_one_group_per_grouping():
    rows = [
        row("CVE-1", 10, 1, cwe="CWE-79", score=9.8, vector="NETWORK", exploit=True),
        row("CVE-2", 10, 0, cwe="CWE-79;CWE-20", score=None, vector=None),
        row("CVE-3", 10, 0, cwe="CWE-89", score=5.0, vector="LOCAL", published="2023-05-01"),
        row("CVE-4", 10, 0, cwe=None, score=2.0, vector="LOCAL"),
    ]

    grouped = add_groups(survival_table(rows)).set_index("cve_id")

    assert grouped["severity"].to_dict() == {
        "CVE-1": "critical",
        "CVE-2": MISSING,
        "CVE-3": "medium",
        "CVE-4": "low",
    }
    assert grouped["attack_vector"].to_dict() == {
        "CVE-1": "NETWORK",
        "CVE-2": MISSING,
        "CVE-3": "LOCAL",
        "CVE-4": "LOCAL",
    }
    assert grouped["exploit_at_publication"].to_dict() == {
        "CVE-1": "yes",
        "CVE-2": "no",
        "CVE-3": "no",
        "CVE-4": "no",
    }
    assert grouped.loc["CVE-2", "cwe"] == "CWE-79"
    assert grouped.loc["CVE-4", "cwe"] == MISSING
    assert grouped["year"].to_dict() == {
        "CVE-1": "2022",
        "CVE-2": "2022",
        "CVE-3": "2023",
        "CVE-4": "2022",
    }


# --- Kaplan-Meier numbers ----------------------------------------------------


def test_incidence_at_30_90_365_days_matches_the_hand_calculation():
    table = survival_table(HAND_ROWS)
    kmf = fit_km(table["duration_days"], table["event"])

    assert incidence_at(kmf, 30, 600)[0] == pytest.approx(1 / 8)
    assert incidence_at(kmf, 90, 600)[0] == pytest.approx(1 - 35 / 48)
    assert incidence_at(kmf, 365, 600)[0] == pytest.approx(1 - 105 / 192)


def test_the_interval_contains_the_estimate():
    table = survival_table(HAND_ROWS)
    kmf = fit_km(table["duration_days"], table["event"])

    estimate, lower, upper = incidence_at(kmf, 365, 600)

    assert lower < estimate < upper


def test_median_is_not_reached_when_incidence_stays_under_half():
    table = survival_table(HAND_ROWS)  # the lowest S(t) is 105/192, above 0.5

    assert median_days(fit_km(table["duration_days"], table["event"])) == NOT_REACHED


def test_median_is_reported_when_it_is_reached():
    table = survival_table([row("CVE-A", 10, 1), row("CVE-B", 20, 1), row("CVE-C", 30, 0)])

    assert median_days(fit_km(table["duration_days"], table["event"])) == 20.0


def test_no_incidence_is_given_after_the_follow_up_ends():
    table = survival_table([row("CVE-A", 10, 1), row("CVE-B", 200, 0)])
    kmf = fit_km(table["duration_days"], table["event"])

    assert incidence_at(kmf, 365, 200) == (None, None, None)


def test_no_events_gives_zero_and_no_interval():
    table = survival_table([row("CVE-A", 400, 0), row("CVE-B", 500, 0), row("CVE-C", 50, 1)])
    kmf = fit_km(table["duration_days"], table["event"])

    assert incidence_at(kmf, 30, 500) == (0.0, None, None)
    assert incidence_cell(0.0, None, None) == "0.00 (no events)"
    assert incidence_cell(None, None, None) == "-"
    assert incidence_cell(0.125, 0.02, 0.6) == "12.50 (2.00-60.00)"


def test_summarize_group_counts_rows_and_events():
    summary, _ = summarize_group(survival_table(HAND_ROWS), "main", "overall", "all CVEs")

    assert summary["n"] == 8
    assert summary["events"] == 3
    assert summary["last_follow_up_days"] == 600
    assert summary["incidence_30d"] == pytest.approx(0.125)
    assert summary["median_days"] == NOT_REACHED


# --- Log-rank ----------------------------------------------------------------


def two_different_groups():
    fast = [row(f"CVE-F{i}", 5 + i, 1, score=9.8) for i in range(20)]
    slow = [row(f"CVE-S{i}", 900, 0, score=5.0) for i in range(18)]
    slow += [row("CVE-S18", 800, 1, score=5.0), row("CVE-S19", 850, 1, score=5.0)]
    return add_groups(survival_table(fast + slow))


def test_logrank_gives_a_small_p_value_for_two_clearly_different_groups():
    results = logrank_tests(two_different_groups(), "main", "severity")

    assert len(results) == 1  # two groups: no pairwise tests
    assert results[0]["test"] == "overall"
    assert results[0]["degrees_of_freedom"] == 1
    assert 0 <= results[0]["p_value"] < 0.001


def test_logrank_adds_holm_corrected_pairwise_tests_for_more_than_two_groups():
    grouped = two_different_groups()
    extra = add_groups(survival_table([row(f"CVE-L{i}", 300, i % 2, score=2.0) for i in range(10)]))
    grouped = pd.concat([grouped, extra], ignore_index=True)

    results = logrank_tests(grouped, "main", "severity")

    pairwise = [result for result in results if result["test"] == "pairwise"]
    assert results[0]["degrees_of_freedom"] == 2
    assert len(pairwise) == 3
    for result in pairwise:
        assert result["p_value"] <= result["p_value_holm"] <= 1


def test_logrank_is_skipped_for_a_single_group():
    grouped = add_groups(survival_table(HAND_ROWS))

    assert logrank_tests(grouped, "main", "attack_vector") == []


def test_holm_adjust_matches_a_hand_calculation():
    # Sorted: 0.01 * 3 = 0.03; 0.03 * 2 = 0.06; 0.04 * 1 = 0.04 -> raised to 0.06
    assert holm_adjust([0.01, 0.04, 0.03]) == pytest.approx([0.03, 0.06, 0.06])
    assert holm_adjust([0.5, 0.9]) == pytest.approx([1.0, 1.0])
    assert holm_adjust([]) == []


# --- The whole run -----------------------------------------------------------


def test_main_writes_the_figures_and_the_two_csv_files(tmp_path):
    # A made-up project folder, so the real data and outputs are never touched
    settings = load_settings(tmp_path)
    processed = settings.data_processed / "b_survival"
    processed.mkdir(parents=True)
    rows = [
        row(
            f"CVE-{i}",
            10 + 37 * i,
            int(i % 4 == 0),
            score=[9.8, 7.5, 5.0][i % 3],
            vector=["NETWORK", "LOCAL"][i % 2],
            cwe=["CWE-79", "CWE-89", None][i % 3],
            exploit=i % 5 == 0,
            published=["2022-03-01", "2023-03-01"][i % 2],
        )  # fmt: skip
        for i in range(30)
    ]
    rows.append(row("CVE-X", -3, 1, already=True))
    rows.append(row("CVE-Y", 700, 1, launch=True, published="2020-01-01"))
    table = survival_table(rows)
    out = table.copy()
    out["exploit_first_date"] = ""
    out.to_csv(processed / "survival_table.csv", index=False, date_format="%Y-%m-%dT%H:%M:%S.%fZ")

    base_dir = main(settings)

    assert base_dir == tmp_path / "outputs" / "b_survival" / "kaplan_meier"
    assert sorted(path.name for path in base_dir.iterdir()) == ["full", "post_kev"]
    for cohort in ("full", "post_kev"):
        names = {path.name for path in (base_dir / cohort).iterdir()}
        assert {"km_summary.csv", "logrank_results.csv"} <= names
        assert "km_main_severity.png" in names
        assert "km_sensitivity_year.png" in names
        logrank = pd.read_csv(base_dir / cohort / "logrank_results.csv")
        assert set(logrank["test"]) <= {"overall", "pairwise"}
        assert logrank["p_value"].between(0, 1).all()
        assert set(logrank["cohort"]) == {cohort}

    summary = pd.read_csv(base_dir / "full" / "km_summary.csv")
    overall = summary[(summary["grouping"] == "overall")].set_index("analysis")
    assert overall.loc["main", "n"] == 31  # CVE-X (already exploited) is left out
    assert overall.loc["sensitivity", "n"] == 30  # CVE-Y (launch group) is left out too

    # post_kev: CVE-Y (published 2020) is not in the cohort at all
    summary = pd.read_csv(base_dir / "post_kev" / "km_summary.csv")
    overall = summary[(summary["grouping"] == "overall")].set_index("analysis")
    assert overall.loc["main", "n"] == 30
    assert overall.loc["sensitivity", "n"] == 30
    assert set(summary["cohort"]) == {"post_kev"}


def test_exploit_comparison_gives_yes_and_no_with_the_logrank_p():
    rows = [row(f"CVE-Y{i}", 5 + i, 1, exploit=True) for i in range(5)]
    # One censored "yes" CVE watched past day 365, so the 365-day value exists
    rows += [row("CVE-Y5", 400, 0, exploit=True)]
    rows += [row(f"CVE-N{i}", 900, 0) for i in range(20)]
    rows += [row("CVE-N20", 800, 1)]
    grouped = add_groups(survival_table(rows))
    summary_rows, _ = summarize_grouping(grouped, "main", "exploit_at_publication")
    summary = pd.DataFrame(summary_rows)
    logrank = pd.DataFrame(logrank_tests(grouped, "main", "exploit_at_publication"))

    comparison = exploit_comparison(summary, logrank)

    assert comparison["yes"]["n"] == 6
    assert comparison["yes"]["events"] == 5
    assert comparison["yes"]["incidence_365d"] == pytest.approx(5 / 6)
    assert comparison["no"]["n"] == 21
    assert comparison["no"]["events"] == 1
    assert comparison["no"]["incidence_365d"] == 0.0
    assert 0 <= comparison["logrank_p"] < 0.001
