"""
Build the survival table: one row per study CVE.

The table says, for every CVE: when the clock started (publication), how long
it was watched (duration), and whether the event happened (listed in KEV) or
not (censored: not exploited YET, which is not the same as "safe").

Input:   the linked table of link_sources.py (made in memory)
Output:  data/processed/b_survival/survival_table.csv

Columns of the output, in four groups:

  Identity
    cve_id, published_at

  Outcome (made from KEV; never used as inputs)
    duration_days       calendar days from the publication day to the KEV day if
                        the CVE is in KEV, otherwise to the snapshot day
    event               1 if listed in KEV up to the snapshot, 0 if censored
    already_exploited   True if the KEV day is before the publication day
    kev_launch_group    True if the KEV day is 2021-11-03, the day KEV started

  Day-0 inputs (only what is known on the publication day)
    cvss_base_score, cvss_attack_vector, cvss_attack_complexity,
    cvss_privileges_required, cvss_user_interaction, cvss_missing,
    cvss_is_primary, cwe_ids, exploit_at_publication

  Time-varying input (for the model that lets the exploit appear later)
    exploit_first_date  day the first public exploit appeared (empty if none)

The KEV date itself is NOT written to the table, so nobody can use it as an
input by accident.

The rules (each one is also explained in data_decisions.md):
  - Duration counts calendar days (UTC) and is the same as in eda.py.
  - A CVE listed on its publication day has duration 0 and stays an event.
  - A negative duration is not clipped. Those CVEs stay in the table and are
    flagged by already_exploited.
  - There is no plain "has any exploit" column. An exploit that appears after
    the publication day was not known on the publication day, so a column that
    says "this CVE has an exploit" would give a model information from the
    future (look-ahead leakage). Only exploit_at_publication is a Day-0 input.
  - CVSS and CWE are the values on the download days, not on the publication
    day (see decision 3 in data_decisions.md), so results are "retrospective".

Run from anywhere (run the three clean_ modules first):
    uv run python -m vesper.components.b_survival.survival_table
"""

import pandas as pd

from vesper.components.b_survival.link_sources import (
    as_day,
    link_sources,
    load_clean_tables,
)
from vesper.components.b_survival.link_sources import (
    print_report as print_link_report,
)
from vesper.components.b_survival.study_design import PROCESSED_SUBFOLDER, SNAPSHOT_DATE
from vesper.config import load_settings

OUTPUT_FILE_NAME = "survival_table.csv"

IDENTITY_COLUMNS = ["cve_id", "published_at"]
OUTCOME_COLUMNS = ["duration_days", "event", "already_exploited", "kev_launch_group"]
# Inputs known on the publication day (the only columns a model may use as fixed inputs)
INPUT_COLUMNS = [
    "cvss_base_score",
    "cvss_attack_vector",
    "cvss_attack_complexity",
    "cvss_privileges_required",
    "cvss_user_interaction",
    "cvss_missing",
    "cvss_is_primary",
    "cwe_ids",
    "exploit_at_publication",
]
TIME_VARYING_COLUMNS = ["exploit_first_date"]
OUTPUT_COLUMNS = IDENTITY_COLUMNS + OUTCOME_COLUMNS + INPUT_COLUMNS + TIME_VARYING_COLUMNS

# How dates are written in the CSV: ISO 8601 with "Z" (UTC), like the clean tables
CSV_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


# ---------------------------------------------------------------------------
# Building the table
# ---------------------------------------------------------------------------


def build_survival_table(linked, snapshot_date=SNAPSHOT_DATE):
    """Turn the linked table into the survival table (one row per CVE).

    `linked` is the table returned by link_sources.link_sources().
    """
    snapshot = as_day(snapshot_date)
    published_day = linked["published_at"].dt.normalize()
    in_kev = linked["in_kev"].astype(bool)
    kev_day = linked["kev_date_added"].dt.normalize()

    # --- Outcome: the KEV date is used here, and only here ---------------------
    # The clock stops at the KEV day if the CVE is in KEV, else at the snapshot.
    stop_day = kev_day.where(in_kev, snapshot)
    duration_days = (stop_day - published_day).dt.days
    event = in_kev.astype(int)
    already_exploited = in_kev & (kev_day < published_day)
    kev_launch_group = in_kev & linked["added_on_kev_start_date"].astype(bool)

    # --- Day-0 inputs: nothing below reads a KEV column ------------------------
    first_exploit_day = linked["first_exploit_date"].dt.normalize()
    # An empty date compares as False: no exploit, so no exploit at publication
    exploit_at_publication = first_exploit_day <= published_day

    table = pd.DataFrame(
        {
            "cve_id": linked["cve_id"],
            "published_at": linked["published_at"],
            "duration_days": duration_days,
            "event": event,
            "already_exploited": already_exploited,
            "kev_launch_group": kev_launch_group,
            "cvss_base_score": linked["cvss_base_score"],
            "cvss_attack_vector": linked["cvss_attack_vector"],
            "cvss_attack_complexity": linked["cvss_attack_complexity"],
            "cvss_privileges_required": linked["cvss_privileges_required"],
            "cvss_user_interaction": linked["cvss_user_interaction"],
            "cvss_missing": linked["cvss_missing"].astype(bool),
            "cvss_is_primary": linked["cvss_is_primary"],
            "cwe_ids": linked["cwe_ids"],
            "exploit_at_publication": exploit_at_publication,
            "exploit_first_date": first_exploit_day,
        }
    )
    return table[OUTPUT_COLUMNS].reset_index(drop=True)


# ---------------------------------------------------------------------------
# Checks. Each one returns the NUMBER OF ROWS THAT BREAK THE RULE (0 = good).
# ---------------------------------------------------------------------------


def check_no_duplicate_cve_ids(table):
    """Rows whose CVE ID appears more than once."""
    return int(table["cve_id"].duplicated(keep=False).sum())


def check_event_is_zero_or_one(table):
    """Rows where `event` is not 0 or 1."""
    return int((~table["event"].isin([0, 1])).sum())


def check_no_publication_after_snapshot(table, snapshot_date=SNAPSHOT_DATE):
    """Rows published on a day after the snapshot date."""
    return int((table["published_at"].dt.normalize() > as_day(snapshot_date)).sum())


def check_duration_not_negative(table):
    """Rows with a negative duration that are not flagged as already_exploited."""
    return int(((table["duration_days"] < 0) & ~table["already_exploited"]).sum())


def check_row_count(table, expected_rows):
    """How many rows the table is away from the expected number of study CVEs."""
    return abs(len(table) - expected_rows)


def run_checks(table, expected_rows, snapshot_date=SNAPSHOT_DATE):
    """Run every check. Returns {check name: number of rows that break the rule}."""
    return {
        "no duplicate CVE IDs": check_no_duplicate_cve_ids(table),
        "event is only 0 or 1": check_event_is_zero_or_one(table),
        "no publication date after the snapshot": check_no_publication_after_snapshot(
            table, snapshot_date
        ),
        "duration never negative, except already_exploited": check_duration_not_negative(table),
        "row count equals the study CVE count": check_row_count(table, expected_rows),
    }


# ---------------------------------------------------------------------------
# Summary and main program
# ---------------------------------------------------------------------------


def summarize(table):
    """Count the things the survival table should be reported with."""
    events = table[table["event"] == 1]
    return {
        "rows": len(table),
        "events": len(events),
        "censored": int((table["event"] == 0).sum()),
        "already_exploited": int(table["already_exploited"].sum()),
        "kev_launch_group": int(table["kev_launch_group"].sum()),
        "zero_day_events": int((events["duration_days"] == 0).sum()),
        "percent_exploit_at_publication_among_events": _percent(events["exploit_at_publication"]),
        "percent_exploit_at_publication_among_all": _percent(table["exploit_at_publication"]),
        "median_duration_events": _median(events["duration_days"]),
        "median_duration_events_not_already_exploited": _median(
            events.loc[~events["already_exploited"], "duration_days"]
        ),
    }


def _percent(flags):
    return 100 * flags.mean() if len(flags) else None


def _median(days):
    return float(days.median()) if len(days) else None


def print_summary(summary, checks):
    """Print the numbers of the table and the result of every check."""
    print("Survival table")
    print("  Rows (one per study CVE):", summary["rows"])
    print("  Events (listed in KEV up to the snapshot):", summary["events"])
    print("  Censored (not in KEV):", summary["censored"])
    print("  already_exploited (listed before publication):", summary["already_exploited"])
    print("  kev_launch_group (listed on the KEV start date):", summary["kev_launch_group"])
    print("  Events with duration 0 (listed on the publication day):", summary["zero_day_events"])
    print("  Share with exploit_at_publication")
    share = summary["percent_exploit_at_publication_among_events"]
    print(f"    among events: {share:.2f}%")
    share = summary["percent_exploit_at_publication_among_all"]
    print(f"    among all CVEs: {share:.2f}%")
    print("  Median duration of events (days)")
    print("    all events:", summary["median_duration_events"])
    print("    without already_exploited:", summary["median_duration_events_not_already_exploited"])
    print("  Checks (number of rows that break the rule)")
    for name, problems in checks.items():
        print(f"    {name}: {problems} ({'ok' if problems == 0 else 'FAILED'})")


def main(settings=None):
    """Link the sources, build the table, run the checks, print and save the table."""
    # Folders come from vesper.config
    settings = settings or load_settings()
    processed_dir = settings.data_processed / PROCESSED_SUBFOLDER

    print("Reading:", processed_dir)
    nvd, kev, exploits = load_clean_tables(processed_dir)
    linked, link_report = link_sources(nvd, kev, [exploits])
    print_link_report(link_report)
    print()

    table = build_survival_table(linked)
    checks = run_checks(table, expected_rows=link_report["study_cves"])
    print_summary(summarize(table), checks)

    # A table that fails a check is never saved
    failed = [name for name, problems in checks.items() if problems]
    if failed:
        raise ValueError(f"Survival table not saved. Failed checks: {failed}")

    output_path = processed_dir / OUTPUT_FILE_NAME
    out = table.copy()
    out["exploit_first_date"] = out["exploit_first_date"].dt.strftime("%Y-%m-%d")
    out.to_csv(output_path, index=False, date_format=CSV_DATE_FORMAT)
    print("Saved to:", output_path)
    return output_path


if __name__ == "__main__":
    main()
