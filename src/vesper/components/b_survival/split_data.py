"""Chronological train/test split of the survival table."""

import pandas as pd

from vesper.components.b_survival.link_sources import as_day
from vesper.components.b_survival.study_design import (
    COHORTS,
    CUTOFF_DATES,
    MATURITY_DAYS,
    PROCESSED_SUBFOLDER,
    SNAPSHOT_DATE,
)
from vesper.components.b_survival.survival_table import (
    CSV_DATE_FORMAT,
    OUTPUT_FILE_NAME,
    filter_cohort,
)
from vesper.config import load_settings

SPLITS_SUBFOLDER = "splits"
SUMMARY_FILE_NAME = "split_summary.csv"

# Fewer events than this in a train set: a warning is printed and recorded
MIN_TRAIN_EVENTS = 100

# Column names that must never be in a train or test file. The KEV date is the
# outcome, and a plain "has an exploit" column would use an exploit that may
# appear after the prediction moment (look-ahead leakage).
FORBIDDEN_COLUMNS = {
    "kev_date_added",
    "kev_date",
    "date_added",
    "in_kev",
    "has_exploit",
    "has_any_exploit",
    "any_exploit",
    "exploit_count",
}


# ---------------------------------------------------------------------------
# Splitting
# ---------------------------------------------------------------------------


def stop_day(table):
    """The day each row stops being watched: publication day + duration."""
    return table["published_at"].dt.normalize() + pd.to_timedelta(table["duration_days"], unit="D")


def recensor_train(train, cutoff):
    """Make a train set know only what was known at the cut-off.

    Returns the new train table and two counts: events turned into censored
    rows, and exploit dates removed.
    """
    cutoff_day = as_day(cutoff)
    published_day = train["published_at"].dt.normalize()

    # An event is known only if it happened before the cut-off day
    known_event = (train["event"] == 1) & (stop_day(train) < cutoff_day)
    days_to_cutoff = (cutoff_day - published_day).dt.days

    result = train.copy()
    result["duration_days"] = train["duration_days"].where(known_event, days_to_cutoff)
    result["event"] = known_event.astype(int)
    result["kev_launch_group"] = train["kev_launch_group"].astype(bool) & known_event

    # An exploit published on or after the cut-off did not exist yet
    unknown_exploit = result["exploit_first_date"] >= cutoff_day
    result.loc[unknown_exploit, "exploit_first_date"] = pd.NaT

    events_recensored = int(((train["event"] == 1) & ~known_event).sum())
    return result, events_recensored, int(unknown_exploit.sum())


def split_at_cutoff(table, cutoff, window_days=MATURITY_DAYS):
    """Split the survival table at one cut-off date.

    Returns the train table, the test table and a dictionary of counts.
    """
    cutoff_day = as_day(cutoff)
    window_end = cutoff_day + pd.Timedelta(days=window_days)
    published = table["published_at"]

    train = table[published < cutoff_day]
    test = table[(published >= cutoff_day) & (published < window_end)]
    info = {
        "rows_not_used": len(table) - len(train) - len(test),
        "train_already_exploited_removed": int(train["already_exploited"].sum()),
        "test_already_exploited_removed": int(test["already_exploited"].sum()),
    }

    # Negative durations are removed from both sets
    train = train[~train["already_exploited"]]
    test = test[~test["already_exploited"]].copy()

    train, info["train_events_recensored"], info["train_exploit_dates_removed"] = recensor_train(
        train, cutoff
    )
    return train.reset_index(drop=True), test.reset_index(drop=True), info


def describe_split(table):
    """Rows, events, censored rows and event rate (in percent) of one set."""
    rows = len(table)
    events = int((table["event"] == 1).sum())
    return {
        "rows": rows,
        "events": events,
        "censored": rows - events,
        "event_rate": 100 * events / rows if rows else None,
    }


# ---------------------------------------------------------------------------
# Leakage checks. Each one returns the NUMBER OF ROWS (or columns) THAT BREAK
# THE RULE (0 = good).
# ---------------------------------------------------------------------------


def check_train_published_before_cutoff(train, cutoff):
    """Train rows published on or after the cut-off."""
    return int((train["published_at"] >= as_day(cutoff)).sum())


def check_train_follow_up_within_cutoff(train, cutoff):
    """Train rows whose duration or event reaches the cut-off or later.

    A censored row may stop exactly at the cut-off. An event must be before it.
    """
    cutoff_day = as_day(cutoff)
    stops = stop_day(train)
    too_long = stops > cutoff_day
    event_not_known = (train["event"] == 1) & (stops >= cutoff_day)
    return int((too_long | event_not_known).sum())


def check_train_exploit_dates_before_cutoff(train, cutoff):
    """Train rows with an exploit date on or after the cut-off."""
    return int((train["exploit_first_date"] >= as_day(cutoff)).sum())


def check_no_shared_cve_ids(train, test):
    """CVE IDs that are in both the train set and the test set."""
    return len(set(train["cve_id"]) & set(test["cve_id"]))


def check_no_negative_durations(table):
    """Rows with a negative duration."""
    return int((table["duration_days"] < 0).sum())


def check_no_forbidden_columns(table):
    """Columns that hold the KEV date or a plain "has exploit" flag (by name)."""
    return len(FORBIDDEN_COLUMNS & set(table.columns))


def check_test_follow_up(test, snapshot_date=SNAPSHOT_DATE, maturity_days=MATURITY_DAYS):
    """Test rows with less than maturity_days of follow-up before the snapshot.

    The proposal withholds CVEs from testing when their outcome is not settled.
    """
    latest_day = as_day(snapshot_date) - pd.Timedelta(days=maturity_days)
    return int((test["published_at"].dt.normalize() > latest_day).sum())


def check_rows_in_cohort(table, cohort):
    """Rows that do not belong to the cohort."""
    return len(table) - len(filter_cohort(table, cohort))


def run_checks(train, test, cutoff, cohort="full"):
    """Run every leakage check. Returns {check name: number that break the rule}."""
    return {
        "every train row is in the cohort": check_rows_in_cohort(train, cohort),
        "every test row is in the cohort": check_rows_in_cohort(test, cohort),
        "no train row published on or after the cut-off": check_train_published_before_cutoff(
            train, cutoff
        ),
        "no train event or duration reaches the cut-off or later": (
            check_train_follow_up_within_cutoff(train, cutoff)
        ),
        "no train exploit date on or after the cut-off": check_train_exploit_dates_before_cutoff(
            train, cutoff
        ),
        "no CVE ID in both train and test": check_no_shared_cve_ids(train, test),
        "no negative duration in train": check_no_negative_durations(train),
        "no negative duration in test": check_no_negative_durations(test),
        "no KEV date or has-exploit column in train": check_no_forbidden_columns(train),
        "no KEV date or has-exploit column in test": check_no_forbidden_columns(test),
        "every test CVE has the maturity follow-up": check_test_follow_up(test),
    }


# ---------------------------------------------------------------------------
# Reading, printing and main program
# ---------------------------------------------------------------------------


def load_survival_table(path):
    """Read survival_table.csv. Dates are read as UTC."""
    table = pd.read_csv(path, dtype={"cvss_is_primary": "boolean"})
    table["published_at"] = pd.to_datetime(table["published_at"], format="ISO8601", utc=True)
    table["exploit_first_date"] = pd.to_datetime(
        table["exploit_first_date"], format="%Y-%m-%d", utc=True
    )
    return table


def save_split(table, path):
    """Write one train or test table, with dates written like survival_table.csv."""
    out = table.copy()
    out["exploit_first_date"] = out["exploit_first_date"].dt.strftime("%Y-%m-%d")
    out.to_csv(path, index=False, date_format=CSV_DATE_FORMAT)


def small_train_warning(train, min_events=MIN_TRAIN_EVENTS):
    """A warning text if the train set has fewer than min_events events, else None."""
    events = int((train["event"] == 1).sum())
    if events >= min_events:
        return None
    return f"only {events} train events (fewer than {min_events}); a model fit may be unreliable"


def summary_row(cohort, cutoff, train, test, warning):
    """One row of split_summary.csv."""
    row = {"cohort": cohort, "cutoff": cutoff.isoformat()}
    for name, table in (("train", train), ("test", test)):
        for key, value in describe_split(table).items():
            row[f"{name}_{key}"] = value
    row["small_train_warning"] = warning is not None
    row["warning"] = warning or ""
    return row


def print_cutoff(cohort, cutoff, train, test, info, checks, window_days=MATURITY_DAYS):
    """Print the small table of one cut-off and the result of its checks."""
    window_last_day = (as_day(cutoff) + pd.Timedelta(days=window_days - 1)).date()
    print()
    print(
        f"[{cohort}] Cut-off {cutoff.isoformat()}"
        f"  (test CVEs published {cutoff} to {window_last_day})"
    )
    print(f"  {'':6}{'rows':>9}{'events':>9}{'censored':>10}{'event rate':>12}")
    for name, table in (("train", train), ("test", test)):
        d = describe_split(table)
        rate = f"{d['event_rate']:.2f}%" if d["event_rate"] is not None else "n/a"
        print(f"  {name:6}{d['rows']:>9}{d['events']:>9}{d['censored']:>10}{rate:>12}")
    print(
        "  already_exploited rows removed: train", info["train_already_exploited_removed"], end=""
    )
    print(", test", info["test_already_exploited_removed"])
    print("  train events turned into censored at the cut-off:", info["train_events_recensored"])
    print("  train exploit dates removed (on or after the cut-off):", end=" ")
    print(info["train_exploit_dates_removed"])
    print("  rows not used (published after the test window):", info["rows_not_used"])
    for name, problems in checks.items():
        status = "ok" if problems == 0 else "FAILED"
        print(f"  check, {name}: {problems} ({status})")


def print_overview(rows):
    """Print rows and events of every cohort and cut-off, with the warnings."""
    print()
    print("Overview (train / test)")
    header = f"  {'cohort':<10}{'cut-off':<12}{'train rows':>11}{'events':>8}"
    print(header + f"{'test rows':>11}{'events':>8}")
    for row in rows:
        mark = "  WARNING: small train set" if row["small_train_warning"] else ""
        print(
            f"  {row['cohort']:<10}{row['cutoff']:<12}{row['train_rows']:>11}"
            f"{row['train_events']:>8}{row['test_rows']:>11}{row['test_events']:>8}{mark}"
        )


def main(settings=None, cutoffs=CUTOFF_DATES, cohorts=COHORTS, min_train_events=MIN_TRAIN_EVENTS):
    """Split every cohort at every cut-off, run the checks, print, and save if all pass."""
    # Folders come from vesper.config
    settings = settings or load_settings()
    processed_dir = settings.data_processed / PROCESSED_SUBFOLDER
    splits_dir = processed_dir / SPLITS_SUBFOLDER

    table = load_survival_table(processed_dir / OUTPUT_FILE_NAME)
    print("Read:", processed_dir / OUTPUT_FILE_NAME, f"({len(table)} rows)")
    print("Test window:", MATURITY_DAYS, "days; snapshot date:", SNAPSHOT_DATE.isoformat())

    # Work out and check every cohort and cut-off first. Nothing is saved before all pass.
    results, summary_rows, failed = [], [], []
    for cohort in cohorts:
        cohort_table = filter_cohort(table, cohort)
        print()
        print(f"Cohort {cohort}: {len(cohort_table)} rows")
        for cutoff in cutoffs:
            train, test, info = split_at_cutoff(cohort_table, cutoff)
            checks = run_checks(train, test, cutoff, cohort)
            print_cutoff(cohort, cutoff, train, test, info, checks)
            failed += [
                f"{cohort} {cutoff}: {name}" for name, problems in checks.items() if problems
            ]

            # A small train set is kept, but the warning is printed and recorded
            warning = small_train_warning(train, min_train_events)
            if warning:
                print(f"  WARNING [{cohort} {cutoff}]: {warning}")
            summary_rows.append(summary_row(cohort, cutoff, train, test, warning))
            results.append((cohort, cutoff, train, test))

    print_overview(summary_rows)
    if failed:
        raise ValueError(f"Splits not saved. Failed checks: {failed}")

    for cohort, cutoff, train, test in results:
        cohort_dir = splits_dir / cohort
        cohort_dir.mkdir(parents=True, exist_ok=True)
        save_split(train, cohort_dir / f"train_{cutoff.isoformat()}.csv")
        save_split(test, cohort_dir / f"test_{cutoff.isoformat()}.csv")
    pd.DataFrame(summary_rows).to_csv(splits_dir / SUMMARY_FILE_NAME, index=False)
    print()
    print("Saved", 2 * len(results), "split files and", SUMMARY_FILE_NAME, "to:", splits_dir)
    return splits_dir


if __name__ == "__main__":
    main()
