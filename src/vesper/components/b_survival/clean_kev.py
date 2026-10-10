"""
Clean the CISA KEV catalogue into one row per CVE.

KEV gives the "event" of the survival analysis: `dateAdded` is the day CISA
confirmed that a CVE was exploited in the wild. Only the CVE ID and that date
are kept. The date is an outcome, so it must never be used as a feature.

Input:   data/raw/kev/kev_2026-10-01.json           (never changed)
Output:  data/processed/b_survival/kev_clean.csv

Columns of the output:
    cve_id                   the CVE identifier (KEV field `cveID`)
    date_added               day the CVE was added to KEV, as midnight UTC
    added_on_kev_start_date  True if date_added is the day the catalogue started
    after_snapshot           True if date_added is after the snapshot date

Run from anywhere:
    uv run python -m vesper.components.b_survival.clean_kev
"""

import json
from datetime import date

import pandas as pd

from vesper.components.b_survival.snapshot import PROCESSED_SUBFOLDER, SNAPSHOT_DATE
from vesper.config import load_settings
from vesper.contracts.vulnerability import CVE_ID_PATTERN

# The raw file to clean (the date in the name is the day it was downloaded)
KEV_FILE_NAME = "kev_2026-10-01.json"
OUTPUT_FILE_NAME = "kev_clean.csv"

# The day CISA published the catalogue. It started with a backlog of CVEs that
# had been exploited earlier, sometimes years earlier. For those CVEs the date
# means "the catalogue started", not "exploitation was confirmed on this day".
KEV_START_DATE = date(2021, 11, 3)

# How dates are written in the CSV: ISO 8601 with "Z", which means UTC
CSV_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def clean_kev(records, snapshot_date=SNAPSHOT_DATE):
    """Turn the KEV records into a clean table with one row per CVE.

    `records` is the list under "vulnerabilities" in the KEV file.
    Returns the clean table and a report (a dictionary of counts) that says
    how many rows were removed at each step.
    """
    # --- 1. Keep only the two fields we need -------------------------------
    table = pd.DataFrame(
        {
            "cve_id": [record.get("cveID") for record in records],
            "date_added": [record.get("dateAdded") for record in records],
        }
    )
    report = {"rows_before": len(table)}

    # --- 2. Check every CVE ID against the shared pattern ------------------
    # Remove spaces around the ID and use capital letters, then check it.
    # A missing ID becomes an empty text, which fails the check.
    table["cve_id"] = table["cve_id"].fillna("").astype(str).str.strip().str.upper()
    # (.astype(bool) keeps this a true/false column even when the table is empty)
    valid_id = table["cve_id"].apply(lambda cve_id: bool(CVE_ID_PATTERN.match(cve_id)))
    valid_id = valid_id.astype(bool)
    report["removed_invalid_cve_id"] = int((~valid_id).sum())
    table = table[valid_id].copy()

    # --- 3. Read the date as UTC --------------------------------------------
    # KEV writes dates as YYYY-MM-DD. Anything else becomes NaT ("not a time")
    # and the row is removed, because an event without a date cannot be used.
    table["date_added"] = pd.to_datetime(
        table["date_added"], format="%Y-%m-%d", errors="coerce", utc=True
    )
    bad_date = table["date_added"].isna()
    report["removed_unreadable_date"] = int(bad_date.sum())
    table = table[~bad_date]

    # --- 4. One row per CVE --------------------------------------------------
    # If a CVE is listed more than once, keep its earliest date: the first day
    # exploitation was confirmed. Sorting first puts the earliest date on top.
    report["cves_listed_more_than_once"] = int(table["cve_id"].duplicated().sum())
    dates_per_cve = table.groupby("cve_id")["date_added"].nunique()
    report["cves_with_conflicting_dates"] = int((dates_per_cve > 1).sum())
    table = table.sort_values(["date_added", "cve_id"])
    table = table.drop_duplicates(subset="cve_id", keep="first").reset_index(drop=True)
    report["removed_duplicate_cve"] = report["cves_listed_more_than_once"]

    # --- 5. Flag the day the catalogue started -------------------------------
    start = pd.Timestamp(KEV_START_DATE, tz="UTC")
    table["added_on_kev_start_date"] = table["date_added"] == start

    # --- 6. Flag dates after the snapshot (flag only, never delete) ----------
    snapshot = pd.Timestamp(snapshot_date, tz="UTC")
    table["after_snapshot"] = table["date_added"].dt.normalize() > snapshot

    report["rows_after"] = len(table)
    report["flagged_added_on_kev_start_date"] = int(table["added_on_kev_start_date"].sum())
    report["flagged_after_snapshot"] = int(table["after_snapshot"].sum())
    return table, report


def print_report(report):
    """Print what the cleaning kept and removed, and why."""
    print("KEV cleaning report")
    print("  Rows before:", report["rows_before"])
    print("  Removed, CVE ID does not match the CVE pattern:", report["removed_invalid_cve_id"])
    print("  Removed, dateAdded missing or not a date:", report["removed_unreadable_date"])
    print("  Removed, CVE already listed (earliest date kept):", report["removed_duplicate_cve"])
    print("    of these, CVEs with two different dates:", report["cves_with_conflicting_dates"])
    print("  Rows after (one per CVE):", report["rows_after"])
    print("  Flagged, added on the KEV start date:", report["flagged_added_on_kev_start_date"])
    print("  Flagged, added after the snapshot date:", report["flagged_after_snapshot"])


def main(settings=None):
    """Read the raw KEV file, clean it, print the report and save the CSV."""
    # Folders come from vesper.config
    settings = settings or load_settings()
    raw_path = settings.raw_source("kev") / KEV_FILE_NAME
    output_dir = settings.data_processed / PROCESSED_SUBFOLDER

    print("Reading:", raw_path)
    catalogue = json.loads(raw_path.read_text(encoding="utf-8"))
    table, report = clean_kev(catalogue["vulnerabilities"])
    print_report(report)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / OUTPUT_FILE_NAME
    table.to_csv(output_path, index=False, date_format=CSV_DATE_FORMAT)
    print("Saved to:", output_path)
    return output_path


if __name__ == "__main__":
    main()
