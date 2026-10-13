"""
Clean the NVD records into one row per CVE.

NVD gives the start of the survival clock, `published_at` (the day a CVE was
disclosed), and the covariates: the CVSS score, the CVSS vector and the
weakness types (CWE).

Input:   data/raw/nvd/nvd_YYYY-MM.json.gz, one file per month   (never changed)
Output:  data/processed/b_survival/nvd_clean.csv

Columns of the output. Names follow vesper.contracts.vulnerability.Vulnerability
where that record has the field:
    cve_id                    the CVE identifier
    published_at              when NVD published the CVE (UTC)
    last_modified_at          when NVD last changed the record (UTC)
    nvd_status                NVD's status of the record, for example "Analyzed"
    cvss_base_score           CVSS base score, 0 to 10 (empty if missing)
    cvss_version              "3.1" or "3.0" (empty if missing)
    cvss_vector               the full CVSS vector text (empty if missing)
    cvss_missing              True if the CVE has no CVSS 3.1 or 3.0 score
    cvss_is_primary           True if the score used is NVD's own ("Primary"),
                              False if it is from another source (empty if missing)
    cvss_attack_vector        NETWORK, ADJACENT_NETWORK, LOCAL or PHYSICAL
    cvss_attack_complexity    LOW or HIGH
    cvss_privileges_required  NONE, LOW or HIGH
    cvss_user_interaction     NONE or REQUIRED
    cwe_ids                   CWE IDs separated by ";" (empty if none)
    after_snapshot            True if published after the snapshot date
    modified_after_snapshot   True if last modified after the snapshot date
    snapshot_date             the snapshot date, the same in every row

Two things to remember when this table is used:
  - The values are the state of the record on the day it was downloaded, not
    on the day the CVE was published. NVD often adds the CVSS score later.
  - NVD copies the KEV date into some records (`cisaExploitAdd`). That is the
    outcome, so this module never reads it.

When reading the CSV again, read `cvss_version` as text, or "3.0" becomes 3.0.

Run from anywhere:
    uv run python -m vesper.components.b_survival.clean_nvd
"""

import gzip
import json

import pandas as pd

from vesper.components.b_survival.study_design import PROCESSED_SUBFOLDER, SNAPSHOT_DATE
from vesper.config import load_settings
from vesper.contracts.vulnerability import CVE_ID_PATTERN

OUTPUT_FILE_NAME = "nvd_clean.csv"

# Where NVD keeps the CVSS scores of each version, in the order we prefer them
PREFERRED_CVSS_KEYS = ["cvssMetricV31", "cvssMetricV30"]

# The four parts of the CVSS vector that we keep, and what their letters mean.
# Example vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N
VECTOR_COLUMNS = {
    "cvss_attack_vector": (
        "AV",
        {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"},
    ),
    "cvss_attack_complexity": ("AC", {"L": "LOW", "H": "HIGH"}),
    "cvss_privileges_required": ("PR", {"N": "NONE", "L": "LOW", "H": "HIGH"}),
    "cvss_user_interaction": ("UI", {"N": "NONE", "R": "REQUIRED"}),
}

# A CVE that was withdrawn. It is not a real vulnerability, so it is dropped.
REJECTED_STATUS = "rejected"

# Columns of the saved table, in order
OUTPUT_COLUMNS = [
    "cve_id",
    "published_at",
    "last_modified_at",
    "nvd_status",
    "cvss_base_score",
    "cvss_version",
    "cvss_vector",
    "cvss_missing",
    "cvss_is_primary",
    *VECTOR_COLUMNS,
    "cwe_ids",
    "after_snapshot",
    "modified_after_snapshot",
    "snapshot_date",
]

# Columns that are worked out during cleaning, not taken from the record
ADDED_COLUMNS = ["after_snapshot", "modified_after_snapshot", "snapshot_date"]

# Column used only to count things for the report; it is not saved
HELPER_COLUMNS = ["has_other_cvss"]

# How dates are written in the CSV: ISO 8601 with "Z", which means UTC
CSV_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def pick_cvss(metrics):
    """Choose one CVSS entry for a CVE, or None if it has no 3.1 or 3.0 score.

    Version 3.1 is preferred, then 3.0. Inside a version, the "Primary" entry
    is preferred. If there is no Primary entry, the first one listed is used.
    """
    for key in PREFERRED_CVSS_KEYS:
        entries = metrics.get(key) or []
        for entry in entries:
            if entry.get("type") == "Primary":
                return entry
        if entries:
            return entries[0]
    return None


def parse_vector(vector):
    """Read the four parts we keep from a CVSS vector, as words.

    A part that is absent, or has a letter we do not know, becomes None.
    """
    # "CVSS:3.1/AV:N/AC:L" -> {"CVSS": "3.1", "AV": "N", "AC": "L"}
    parts = dict(part.split(":", 1) for part in (vector or "").split("/") if ":" in part)
    return {
        column: meanings.get(parts.get(short_name))
        for column, (short_name, meanings) in VECTOR_COLUMNS.items()
    }


def collect_cwe_ids(weaknesses):
    """Return the CWE IDs of a CVE as text separated by ";", or None if it has none.

    NVD's placeholders "NVD-CWE-noinfo" and "NVD-CWE-Other" are not weakness
    types, so they are left out. Each CWE appears once, in number order.
    """
    numbers = set()
    for weakness in weaknesses or []:
        for description in weakness.get("description", []):
            value = str(description.get("value", "")).strip().upper()
            if value.startswith("CWE-") and value[4:].isdigit():
                numbers.add(int(value[4:]))
    return ";".join(f"CWE-{number}" for number in sorted(numbers)) or None


def extract_row(cve):
    """Take the fields we need from one NVD record (the part under "cve")."""
    metrics = cve.get("metrics") or {}
    cvss = pick_cvss(metrics)
    cvss_data = cvss.get("cvssData", {}) if cvss else {}
    vector = cvss_data.get("vectorString")

    # Is there a CVSS score of another version (2.0 or 4.0)? Only for the report.
    other_keys = [
        key
        for key, entries in metrics.items()
        if key.startswith("cvssMetric") and key not in PREFERRED_CVSS_KEYS and entries
    ]

    return {
        "cve_id": cve.get("id"),
        "published_at": cve.get("published"),
        "last_modified_at": cve.get("lastModified"),
        "nvd_status": cve.get("vulnStatus"),
        "cvss_base_score": cvss_data.get("baseScore"),
        "cvss_version": cvss_data.get("version"),
        "cvss_vector": vector,
        "cvss_missing": cvss is None,
        # Who gave the score used: NVD itself ("Primary") or another source
        "cvss_is_primary": cvss.get("type") == "Primary" if cvss else None,
        **parse_vector(vector),
        "cwe_ids": collect_cwe_ids(cve.get("weaknesses")),
        "has_other_cvss": bool(other_keys),
    }


def clean_nvd(records, snapshot_date=SNAPSHOT_DATE):
    """Turn NVD records into a clean table with one row per CVE.

    `records` are the items of the "vulnerabilities" lists in the raw files.
    Returns the clean table and a report (a dictionary of counts) that says
    how many rows were removed at each step.
    """
    # --- 1. One flat row per record ------------------------------------------
    rows = [extract_row(record["cve"]) for record in records]
    # Naming the columns keeps them in place even when there are no records
    extracted = [column for column in OUTPUT_COLUMNS if column not in ADDED_COLUMNS]
    table = pd.DataFrame(rows, columns=extracted + HELPER_COLUMNS)
    table["cvss_missing"] = table["cvss_missing"].astype(bool)
    table["has_other_cvss"] = table["has_other_cvss"].astype(bool)
    # "boolean" is a true/false column that can also be empty (no CVSS score)
    table["cvss_is_primary"] = table["cvss_is_primary"].astype("boolean")
    report = {"rows_before": len(table)}

    # --- 2. Check every CVE ID against the shared pattern --------------------
    # (.astype(bool) keeps this a true/false column even when the table is empty)
    table["cve_id"] = table["cve_id"].fillna("").astype(str).str.strip().str.upper()
    valid_id = table["cve_id"].apply(lambda cve_id: bool(CVE_ID_PATTERN.match(cve_id)))
    valid_id = valid_id.astype(bool)
    report["removed_invalid_cve_id"] = int((~valid_id).sum())
    table = table[valid_id].copy()

    # --- 3. Read the dates as UTC ---------------------------------------------
    # NVD writes times without a time zone, for example 2015-01-09T18:59:02.587.
    # They are UTC. A value that is not a date becomes NaT ("not a time"), and
    # the row is removed: without a publication date the clock cannot start.
    for column in ("published_at", "last_modified_at"):
        table[column] = pd.to_datetime(table[column], format="ISO8601", errors="coerce", utc=True)
    bad_date = table["published_at"].isna() | table["last_modified_at"].isna()
    report["removed_unreadable_date"] = int(bad_date.sum())
    table = table[~bad_date].copy()

    # --- 4. Drop rejected CVEs -------------------------------------------------
    table["nvd_status"] = table["nvd_status"].fillna("").astype(str).str.strip()
    rejected = table["nvd_status"].str.lower() == REJECTED_STATUS
    report["removed_rejected"] = int(rejected.sum())
    table = table[~rejected]

    # --- 5. One row per CVE ----------------------------------------------------
    # If a CVE is in two files, keep the record that NVD changed most recently.
    table = table.sort_values(["cve_id", "last_modified_at"])
    is_duplicate = table.duplicated(subset="cve_id", keep="last")
    report["removed_duplicate_cve"] = int(is_duplicate.sum())
    table = table[~is_duplicate]
    table = table.sort_values(["published_at", "cve_id"]).reset_index(drop=True)

    # --- 6. Flag dates after the snapshot (flag only, never delete) ------------
    snapshot = pd.Timestamp(snapshot_date, tz="UTC")
    table["after_snapshot"] = table["published_at"].dt.normalize() > snapshot
    table["modified_after_snapshot"] = table["last_modified_at"].dt.normalize() > snapshot
    table["snapshot_date"] = snapshot_date.isoformat()

    # --- 7. Count what is in the clean table ------------------------------------
    report["rows_after"] = len(table)
    report["flagged_after_snapshot"] = int(table["after_snapshot"].sum())
    report["flagged_modified_after_snapshot"] = int(table["modified_after_snapshot"].sum())
    report["status_counts"] = table["nvd_status"].value_counts().to_dict()
    report["cvss_version_3_1"] = int((table["cvss_version"] == "3.1").sum())
    report["cvss_version_3_0"] = int((table["cvss_version"] == "3.0").sum())
    # An empty cvss_is_primary (no CVSS score) is counted in neither line
    report["cvss_primary"] = int(table["cvss_is_primary"].eq(True).sum())
    report["cvss_not_primary"] = int(table["cvss_is_primary"].eq(False).sum())
    report["cvss_missing"] = int(table["cvss_missing"].sum())
    report["cvss_missing_with_other_version"] = int(
        (table["cvss_missing"] & table["has_other_cvss"]).sum()
    )

    # Per publication year: how many CVEs, and how many of them have no CVSS score
    by_year = table.groupby(table["published_at"].dt.year)["cvss_missing"].agg(["size", "sum"])
    report["cvss_missing_by_year"] = {
        int(year): (int(row["size"]), int(row["sum"])) for year, row in by_year.iterrows()
    }

    table = table[OUTPUT_COLUMNS]
    # An empty cell is a missing value: no CVSS score, or no CWE
    report["missing_values"] = {column: int(table[column].isna().sum()) for column in table}
    return table, report


def print_report(report):
    """Print what the cleaning kept and removed, and why."""
    print("NVD cleaning report")
    print("  Rows before:", report["rows_before"])
    print("  Removed, CVE ID does not match the CVE pattern:", report["removed_invalid_cve_id"])
    print("  Removed, a date is missing or not a date:", report["removed_unreadable_date"])
    print("  Removed, status is Rejected:", report["removed_rejected"])
    print("  Removed, CVE already present (latest record kept):", report["removed_duplicate_cve"])
    print("  Rows after (one per CVE):", report["rows_after"])
    print("  Flagged, published after the snapshot date:", report["flagged_after_snapshot"])
    print("  Flagged, modified after the snapshot date:", report["flagged_modified_after_snapshot"])
    print("  CVSS score used")
    print("    version 3.1:", report["cvss_version_3_1"])
    print("    version 3.0:", report["cvss_version_3_0"])
    print("    cvss_is_primary True (NVD's own score):", report["cvss_primary"])
    print("    cvss_is_primary False (another source):", report["cvss_not_primary"])
    print("    cvss_is_primary empty (no 3.1 or 3.0 score):", report["cvss_missing"])
    print("      of these, with a 2.0 or 4.0 score:", report["cvss_missing_with_other_version"])
    print("  CVSS missing by publication year (CVEs, missing, percent)")
    for year, (cves, missing) in report["cvss_missing_by_year"].items():
        print(f"    {year}: {cves}, {missing}, {100 * missing / cves:.1f}%")
    print("  Status of the rows kept")
    for status, count in report["status_counts"].items():
        print(f"    {status}: {count}")
    print("  Missing values per column")
    for column, count in report["missing_values"].items():
        print(f"    {column}: {count}")


def read_raw_records(nvd_dir):
    """Give the CVE records of every monthly file, one file in memory at a time."""
    for path in sorted(nvd_dir.glob("nvd_*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as file:
            yield from json.load(file)["vulnerabilities"]


def main(settings=None):
    """Read the raw NVD files, clean them, print the report and save the CSV."""
    # Folders come from vesper.config
    settings = settings or load_settings()
    nvd_dir = settings.raw_source("nvd")
    output_dir = settings.data_processed / PROCESSED_SUBFOLDER

    print("Reading:", nvd_dir)
    table, report = clean_nvd(read_raw_records(nvd_dir))
    print_report(report)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / OUTPUT_FILE_NAME
    table.to_csv(output_path, index=False, date_format=CSV_DATE_FORMAT)
    print("Saved to:", output_path)
    return output_path


if __name__ == "__main__":
    main()
