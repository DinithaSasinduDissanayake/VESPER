"""
Link the three clean sources into one table with one row per study CVE.

NVD is the base table. KEV and ExploitDB are attached to it with a left join,
so a CVE that is not in KEV (or has no exploit) keeps its row with empty
fields. Nothing is decided here: the survival rules are in survival_table.py.

Input:   data/processed/b_survival/nvd_clean.csv, kev_clean.csv, exploitdb_clean.csv
Output:  none. The linked table is returned in memory for survival_table.py,
         and a report of the joins is printed.

Study CVEs are the NVD CVEs published from STUDY_START up to SNAPSHOT_DATE.
The upper end uses the `after_snapshot` flags written by the clean_ modules.

Run from anywhere (run the three clean_ modules first):
    uv run python -m vesper.components.b_survival.link_sources
"""

import pandas as pd

from vesper.components.b_survival import clean_exploitdb, clean_kev, clean_nvd
from vesper.components.b_survival.study_design import PROCESSED_SUBFOLDER, STUDY_START
from vesper.config import load_settings

# The reasons a CVE from KEV or ExploitDB can be missing from the study table
REASON_BEFORE_START = "published before STUDY_START"
REASON_AFTER_SNAPSHOT = "published after SNAPSHOT_DATE"
REASON_OLD_ID = "not in the NVD table, CVE ID older than the NVD download"
REASON_OTHER = "not in the NVD table, other reason (for example Rejected)"


def as_day(moment):
    """Turn a date into a UTC timestamp at midnight, so days can be compared."""
    return pd.Timestamp(moment, tz="UTC")


def first_exploit_dates(exploit_tables):
    """Give, for every CVE, its earliest public exploit date and its exploit count.

    `exploit_tables` is a LIST of tables, one per source of exploit code. Today
    the list has one table (ExploitDB). A second source can be added later by
    adding a table to the list; nothing else has to change.

    Each table needs the columns cve_id, exploit_id, date_published (UTC) and
    after_snapshot, which is what clean_exploitdb writes. Rows with
    after_snapshot = True are not used.

    Returns a table with one row per CVE:
        cve_id
        first_exploit_date   earliest publication day over all sources
        exploit_count        number of distinct exploits (distinct source and id)
    """
    parts = []
    for number, table in enumerate(exploit_tables):
        used = table.loc[~table["after_snapshot"], ["cve_id", "exploit_id", "date_published"]]
        used = used.assign(source=number)
        parts.append(used)

    empty = pd.DataFrame(
        {
            "cve_id": pd.Series(dtype="object"),
            "first_exploit_date": pd.Series(dtype="datetime64[ns, UTC]"),
            "exploit_count": pd.Series(dtype="int64"),
        }
    )
    if not parts:
        return empty
    pairs = pd.concat(parts, ignore_index=True)
    if pairs.empty:
        return empty

    # An exploit is identified by its source and its id: the same id in two
    # sources is two different exploits.
    pairs["exploit_key"] = pairs["source"].astype(str) + ":" + pairs["exploit_id"].astype(str)
    pairs["day"] = pairs["date_published"].dt.normalize()
    grouped = pairs.groupby("cve_id").agg(
        first_exploit_date=("day", "min"), exploit_count=("exploit_key", "nunique")
    )
    return grouped.reset_index()


def explain_unmatched(cve_ids, nvd, study_ids, study_start=STUDY_START):
    """Count why CVE IDs are not in the study table.

    `nvd` is the whole NVD table (before the study window was applied).
    Returns a dictionary: reason -> number of CVE IDs.
    """
    missing = pd.Series(sorted(set(cve_ids) - set(study_ids)), dtype="object")
    published = nvd.set_index("cve_id")["published_at"].dt.normalize()
    after_flag = nvd.set_index("cve_id")["after_snapshot"]

    in_nvd = missing.isin(published.index)
    day = missing.map(published)
    first_year = int(nvd["published_at"].dt.year.min()) if len(nvd) else 0
    id_year = missing.str.split("-").str[1].astype(int) if len(missing) else pd.Series(dtype=int)

    before_start = in_nvd & (day < as_day(study_start))
    after_snapshot = in_nvd & missing.map(after_flag).eq(True)
    old_id = ~in_nvd & (id_year < first_year)
    other = ~in_nvd & ~old_id
    return {
        REASON_BEFORE_START: int(before_start.sum()),
        REASON_AFTER_SNAPSHOT: int(after_snapshot.sum()),
        REASON_OLD_ID: int(old_id.sum()),
        REASON_OTHER: int(other.sum()),
    }


def link_sources(nvd, kev, exploit_tables, study_start=STUDY_START):
    """Link NVD, KEV and the exploit tables into one table, one row per study CVE.

    Returns the linked table and a report (a dictionary of counts).

    Columns added to the NVD columns:
        in_kev, kev_date_added, added_on_kev_start_date     from KEV (up to the snapshot)
        first_exploit_date, exploit_count                    from the exploit tables

    kev_date_added is an OUTCOME. It is kept only so that survival_table.py can
    work out the duration and the event; it must never become an input.
    """
    report = {"nvd_rows": len(nvd), "kev_rows": len(kev)}

    # --- 1. The study CVEs: published from STUDY_START up to the snapshot -----
    in_window = (nvd["published_at"].dt.normalize() >= as_day(study_start)) & ~nvd["after_snapshot"]
    study = nvd[in_window].reset_index(drop=True)
    report["study_cves"] = len(study)

    # --- 2. KEV: listings up to the snapshot date -----------------------------
    kev_used = kev.loc[~kev["after_snapshot"], ["cve_id", "date_added", "added_on_kev_start_date"]]
    kev_used = kev_used.rename(columns={"date_added": "kev_date_added"})
    report["kev_rows_up_to_snapshot"] = len(kev_used)
    # one_to_one makes pandas stop if a CVE appears twice on either side
    linked = study.merge(kev_used, on="cve_id", how="left", validate="one_to_one", indicator=True)
    linked["in_kev"] = linked["_merge"] == "both"
    linked = linked.drop(columns="_merge")
    # A CVE with no KEV match has an empty flag, which is read as False here
    linked["added_on_kev_start_date"] = linked["added_on_kev_start_date"].eq(True)
    report["kev_matched"] = int(linked["in_kev"].sum())
    report["kev_unmatched"] = explain_unmatched(
        kev_used["cve_id"], nvd, study["cve_id"], study_start
    )

    # --- 3. Exploit code: earliest date and number of exploits per CVE --------
    exploits = first_exploit_dates(exploit_tables)
    report["exploit_rows"] = [len(table) for table in exploit_tables]
    report["exploit_cves"] = len(exploits)
    linked = linked.merge(exploits, on="cve_id", how="left", validate="one_to_one")
    linked["exploit_count"] = linked["exploit_count"].fillna(0).astype(int)
    report["exploit_cves_matched"] = int((linked["exploit_count"] > 0).sum())
    report["exploit_unmatched"] = explain_unmatched(
        exploits["cve_id"], nvd, study["cve_id"], study_start
    )

    return linked, report


def print_report(report):
    """Print the sizes of the sources and what matched in each join."""
    print("Linking report")
    print("  Rows per source")
    print("    NVD (clean table):", report["nvd_rows"])
    print("    NVD, study CVEs (published from STUDY_START to the snapshot):", report["study_cves"])
    print("    KEV (clean table):", report["kev_rows"])
    print("    KEV, listed up to the snapshot:", report["kev_rows_up_to_snapshot"])
    for number, rows in enumerate(report["exploit_rows"], start=1):
        print(f"    exploit source {number} (clean table, one row per exploit and CVE):", rows)
    print(
        "    exploit sources, distinct CVEs with an exploit up to the snapshot:",
        report["exploit_cves"],
    )
    print("  Join: study CVEs <- KEV")
    print("    KEV CVEs matched (found in the study table):", report["kev_matched"])
    unmatched = sum(report["kev_unmatched"].values())
    print("    KEV CVEs unmatched:", unmatched)
    for reason, count in report["kev_unmatched"].items():
        print(f"      {reason}: {count}")
    print(
        "    study CVEs without a KEV listing (censored):",
        report["study_cves"] - report["kev_matched"],
    )
    print("  Join: study CVEs <- exploit sources")
    print(
        "    CVEs with an exploit, matched (found in the study table):",
        report["exploit_cves_matched"],
    )
    unmatched = sum(report["exploit_unmatched"].values())
    print("    CVEs with an exploit, unmatched:", unmatched)
    for reason, count in report["exploit_unmatched"].items():
        print(f"      {reason}: {count}")
    print(
        "    study CVEs without an exploit:",
        report["study_cves"] - report["exploit_cves_matched"],
    )


def load_clean_tables(processed_dir):
    """Read the three clean CSV files. Dates are read as UTC; no column is dropped."""
    # cvss_version is text ("3.0" must stay "3.0"); cvss_is_primary can be empty
    nvd = pd.read_csv(
        processed_dir / clean_nvd.OUTPUT_FILE_NAME,
        dtype={"cvss_version": "str", "cvss_is_primary": "boolean"},
    )
    kev = pd.read_csv(processed_dir / clean_kev.OUTPUT_FILE_NAME)
    exploits = pd.read_csv(
        processed_dir / clean_exploitdb.OUTPUT_FILE_NAME, dtype={"exploit_id": "str"}
    )

    for table, columns in (
        (nvd, ["published_at", "last_modified_at"]),
        (kev, ["date_added"]),
        (exploits, ["date_published"]),
    ):
        for column in columns:
            table[column] = pd.to_datetime(table[column], format="ISO8601", utc=True)
    return nvd, kev, exploits


def main(settings=None):
    """Read the clean tables, link them, print the report and return the linked table."""
    # Folders come from vesper.config
    settings = settings or load_settings()
    processed_dir = settings.data_processed / PROCESSED_SUBFOLDER

    print("Reading:", processed_dir)
    nvd, kev, exploits = load_clean_tables(processed_dir)
    linked, report = link_sources(nvd, kev, [exploits])
    print_report(report)
    return linked, report


if __name__ == "__main__":
    main()
