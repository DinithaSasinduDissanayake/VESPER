"""
First exploration (EDA) of the cleaned data of Component B.

It reads the three clean tables, counts things and draws three figures. It is
exploration only: the tables are joined in memory to count, the survival table
is not built here, and no joined table is saved.

Only CVEs published from STUDY_START up to SNAPSHOT_DATE are used, and only
KEV and exploit dates up to SNAPSHOT_DATE.

Days are counted between calendar days (UTC): a CVE that is listed in KEV on
the day it is published has 0 days.

Input:   data/processed/b_survival/nvd_clean.csv, kev_clean.csv, exploitdb_clean.csv
Output:  outputs/b_survival/eda/01_cves_per_year.png
         outputs/b_survival/eda/02_days_to_kev.png
         outputs/b_survival/eda/03_days_to_kev_published_since_kev_start.png
         outputs/b_survival/eda/eda_summary.csv   (every number that is printed)

Run from anywhere (run the three clean_ modules first):
    uv run python -m vesper.components.b_survival.eda
"""

import math

import matplotlib.pyplot as plt
import pandas as pd

from vesper.components.b_survival import clean_exploitdb, clean_kev, clean_nvd
from vesper.components.b_survival.clean_kev import KEV_START_DATE
from vesper.components.b_survival.study_design import (
    PROCESSED_SUBFOLDER,
    SNAPSHOT_DATE,
    STUDY_START,
)
from vesper.config import load_settings

# Draw straight to files; no window is opened
plt.switch_backend("Agg")

# Subfolder of outputs/b_survival/ for everything this module writes
EDA_SUBFOLDER = "eda"
SUMMARY_FILE_NAME = "eda_summary.csv"

# Width of one histogram bar, in days
HISTOGRAM_BIN_DAYS = 30

# Figure colours (one colour per kind of thing, on a light background)
COLOUR_ALL_CVES = "#2a78d6"
COLOUR_KEV = "#eb6834"
COLOUR_BACKGROUND = "#fcfcfb"
COLOUR_TEXT = "#52514e"
COLOUR_GRID = "#e4e3df"


# ---------------------------------------------------------------------------
# Calculations (tested with small made-up tables)
# ---------------------------------------------------------------------------


def as_day(moment):
    """Turn a date into a UTC timestamp at midnight, so days can be compared."""
    return pd.Timestamp(moment, tz="UTC")


def build_study_table(nvd, kev, exploits, study_start=STUDY_START, snapshot_date=SNAPSHOT_DATE):
    """Make one row per CVE in the study window, for counting only (never saved).

    `nvd` has the columns cve_id and published_at, `kev` has cve_id and
    date_added, `exploits` has cve_id and date_published; the dates are UTC.

    Columns of the result:
        cve_id, published_day, year
        in_kev, kev_day, days_to_kev       (kev_day and days are empty if not in KEV)
        has_exploit, first_exploit_day     (earliest ExploitDB entry of the CVE)
        exploit_by_publication             True if that entry is on or before published_day
    """
    start, snapshot = as_day(study_start), as_day(snapshot_date)

    # CVEs published inside the study window
    table = pd.DataFrame(
        {"cve_id": nvd["cve_id"], "published_day": nvd["published_at"].dt.normalize()}
    )
    table = table[(table["published_day"] >= start) & (table["published_day"] <= snapshot)]
    table["year"] = table["published_day"].dt.year

    # KEV listings up to the snapshot date
    kev_days = pd.DataFrame({"cve_id": kev["cve_id"], "kev_day": kev["date_added"].dt.normalize()})
    kev_days = kev_days[kev_days["kev_day"] <= snapshot]
    table = table.merge(kev_days, on="cve_id", how="left")
    table["in_kev"] = table["kev_day"].notna()
    table["days_to_kev"] = (table["kev_day"] - table["published_day"]).dt.days

    # Earliest exploit of each CVE, among exploits published up to the snapshot date
    exploit_days = pd.DataFrame(
        {"cve_id": exploits["cve_id"], "day": exploits["date_published"].dt.normalize()}
    )
    exploit_days = exploit_days[exploit_days["day"] <= snapshot]
    first_exploit = exploit_days.groupby("cve_id")["day"].min().rename("first_exploit_day")
    table = table.merge(first_exploit, on="cve_id", how="left")
    table["has_exploit"] = table["first_exploit_day"].notna()
    # A comparison with an empty date is False, which is what we want here
    table["exploit_by_publication"] = table["first_exploit_day"] <= table["published_day"]

    return table.reset_index(drop=True)


def cves_per_year(study):
    """Count the CVEs of each publication year, and how many of them are in KEV."""
    per_year = study.groupby("year")["in_kev"].agg(cves="size", in_kev="sum")
    per_year["in_kev"] = per_year["in_kev"].astype(int)
    per_year["percent_in_kev"] = 100 * per_year["in_kev"] / per_year["cves"]
    return per_year


def kev_match(nvd, kev, study_start=STUDY_START, snapshot_date=SNAPSHOT_DATE):
    """Say, for the KEV CVEs listed up to the snapshot, where each one ends up.

    Returns a dictionary: reason -> number of KEV CVEs. The first reason,
    "in the study", is the matched group; the others explain the unmatched ones.
    """
    start, snapshot = as_day(study_start), as_day(snapshot_date)
    listed = kev[kev["date_added"].dt.normalize() <= snapshot]
    published = pd.DataFrame(
        {"cve_id": nvd["cve_id"], "published_day": nvd["published_at"].dt.normalize()}
    )
    merged = listed[["cve_id"]].merge(published, on="cve_id", how="left")
    day = merged["published_day"]

    in_table = day.notna()
    # For a CVE that is not in the NVD table, the year in its ID is a hint of
    # the reason: the NVD download starts in a certain year, and older CVEs
    # were never downloaded.
    first_year = int(nvd["published_at"].dt.year.min()) if len(nvd) else 0
    id_year = merged["cve_id"].str.split("-").str[1].astype(int)
    old_id = ~in_table & (id_year < first_year)

    return {
        "in the study": int((in_table & (day >= start) & (day <= snapshot)).sum()),
        "not in the study: published before STUDY_START": int((day < start).sum()),
        "not in the study: published after SNAPSHOT_DATE": int((day > snapshot).sum()),
        "not in the study: not in the NVD table, CVE ID older than the NVD download": int(
            old_id.sum()
        ),
        "not in the study: not in the NVD table, other reason (for example Rejected)": int(
            (~in_table & ~old_id).sum()
        ),
    }


def describe_days(days):
    """Give the count, minimum, 25%, median, 75% and maximum of a list of days."""
    days = pd.Series(days, dtype="float64").dropna()
    if days.empty:
        return {"count": 0, "min": None, "q25": None, "median": None, "q75": None, "max": None}
    return {
        "count": int(len(days)),
        "min": float(days.min()),
        "q25": float(days.quantile(0.25)),
        "median": float(days.median()),
        "q75": float(days.quantile(0.75)),
        "max": float(days.max()),
    }


def kev_timing_checks(study, kev_start_date=KEV_START_DATE):
    """Count two special groups among the study CVEs that are in KEV."""
    in_kev = study[study["in_kev"]]
    return {
        "listed before publication (negative days)": int((in_kev["days_to_kev"] < 0).sum()),
        "listed on the publication day (0 days)": int((in_kev["days_to_kev"] == 0).sum()),
        "listed on the KEV start date": int((in_kev["kev_day"] == as_day(kev_start_date)).sum()),
    }


def published_since(study, first_day):
    """Keep the CVEs published on or after a given day."""
    return study[study["published_day"] >= as_day(first_day)]


def exploit_shares(study):
    """Count CVEs with exploit code, among KEV CVEs and among all CVEs.

    Returns a table with one row per group and, for each of the two exploit
    measures, the number of CVEs and the percentage of the group.
    """
    groups = {"KEV CVEs": study[study["in_kev"]], "all CVEs": study}
    rows = []
    for name, group in groups.items():
        size = len(group)
        any_exploit = int(group["has_exploit"].sum())
        by_publication = int(group["exploit_by_publication"].sum())
        rows.append(
            {
                "group": name,
                "cves": size,
                "with_any_exploit": any_exploit,
                "percent_with_any_exploit": 100 * any_exploit / size if size else None,
                "with_exploit_by_publication": by_publication,
                "percent_with_exploit_by_publication": 100 * by_publication / size
                if size
                else None,
            }
        )
    return pd.DataFrame(rows).set_index("group")


def event_rate(study):
    """Share of the study CVEs that are in KEV, in percent."""
    return 100 * study["in_kev"].mean() if len(study) else None


# ---------------------------------------------------------------------------
# Figures (not tested: they only draw the numbers calculated above)
# ---------------------------------------------------------------------------


def style_axes(axes):
    """Give a plot a quiet look: light grid, no box around it."""
    axes.set_facecolor(COLOUR_BACKGROUND)
    axes.grid(axis="y", color=COLOUR_GRID, linewidth=0.8)
    axes.set_axisbelow(True)  # grid behind the bars
    for side in ("top", "right", "left"):
        axes.spines[side].set_visible(False)
    axes.spines["bottom"].set_color(COLOUR_GRID)
    axes.tick_params(colors=COLOUR_TEXT, length=0)


def plot_cves_per_year(per_year, path):
    """Figure 1: CVEs per publication year (top) and how many are in KEV (bottom).

    Two panels are used, not one, because the two counts are very different in size.
    """
    figure, (top, bottom) = plt.subplots(2, 1, figsize=(9, 7), sharex=True)
    figure.set_facecolor(COLOUR_BACKGROUND)
    years = per_year.index.astype(str)

    panels = [
        (top, per_year["cves"], COLOUR_ALL_CVES, "CVEs published"),
        (bottom, per_year["in_kev"], COLOUR_KEV, "Of these, listed in KEV by the snapshot date"),
    ]
    for axes, values, colour, title in panels:
        bars = axes.bar(years, values, color=colour, width=0.7)
        axes.bar_label(bars, labels=[f"{v:,}" for v in values], color=COLOUR_TEXT, fontsize=8)
        axes.set_title(title, loc="left", fontsize=11, color=COLOUR_TEXT)
        axes.yaxis.set_major_formatter(lambda value, _: f"{value:,.0f}")
        style_axes(axes)
    bottom.set_xlabel("Publication year", color=COLOUR_TEXT)

    figure.suptitle("CVEs per publication year, and how many are in KEV", x=0.02, ha="left")
    figure.tight_layout()
    figure.savefig(path, dpi=150)
    plt.close(figure)


def plot_days_to_kev(days, title, path):
    """Figures 2 and 3: histogram of the days from publication to KEV listing."""
    days = pd.Series(days, dtype="float64").dropna()
    figure, axes = plt.subplots(figsize=(9, 4.8))
    figure.set_facecolor(COLOUR_BACKGROUND)

    if not days.empty:
        # Bars of 30 days each. The edges are multiples of 30, so one edge is at 0.
        width = HISTOGRAM_BIN_DAYS
        first_edge = math.floor(days.min() / width) * width
        last_edge = math.floor(days.max() / width) * width + width
        edges = list(range(first_edge, last_edge + width, width))
        axes.hist(days, bins=edges, color=COLOUR_KEV, edgecolor=COLOUR_BACKGROUND, linewidth=0.5)

        # Leave room above the tallest bar for the median label
        axes.set_ylim(top=axes.get_ylim()[1] * 1.12)

        median = days.median()
        axes.axvline(median, color=COLOUR_TEXT, linewidth=1.2, linestyle="--")
        axes.annotate(
            f"median: {median:,.0f} days",
            xy=(median, 0.98),
            xycoords=("data", "axes fraction"),
            xytext=(6, 0),
            textcoords="offset points",
            color=COLOUR_TEXT,
            fontsize=9,
            va="top",
        )

    axes.set_title(f"{title}  (n = {len(days):,})", loc="left", fontsize=11)
    axes.set_xlabel(
        f"Days from publication to KEV listing (each bar is {HISTOGRAM_BIN_DAYS} days)",
        color=COLOUR_TEXT,
    )
    axes.set_ylabel("Number of CVEs", color=COLOUR_TEXT)
    axes.xaxis.set_major_formatter(lambda value, _: f"{value:,.0f}")
    style_axes(axes)
    figure.tight_layout()
    figure.savefig(path, dpi=150)
    plt.close(figure)


# ---------------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------------


def load_clean_tables(processed_dir):
    """Read the columns the EDA needs from the three clean CSV files."""
    nvd = pd.read_csv(
        processed_dir / clean_nvd.OUTPUT_FILE_NAME, usecols=["cve_id", "published_at"]
    )
    kev = pd.read_csv(processed_dir / clean_kev.OUTPUT_FILE_NAME, usecols=["cve_id", "date_added"])
    exploits = pd.read_csv(
        processed_dir / clean_exploitdb.OUTPUT_FILE_NAME, usecols=["cve_id", "date_published"]
    )
    # The dates were saved as ISO 8601 text with "Z" (UTC)
    nvd["published_at"] = pd.to_datetime(nvd["published_at"], format="ISO8601", utc=True)
    kev["date_added"] = pd.to_datetime(kev["date_added"], format="ISO8601", utc=True)
    exploits["date_published"] = pd.to_datetime(
        exploits["date_published"], format="ISO8601", utc=True
    )
    return nvd, kev, exploits


class Summary:
    """Prints each number and remembers it, so the CSV holds exactly what was printed."""

    def __init__(self):
        self.rows = []

    def section(self, title):
        self.current = title
        print()
        print(title)

    def add(self, measure, value):
        # Show whole numbers without decimals, and other numbers with two
        if isinstance(value, float):
            value = int(value) if value.is_integer() else round(value, 2)
        self.rows.append({"section": self.current, "measure": measure, "value": value})
        print(f"  {measure}: {value}")

    def add_days(self, days):
        for name, value in describe_days(days).items():
            self.add(f"days, {name}", value)

    def table(self):
        return pd.DataFrame(self.rows, columns=["section", "measure", "value"])


def main(settings=None):
    """Read the clean tables, print every number, save the figures and the summary."""
    # Folders come from vesper.config
    settings = settings or load_settings()
    processed_dir = settings.data_processed / PROCESSED_SUBFOLDER
    output_dir = settings.outputs / PROCESSED_SUBFOLDER / EDA_SUBFOLDER
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Reading:", processed_dir)
    nvd, kev, exploits = load_clean_tables(processed_dir)
    study = build_study_table(nvd, kev, exploits)
    in_kev = study[study["in_kev"]]
    summary = Summary()

    summary.section("0. Study window")
    summary.add("STUDY_START", STUDY_START.isoformat())
    summary.add("SNAPSHOT_DATE", SNAPSHOT_DATE.isoformat())
    summary.add("CVEs in the NVD table", len(nvd))
    summary.add("CVEs in the study window", len(study))

    summary.section("1. CVEs per publication year, and how many are in KEV")
    per_year = cves_per_year(study)
    for year, row in per_year.iterrows():
        summary.add(f"{year}, CVEs", int(row["cves"]))
        summary.add(f"{year}, in KEV", int(row["in_kev"]))
        summary.add(f"{year}, percent in KEV", float(row["percent_in_kev"]))

    summary.section("2. KEV match")
    summary.add("KEV CVEs in the clean KEV table", len(kev))
    for reason, count in kev_match(nvd, kev).items():
        summary.add(f"KEV CVEs {reason}", count)

    summary.section("3. Days from publication to KEV listing (study CVEs in KEV)")
    summary.add_days(in_kev["days_to_kev"])

    summary.section("4. Special groups among the study CVEs in KEV")
    for name, count in kev_timing_checks(study).items():
        summary.add(name, count)

    title_5 = f"5. Days to KEV, only CVEs published on or after {KEV_START_DATE.isoformat()}"
    summary.section(title_5)
    recent = published_since(study, KEV_START_DATE)
    recent_in_kev = recent[recent["in_kev"]]
    summary.add("CVEs published on or after that day", len(recent))
    summary.add_days(recent_in_kev["days_to_kev"])
    summary.add(
        "listed before publication (negative days)", int((recent_in_kev["days_to_kev"] < 0).sum())
    )

    summary.section("6. Exploit code in ExploitDB")
    for group, row in exploit_shares(study).iterrows():
        summary.add(f"{group}, number", int(row["cves"]))
        summary.add(f"{group}, with any exploit", int(row["with_any_exploit"]))
        summary.add(f"{group}, percent with any exploit", row["percent_with_any_exploit"])
        summary.add(
            f"{group}, with an exploit on or before publication",
            int(row["with_exploit_by_publication"]),
        )
        summary.add(
            f"{group}, percent with an exploit on or before publication",
            row["percent_with_exploit_by_publication"],
        )

    summary.section("7. Event rate")
    summary.add("CVEs in the study window", len(study))
    summary.add("of these, in KEV", len(in_kev))
    summary.add("percent in KEV", event_rate(study))

    # --- Save the figures and the summary table --------------------------------
    plot_cves_per_year(per_year, output_dir / "01_cves_per_year.png")
    plot_days_to_kev(
        in_kev["days_to_kev"],
        "Days from publication to KEV listing, all study CVEs in KEV",
        output_dir / "02_days_to_kev.png",
    )
    plot_days_to_kev(
        recent_in_kev["days_to_kev"],
        f"Days to KEV listing, CVEs published on or after {KEV_START_DATE.isoformat()}",
        output_dir / "03_days_to_kev_published_since_kev_start.png",
    )
    summary.table().to_csv(output_dir / SUMMARY_FILE_NAME, index=False)
    print()
    print("Saved figures and", SUMMARY_FILE_NAME, "to:", output_dir)
    return output_dir


if __name__ == "__main__":
    main()
