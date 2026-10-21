"""Download dated EPSS snapshots and combine them into one table."""

import argparse
import time
from datetime import date

import pandas as pd
import requests

from vesper.config import Settings, load_settings

# Check one real file name in the year folders of github.com/empiricalsec/epss_scores
URL_TEMPLATE = (
    "https://raw.githubusercontent.com/empiricalsec/epss_scores/main/"
    "{year}/epss_scores-{day}.csv.gz"
)
# Scores shift when a new EPSS model starts publishing (dates from FIRST's data page)
MODEL_STARTS = (
    ("v5", date(2026, 6, 15)),
    ("v4", date(2025, 3, 17)),
    ("v3", date(2023, 3, 7)),
    ("v2", date(2022, 2, 4)),
)


def model_version(day: date) -> str:
    for name, start in MODEL_STARTS:
        if day >= start:
            return name
    return "v1"


def snapshot_days(start: date) -> list[date]:
    """First day of every month from `start` until today."""
    return [stamp.date() for stamp in pd.date_range(start, date.today(), freq="MS")]


def download(settings: Settings, days: list[date]) -> None:
    folder = settings.raw_source("epss")
    folder.mkdir(parents=True, exist_ok=True)
    for day in days:
        path = folder / f"epss_{day:%Y-%m-%d}.csv.gz"
        if path.exists():
            continue
        url = URL_TEMPLATE.format(year=day.year, day=f"{day:%Y-%m-%d}")
        response = requests.get(url, timeout=120)
        if response.status_code == 404:
            print("not found:", day)
            continue
        response.raise_for_status()
        path.write_bytes(response.content)
        print("saved", path.name)
        time.sleep(0.5)


def combine(settings: Settings) -> pd.DataFrame:
    """Join all snapshots into one table, keeping only CVEs that are in the NVD table."""
    ids = pd.read_parquet(settings.data_processed / "vulnerabilities.parquet", columns=["cve_id"])
    known = set(ids["cve_id"])
    frames = []
    for path in sorted(settings.raw_source("epss").glob("epss_*.csv.gz")):
        day = date.fromisoformat(path.name[5:15])
        frame = pd.read_csv(path, comment="#")  # newer files start with a '#' version line
        frame = frame.rename(columns={"cve": "cve_id", "epss": "epss_score"})
        frame["cve_id"] = frame["cve_id"].str.strip().str.upper()
        frame = frame[frame["cve_id"].isin(known)].copy()
        frame["epss_date"] = day
        frame["epss_model_version"] = model_version(day)
        frames.append(frame)
    if not frames:
        raise SystemExit("No EPSS files found. Check URL_TEMPLATE and run again.")
    table = pd.concat(frames, ignore_index=True)
    table.to_parquet(settings.data_processed / "epss_snapshots.parquet", index=False)
    return table


def main() -> None:
    parser = argparse.ArgumentParser(description="Download EPSS snapshots")
    parser.add_argument("--start", default="2023-01-01", help="first snapshot month, YYYY-MM-DD")
    args = parser.parse_args()

    settings = load_settings()
    download(settings, snapshot_days(date.fromisoformat(args.start)))
    table = combine(settings)
    print(f"{len(table)} rows, {table['cve_id'].nunique()} CVEs")


if __name__ == "__main__":
    main()