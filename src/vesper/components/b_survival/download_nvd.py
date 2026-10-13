"""
Download CVE records from the NVD (National Vulnerability Database) API 2.0.

NVD gives, for every CVE, the disclosure date (`published`) and the CVSS
score and vector. In Component B the published date is the start of the
survival clock and the CVSS metrics are the main covariates.

The download is split into one file per month of publication:
    data/raw/nvd/nvd_2015-01.json.gz, nvd_2015-02.json.gz, ...
If the script stops halfway, run it again: months already saved are skipped.

Run from anywhere (everything from START_YEAR, or one month only for testing):
    uv run python -m vesper.components.b_survival.download_nvd
    uv run python -m vesper.components.b_survival.download_nvd 2015-01
"""

import calendar
import gzip
import json
import sys
import time
from datetime import UTC, date, datetime

import requests

from vesper.config import load_settings

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

# First publication year to download (study period not fixed yet -> change here)
START_YEAR = 2015

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# The API returns at most 2000 CVEs per request ("page")
RESULTS_PER_PAGE = 2000

# NVD rate limits (per rolling 30 seconds): 5 requests without a key, 50 with a key.
# We pause between requests so we always stay well below the limit.
PAUSE_WITH_KEY = 2  # seconds
PAUSE_WITHOUT_KEY = 7  # seconds

# If a request fails, try again this many times, waiting longer each time
MAX_RETRIES = 5

# Folder and API key come from vesper.config (key is read from the top-level .env,
# never written in this script, never printed)
SETTINGS = load_settings()
NVD_DIR = SETTINGS.raw_source("nvd")
API_KEY = SETTINGS.nvd_api_key

PAUSE = PAUSE_WITH_KEY if API_KEY else PAUSE_WITHOUT_KEY


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def list_months(start_year):
    """Return every (year, month) from January of start_year up to the current month."""
    today = date.today()
    months = []
    for year in range(start_year, today.year + 1):
        for month in range(1, 13):
            if (year, month) <= (today.year, today.month):
                months.append((year, month))
    return months


def fetch_page(year, month, start_index):
    """Ask the API for one page of CVEs published in the given month."""
    last_day = calendar.monthrange(year, month)[1]  # 28, 29, 30 or 31
    params = {
        # Publication-date window (UTC). The API allows at most 120 days; one month is safe.
        "pubStartDate": f"{year}-{month:02d}-01T00:00:00.000Z",
        "pubEndDate": f"{year}-{month:02d}-{last_day}T23:59:59.999Z",
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex": start_index,  # where this page starts (0, 2000, 4000, ...)
    }
    # The key is sent as a request header, as the NVD documentation requires
    headers = {"apiKey": API_KEY} if API_KEY else {}

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=120)
            response.raise_for_status()  # HTTP errors (403, 503, ...) -> exception
            return response.json()
        except (requests.exceptions.RequestException, ValueError) as error:
            # Covers: no internet, timeout, rate limit hit, server busy, invalid JSON
            wait = 10 * attempt
            print(f"    request failed (attempt {attempt}/{MAX_RETRIES}): {error}")
            print(f"    waiting {wait} seconds before trying again...")
            time.sleep(wait)

    print("ERROR: NVD did not answer after several attempts.")
    print("Progress so far is saved. Run the script again later to continue.")
    sys.exit(1)


def download_month(year, month):
    """Download all CVEs published in one month, save them, and return how many."""
    cves = []
    start_index = 0

    while True:
        page = fetch_page(year, month, start_index)
        cves.extend(page["vulnerabilities"])  # one record per CVE
        total = page["totalResults"]  # how many CVEs NVD has for this month
        time.sleep(PAUSE)  # respect the rate limit

        start_index += RESULTS_PER_PAGE
        if start_index >= total:  # no more pages
            break

    # Safety check: we must have received exactly what NVD said exists
    if len(cves) != total:
        print(f"ERROR: {year}-{month:02d}: expected {total} CVEs but received {len(cves)}.")
        sys.exit(1)

    content = {
        "month": f"{year}-{month:02d}",
        "downloaded_at": datetime.now(UTC).isoformat(),  # when this snapshot was taken
        "totalResults": total,
        "vulnerabilities": cves,  # records exactly as NVD returned them
    }

    # Write to a temporary file first and rename it at the end, so a file that
    # exists is always complete (an interrupted run never leaves a half file).
    # gzip compresses the JSON to roughly a tenth of its size.
    output_path = NVD_DIR / f"nvd_{year}-{month:02d}.json.gz"
    temp_path = output_path.with_suffix(".tmp")
    with gzip.open(temp_path, "wt", encoding="utf-8") as file:
        json.dump(content, file)
    temp_path.replace(output_path)

    return total


def count_saved_cves():
    """Count the CVEs in every monthly file on disk."""
    total = 0
    for path in sorted(NVD_DIR.glob("nvd_*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as file:
            total += len(json.load(file)["vulnerabilities"])
    return total


# ---------------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------------


def main():
    NVD_DIR.mkdir(parents=True, exist_ok=True)

    # Optional argument "YYYY-MM" = download only that month (used for testing)
    if len(sys.argv) > 1:
        year, month = sys.argv[1].split("-")
        months = [(int(year), int(month))]
    else:
        months = list_months(START_YEAR)

    print("API key found:", "yes" if API_KEY else "no (slower rate limit)")
    print(f"Pause between requests: {PAUSE} seconds")
    print(f"Months to process: {len(months)}")

    today = date.today()
    for number, (year, month) in enumerate(months, start=1):
        label = f"[{number}/{len(months)}] {year}-{month:02d}"
        output_path = NVD_DIR / f"nvd_{year}-{month:02d}.json.gz"

        # Skip finished months. The current month is always downloaded again,
        # because new CVEs are still being published in it.
        is_current_month = (year, month) == (today.year, today.month)
        if output_path.exists() and not is_current_month:
            print(f"{label}: already downloaded, skipping")
            continue

        count = download_month(year, month)
        print(f"{label}: saved {count} CVEs")

    print("Done.")
    print("Total CVEs in", NVD_DIR, ":", count_saved_cves())


if __name__ == "__main__":
    main()
