"""
Download the CISA KEV (Known Exploited Vulnerabilities) catalogue.

KEV is the official list of CVEs confirmed as exploited in the wild.
In Component B it provides the "event" date: the `dateAdded` field.

Run from anywhere:
    uv run python -m vesper.components.b_survival.download_kev
"""

import json
import sys
from datetime import date

import requests

from vesper.config import load_settings

# Official KEV catalogue feed published by CISA
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# data/raw/kev/ in the project (path comes from vesper.config)
RAW_DIR = load_settings().raw_source("kev")


def download_kev():
    """Download the KEV JSON, save it unchanged, and return the saved file path."""
    print("Downloading KEV catalogue from:", KEV_URL)

    # --- 1. Download -------------------------------------------------------
    try:
        response = requests.get(KEV_URL, timeout=60)
        # Turn HTTP errors (404, 500, ...) into Python exceptions
        response.raise_for_status()
    except requests.exceptions.RequestException as error:
        # Covers: no internet, timeout, wrong URL, server error
        print("ERROR: could not download the KEV catalogue.")
        print("Reason:", error)
        sys.exit(1)

    # --- 2. Check that what we received really is JSON ---------------------
    try:
        catalogue = json.loads(response.content)
    except json.JSONDecodeError as error:
        print("ERROR: the downloaded file is not valid JSON.")
        print("Reason:", error)
        sys.exit(1)

    # --- 3. Save the raw bytes exactly as received -------------------------
    # The download date in the filename records WHEN this snapshot was taken.
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    output_path = RAW_DIR / f"kev_{date.today().isoformat()}.json"
    output_path.write_bytes(response.content)
    print("Saved to:", output_path)

    # --- 4. Print a short summary ------------------------------------------
    vulnerabilities = catalogue["vulnerabilities"]  # list with one record per CVE
    # Dates are text in YYYY-MM-DD format, so min/max on text gives earliest/latest
    dates_added = [record["dateAdded"] for record in vulnerabilities]

    print("Catalogue version:", catalogue.get("catalogVersion"))
    print("Number of CVEs:", len(vulnerabilities))
    print("Earliest dateAdded:", min(dates_added))
    print("Latest dateAdded:", max(dates_added))

    return output_path


if __name__ == "__main__":
    download_kev()
