"""Download the CISA KEV catalog: CVEs confirmed as exploited in the wild."""

import json
from datetime import date
from pathlib import Path

import pandas as pd
import requests

from vesper.config import Settings, load_settings

GITHUB_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/develop"
CISA_FEED = "https://www.cisa.gov/sites/default/files/feeds"
FILE_NAME = "known_exploited_vulnerabilities.json"
# The official CISA mirror on GitHub is tried first; cisa.gov can block scripts
KEV_URLS = (f"{GITHUB_MIRROR}/{FILE_NAME}", f"{CISA_FEED}/{FILE_NAME}")
HEADERS = {"User-Agent": "Mozilla/5.0 (VESPER research project)"}


def download(settings: Settings, today: date) -> Path:
    folder = settings.raw_source("kev")
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"kev_{today:%Y-%m-%d}.json"
    for url in KEV_URLS:
        try:
            response = requests.get(url, headers=HEADERS, timeout=60)
            response.raise_for_status()
        except requests.RequestException as error:
            print(f"failed: {url} ({error})")
            continue
        path.write_bytes(response.content)
        print("saved", path.name, "from", url)
        return path
    raise SystemExit("Could not download the KEV catalog from any source")


def build(settings: Settings, raw_file: Path) -> pd.DataFrame:
    """One row per KEV CVE with the date CISA added it."""
    catalog = json.loads(raw_file.read_text(encoding="utf-8"))
    rows = [
        {
            "cve_id": item["cveID"].strip().upper(),
            "kev_added_on": date.fromisoformat(item["dateAdded"]),
            "ransomware_use": item.get("knownRansomwareCampaignUse"),
        }
        for item in catalog["vulnerabilities"]
    ]
    kev = pd.DataFrame(rows).drop_duplicates("cve_id")
    settings.data_processed.mkdir(parents=True, exist_ok=True)
    kev.to_parquet(settings.data_processed / "kev.parquet", index=False)

    # How many KEV CVEs fall inside the CVEs we downloaded from NVD?
    nvd_ids = pd.read_parquet(
        settings.data_processed / "vulnerabilities.parquet", columns=["cve_id"]
    )
    inside = kev[kev["cve_id"].isin(set(nvd_ids["cve_id"]))]
    print(f"KEV entries: {len(kev)}")
    print(f"KEV entries that are in your NVD table: {len(inside)} of {len(nvd_ids)} CVEs")
    print("Added to KEV per year (only those in your NVD table):")
    print(inside.groupby(pd.to_datetime(inside["kev_added_on"]).dt.year).size())
    return kev


def main() -> None:
    settings = load_settings()
    raw_file = download(settings, date.today())
    build(settings, raw_file)


if __name__ == "__main__":
    main()