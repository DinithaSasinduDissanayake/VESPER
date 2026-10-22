"""Download CVE records from the NVD API and convert them to Vulnerability records."""

import argparse
import gzip
import json
import time
from dataclasses import asdict
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pandas as pd
import requests

from vesper.config import Settings, load_settings
from vesper.contracts.vulnerability import Vulnerability

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WINDOW_DAYS = 119  # NVD allows at most 120 days per request
PAGE_SIZE = 2000
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.000"
# The first CVSS version found in this order is used
CVSS_KEYS = ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2")


def _get(params: dict, api_key: str | None) -> dict:
    headers = {"apiKey": api_key} if api_key else {}
    for attempt in range(1, 6):
        response = requests.get(NVD_URL, params=params, headers=headers, timeout=60)
        if response.status_code == 200:
            return response.json()
        print(f"  HTTP {response.status_code}, retry {attempt}/5")
        time.sleep(10 * attempt)
    response.raise_for_status()
    raise RuntimeError("NVD request failed")


def download(settings: Settings, start: date, snapshot: date) -> Path:
    """Save every CVE published from `start` until now as one gzipped JSON-lines file."""
    api_key = settings.nvd_api_key
    print("Using an NVD API key" if api_key else "No NVD API key found: this will be slow")
    pause = 0.7 if api_key else 6.5  # stay under NVD's rate limit
    folder = settings.raw_source("nvd")
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"nvd_{snapshot:%Y-%m-%d}.jsonl.gz"
    partial = path.with_name(path.name + ".part")

    window_start = datetime(start.year, start.month, start.day)
    stop = datetime.now(UTC).replace(tzinfo=None)
    with gzip.open(partial, "wt", encoding="utf-8") as out:
        while window_start < stop:
            window_end = min(window_start + timedelta(days=WINDOW_DAYS), stop)
            index = 0
            while True:
                params = {
                    "pubStartDate": window_start.strftime(TIME_FORMAT),
                    "pubEndDate": window_end.strftime(TIME_FORMAT),
                    "startIndex": index,
                    "resultsPerPage": PAGE_SIZE,
                }
                page = _get(params, api_key)
                for item in page["vulnerabilities"]:
                    out.write(json.dumps(item["cve"]) + "\n")
                index += PAGE_SIZE
                total = page["totalResults"]
                print(f"{window_start:%Y-%m-%d}: {min(index, total)}/{total}")
                time.sleep(pause)
                if index >= total:
                    break
            # Windows share one boundary instant; duplicates are dropped in build()
            window_start = window_end
    partial.replace(path)  # only a finished download gets the final name
    return path


def _utc(text: str) -> datetime:
    # NVD gives times without a zone; they are UTC
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


def _cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    for key in CVSS_KEYS:
        entries = metrics.get(key) or []
        if entries:
            entry = next((m for m in entries if m.get("type") == "Primary"), entries[0])
            data = entry["cvssData"]
            return data.get("baseScore"), data.get("version"), data.get("vectorString")
    return None, None, None


def _cwe_ids(weaknesses: list[dict]) -> tuple[str, ...]:
    found: list[str] = []
    for weakness in weaknesses:
        for item in weakness.get("description", []):
            value = item["value"]
            if value.startswith("CWE-") and value not in found:
                found.append(value)
    return tuple(found)


def _affected(configurations: list[dict]) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for configuration in configurations:
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                parts = match["criteria"].split(":")
                if len(parts) > 4 and (parts[3], parts[4]) not in pairs:
                    pairs.append((parts[3], parts[4]))
    return tuple(pairs)


def parse(cve: dict, snapshot: date) -> Vulnerability:
    """Convert one raw NVD record into the shared Vulnerability record."""
    score, version, vector = _cvss(cve.get("metrics", {}))
    description = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    return Vulnerability(
        cve_id=cve["id"],
        published_at=_utc(cve["published"]),
        last_modified_at=_utc(cve["lastModified"]),
        description=description,
        cvss_base_score=score,
        cvss_version=version,
        cvss_vector=vector,
        cwe_ids=_cwe_ids(cve.get("weaknesses", [])),
        affected=_affected(cve.get("configurations", [])),
        nvd_status=cve.get("vulnStatus", ""),
        snapshot_date=snapshot,
    )


def build(settings: Settings, raw_file: Path, snapshot: date) -> pd.DataFrame:
    """Turn the raw file into one validated row per CVE."""
    rows: dict[str, dict] = {}
    skipped = 0
    with gzip.open(raw_file, "rt", encoding="utf-8") as handle:
        for line in handle:
            cve = json.loads(line)
            if cve.get("vulnStatus") == "Rejected":
                continue
            try:
                record = parse(cve, snapshot)
            except ValueError as error:
                skipped += 1
                print("skipped", cve.get("id"), error)
                continue
            row = asdict(record)
            row["cwe_ids"] = list(record.cwe_ids)
            row["affected"] = [list(pair) for pair in record.affected]
            rows[record.cve_id] = row
    frame = pd.DataFrame(list(rows.values()))
    settings.data_processed.mkdir(parents=True, exist_ok=True)
    frame.to_parquet(settings.data_processed / "vulnerabilities.parquet", index=False)
    print(f"Kept {len(frame)} CVEs, skipped {skipped}")
    return frame


def main() -> None:
    parser = argparse.ArgumentParser(description="Download CVEs from NVD")
    parser.add_argument("--start", default="2023-01-01", help="first publish date, YYYY-MM-DD")
    args = parser.parse_args()

    settings = load_settings()
    today = date.today()
    raw_file = download(settings, date.fromisoformat(args.start), today)
    table = build(settings, raw_file, today)
    print(f"CVSS missing for {table['cvss_base_score'].isna().mean():.1%} of CVEs")


if __name__ == "__main__":
    main()