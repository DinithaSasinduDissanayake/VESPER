"""Build Component A's CVE table from the raw NVD monthly files and the KEV catalogue."""

import argparse
import gzip
import json
import time
from pathlib import Path

import pandas as pd

from vesper.config import load_settings

OUTPUT_SUBFOLDER = "a_text"  # the table goes in data/processed/a_text/
COLUMNS = [
    "cve_id",
    "published_date",
    "description",
    "kev_date_added",
    "vuln_status",
    "cvss_base_score",
]
# The CVSS baseline uses the newest CVSS version NVD gives a base score for (v4.0 is not used).
CVSS_VERSIONS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def english_description(cve: dict) -> str:
    """The first English description (unchanged), otherwise the first one, otherwise ''."""
    descriptions = cve.get("descriptions") or []
    english = [d for d in descriptions if d.get("lang") == "en"]
    return (english or descriptions or [{}])[0].get("value") or ""


def cvss_base_score(cve: dict) -> float | None:
    """Base score of the first metric listed for the newest CVSS version present, else None."""
    metrics = cve.get("metrics") or {}
    for version in CVSS_VERSIONS:
        for metric in metrics.get(version) or []:
            score = (metric.get("cvssData") or {}).get("baseScore")
            if score is not None:
                return float(score)
    return None


def read_nvd(nvd_dir: Path) -> pd.DataFrame:
    """One row per CVE from every nvd_*.json.gz file; Rejected CVEs are kept."""
    rows = []
    for path in sorted(nvd_dir.glob("nvd_*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as file:
            for item in json.load(file)["vulnerabilities"]:
                cve = item["cve"]
                rows.append(
                    {
                        "cve_id": cve["id"].strip().upper(),
                        "published_date": cve.get("published"),
                        "last_modified": cve.get("lastModified"),
                        "description": english_description(cve),
                        "vuln_status": cve.get("vulnStatus"),
                        "cvss_base_score": cvss_base_score(cve),
                    }
                )
    if not rows:
        raise FileNotFoundError(f"no nvd_*.json.gz files in {nvd_dir}")
    frame = pd.DataFrame(rows)
    frame["cvss_base_score"] = frame.cvss_base_score.astype(float)  # None -> NaN
    # NVD times carry no zone but are UTC.
    for column in ("published_date", "last_modified"):
        frame[column] = pd.to_datetime(frame[column], utc=True, format="ISO8601")
    # A CVE in two files: keep its newest record (ties: the later file).
    frame = frame.sort_values("last_modified", kind="stable")
    return frame.drop_duplicates("cve_id", keep="last").drop(columns="last_modified")


def read_kev(kev_file: Path) -> pd.DataFrame:
    """cve_id and the date it was added to KEV (UTC midnight)."""
    items = json.loads(kev_file.read_text(encoding="utf-8"))["vulnerabilities"]
    kev = pd.DataFrame(
        {
            "cve_id": [i["cveID"].strip().upper() for i in items],
            "kev_date_added": pd.to_datetime([i["dateAdded"] for i in items], utc=True),
        }
    )
    return kev.sort_values("kev_date_added").drop_duplicates("cve_id")  # earliest listing


def build(nvd_dir: Path, kev_file: Path, out: Path) -> pd.DataFrame:
    """Join NVD and KEV, sort by CVE id and write the table to `out`."""
    table = read_nvd(nvd_dir).merge(read_kev(kev_file), on="cve_id", how="left")
    table = table[COLUMNS].sort_values("cve_id").reset_index(drop=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    table.to_parquet(out, index=False)
    return table


def main(argv=None):
    settings = load_settings()
    kev_files = sorted(settings.raw_source("kev").glob("kev_*.json"))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nvd", type=Path, default=settings.raw_source("nvd"))
    parser.add_argument("--kev", type=Path, default=kev_files[-1] if kev_files else None)
    parser.add_argument(
        "--out", type=Path, default=settings.data_processed / OUTPUT_SUBFOLDER / "cves.parquet"
    )
    args = parser.parse_args(argv)
    if args.kev is None:
        parser.error("no kev_*.json found; pass --kev")
    start = time.perf_counter()
    table = build(args.nvd, args.kev, args.out)
    print(
        f"{len(table):,} CVEs, {table.kev_date_added.notna().sum():,} in KEV -> {args.out} "
        f"({time.perf_counter() - start:.0f}s)"
    )


if __name__ == "__main__":
    main()
