"""Prepare the shared CVSS and EPSS baseline inputs for Component D."""

import argparse
from datetime import date

import pandas as pd

from vesper.config import Settings, load_settings

OUTPUT_NAME = "d_fusion_baselines.parquet"
CVSS_COLUMNS = ("cvss_base_score", "cvss_version", "cvss_vector")
EPSS_COLUMNS = ("epss_score", "percentile", "epss_date", "epss_model_version")


def build_baseline_inputs(settings: Settings) -> pd.DataFrame:
    """Join NVD CVSS fields to the latest available EPSS snapshot as of NVD.

    The current NVD table is a single snapshot, while the EPSS table contains
    history. Selecting only the latest EPSS date at or before the NVD snapshot
    avoids pairing today's CVSS enrichment with earlier EPSS history.
    """

    nvd_path = settings.data_processed / "vulnerabilities.parquet"
    epss_path = settings.data_processed / "epss_snapshots.parquet"
    if not nvd_path.is_file():
        raise FileNotFoundError(f"NVD table not found: {nvd_path}")
    if not epss_path.is_file():
        raise FileNotFoundError(f"EPSS snapshots not found: {epss_path}")

    vulnerabilities = pd.read_parquet(nvd_path)
    epss = pd.read_parquet(epss_path)
    required_nvd = {"cve_id", "snapshot_date", *CVSS_COLUMNS}
    required_epss = {"cve_id", *EPSS_COLUMNS}
    missing_nvd = required_nvd.difference(vulnerabilities.columns)
    missing_epss = required_epss.difference(epss.columns)
    if missing_nvd:
        raise ValueError(f"NVD table is missing columns: {sorted(missing_nvd)}")
    if missing_epss:
        raise ValueError(f"EPSS table is missing columns: {sorted(missing_epss)}")
    if vulnerabilities.empty:
        raise ValueError("NVD table contains no vulnerabilities")
    if epss.empty:
        raise ValueError("EPSS table contains no snapshots")

    vulnerabilities = vulnerabilities.copy()
    epss = epss.copy()
    vulnerabilities["cve_id"] = vulnerabilities["cve_id"].str.strip().str.upper()
    epss["cve_id"] = epss["cve_id"].str.strip().str.upper()

    nvd_dates = pd.to_datetime(vulnerabilities["snapshot_date"]).dt.date.unique()
    if len(nvd_dates) != 1:
        raise ValueError("NVD table must contain exactly one snapshot date")
    nvd_date = nvd_dates[0]
    epss["epss_date"] = pd.to_datetime(epss["epss_date"]).dt.date
    usable_dates = epss.loc[epss["epss_date"] <= nvd_date, "epss_date"]
    if usable_dates.empty:
        raise ValueError(f"No EPSS snapshot is available on or before {nvd_date}")
    selected_epss_date = usable_dates.max()

    nvd = vulnerabilities[["cve_id", "snapshot_date", *CVSS_COLUMNS]]
    epss_selected = epss.loc[
        epss["epss_date"] == selected_epss_date, list(required_epss)
    ]
    if nvd["cve_id"].duplicated().any():
        raise ValueError("NVD table contains duplicate CVE IDs")
    if epss_selected["cve_id"].duplicated().any():
        raise ValueError(f"EPSS snapshot {selected_epss_date} contains duplicate CVE IDs")
    if not epss_selected["epss_score"].dropna().between(0.0, 1.0).all():
        raise ValueError("EPSS scores must be between 0 and 1")
    if not nvd["cvss_base_score"].dropna().between(0.0, 10.0).all():
        raise ValueError("CVSS base scores must be between 0 and 10")

    result = nvd.merge(
        epss_selected,
        on="cve_id",
        how="left",
        validate="one_to_one",
        sort=False,
    )
    result["snapshot_date"] = pd.to_datetime(result["snapshot_date"]).dt.date
    result = result[
        ["cve_id", "snapshot_date", *CVSS_COLUMNS, *EPSS_COLUMNS]
    ]
    return result.sort_values("cve_id", kind="stable").reset_index(drop=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Join shared NVD CVSS fields with the latest as-of EPSS snapshot"
    )
    parser.parse_args()

    settings = load_settings()
    result = build_baseline_inputs(settings)
    output_path = settings.data_processed / OUTPUT_NAME
    output_path.parent.mkdir(parents=True, exist_ok=True)
    result.to_parquet(output_path, index=False)
    print(f"Saved {len(result)} CVEs to {output_path}")
    print(f"EPSS coverage: {result['epss_score'].notna().sum()} CVEs")
    print(f"CVSS coverage: {result['cvss_base_score'].notna().sum()} CVEs")
    if result["epss_date"].notna().any():
        print(f"EPSS snapshot: {result['epss_date'].dropna().iloc[0]}")
    print(f"NVD snapshot: {result['snapshot_date'].iloc[0]}")


if __name__ == "__main__":
    main()
