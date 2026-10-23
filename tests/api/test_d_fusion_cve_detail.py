"""CVE detail reads vendor/product pairs back from the NVD parquet."""

import pandas as pd
from fastapi.testclient import TestClient

from vesper.api import knapsack
from vesper.api.main import app
from vesper.config import load_settings


def test_affected_pairs_survive_parquet_round_trip(tmp_path, monkeypatch):
    settings = load_settings(tmp_path)
    settings.data_processed.mkdir(parents=True)
    pd.DataFrame(
        [
            {
                "cve_id": "CVE-2026-0001",
                "description": "Example",
                "published_at": pd.Timestamp("2026-01-01", tz="UTC"),
                "last_modified_at": pd.Timestamp("2026-01-02", tz="UTC"),
                "cvss_base_score": 7.5,
                "cvss_version": "3.1",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "cwe_ids": ["CWE-79"],
                "affected": [["acme", "widget"], ["acme", "gadget"]],
                "nvd_status": "Analyzed",
                "snapshot_date": pd.Timestamp("2026-10-01", tz="UTC"),
            }
        ]
    ).to_parquet(settings.data_processed / "vulnerabilities.parquet", index=False)
    monkeypatch.setattr(knapsack, "load_settings", lambda: settings)

    response = TestClient(app).get("/api/d-fusion/cves/CVE-2026-0001")

    assert response.status_code == 200
    assert response.json()["affected"] == [["acme", "widget"], ["acme", "gadget"]]
    assert response.json()["cwe_ids"] == ["CWE-79"]
