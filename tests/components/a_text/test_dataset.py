import gzip
import json

import pandas as pd

from vesper.components.a_text.dataset import (
    COLUMNS,
    build,
    cvss_base_score,
    english_description,
    main,
)


def cve(cve_id, published, modified, descriptions, status="Analyzed"):
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "lastModified": modified,
            "vulnStatus": status,
            "descriptions": descriptions,
        }
    }


def write_month(folder, month, records):
    folder.mkdir(exist_ok=True)
    with gzip.open(folder / f"nvd_{month}.json.gz", "wt", encoding="utf-8") as file:
        json.dump({"month": month, "vulnerabilities": records}, file)


def make_raw(tmp_path):
    nvd, kev = tmp_path / "nvd", tmp_path / "kev.json"
    es = {"lang": "es", "value": "texto"}
    write_month(
        nvd,
        "2024-01",
        [
            cve(
                "CVE-2024-0001",
                "2024-01-05T10:00:00.000",
                "2024-01-06T00:00:00.000",
                [es, {"lang": "en", "value": "old text"}],
            ),
            cve(
                "CVE-2024-0002",
                "2024-01-07T00:00:00.000",
                "2024-01-07T00:00:00.000",
                [es],
                status="Rejected",
            ),
        ],
    )
    write_month(
        nvd,
        "2024-02",
        [
            cve(
                "CVE-2024-0001",
                "2024-01-05T10:00:00.000",
                "2024-03-01T00:00:00.000",
                [{"lang": "en", "value": "new text"}],
            ),
            cve("CVE-2024-0003", "2024-02-01T00:00:00.000", "2024-02-01T00:00:00.000", []),
        ],
    )
    kev.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {"cveID": "CVE-2024-0001", "dateAdded": "2024-02-10"},
                    {"cveID": "CVE-2099-9999", "dateAdded": "2024-02-11"},  # not in NVD: dropped
                ]
            }
        ),
        encoding="utf-8",
    )
    return nvd, kev


def test_english_description_is_preferred_then_first_then_empty():
    assert (
        english_description(
            {"descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "y"}]}
        )
        == "y"
    )
    assert english_description({"descriptions": [{"lang": "es", "value": "x"}]}) == "x"
    assert english_description({}) == ""


def test_build_joins_kev_dedups_and_writes_the_train_columns(tmp_path):
    nvd, kev = make_raw(tmp_path)
    out = tmp_path / "out" / "cves.parquet"
    build(nvd, kev, out)
    table = pd.read_parquet(out).set_index("cve_id")

    assert list(pd.read_parquet(out).columns) == COLUMNS
    assert list(table.index) == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
    assert table.loc["CVE-2024-0001", "description"] == "new text"  # newest record wins
    assert table.loc["CVE-2024-0002", "vuln_status"] == "Rejected"  # Rejected kept
    assert table.loc["CVE-2024-0001", "kev_date_added"] == pd.Timestamp("2024-02-10", tz="UTC")
    assert table.kev_date_added.isna().sum() == 2
    assert table.loc["CVE-2024-0001", "published_date"] == pd.Timestamp(
        "2024-01-05 10:00", tz="UTC"
    )


def test_main_cli(tmp_path, capsys):
    nvd, kev = make_raw(tmp_path)
    out = tmp_path / "cves.parquet"
    main(["--nvd", str(nvd), "--kev", str(kev), "--out", str(out)])
    assert "3 CVEs, 1 in KEV" in capsys.readouterr().out
    assert len(pd.read_parquet(out)) == 3


def test_cvss_base_score_prefers_the_newest_version():
    def metric(score):
        return [{"cvssData": {"baseScore": score}}]

    v2, v30, v31 = metric(5.0), metric(7.5), metric(9.8)
    assert cvss_base_score({"metrics": {"cvssMetricV2": v2, "cvssMetricV31": v31}}) == 9.8
    assert cvss_base_score({"metrics": {"cvssMetricV2": v2, "cvssMetricV30": v30}}) == 7.5
    assert cvss_base_score({"metrics": {"cvssMetricV2": v2, "cvssMetricV40": metric(1.0)}}) == 5.0
    assert cvss_base_score({}) is None
