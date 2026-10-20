import csv
import gzip
import importlib.util
import json
from pathlib import Path

import pandas as pd

_script = (
    Path(__file__).resolve().parents[3] / "scripts" / "select_c_graph_history_expansion_batch.py"
)
_spec = importlib.util.spec_from_file_location("history_expansion_batch_selection", _script)
_selection = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_selection)


def _valid_history(cve_id):
    return {
        "resultsPerPage": 0,
        "startIndex": 0,
        "totalResults": 0,
        "format": "NVD_CVEHistory",
        "version": "2.0",
        "timestamp": "2026-10-15T00:00:00.000",
        "cveChanges": [],
        "vesperPagination": {"page_count": 1},
    }


def _write_fixture(tmp_path):
    manifest = tmp_path / "manifest.csv"
    histories = tmp_path / "histories"
    histories.mkdir()
    rows = []
    for year in range(2016, 2026):
        for index in range(8):
            cve_id = f"CVE-{year}-{index:05d}"
            rows.append({"cve_id": cve_id, "published": f"{year}-06-01T00:00:00+00:00"})
        (histories / f"CVE-{year}-00000.json").write_text(
            json.dumps(_valid_history(f"CVE-{year}-00000")), encoding="utf-8"
        )
    with manifest.open("w", encoding="utf-8", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=["cve_id", "published"])
        writer.writeheader()
        writer.writerows(rows)
    return manifest, histories


def test_batch_selection_is_deterministic_stratified_and_excludes_valid_histories(tmp_path):
    manifest, histories = _write_fixture(tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"
    args = {
        "manifest_path": manifest,
        "history_dirs": (histories,),
        "seed": "test-seed",
        "sample_per_year": 5,
        "request_ceiling": 20,
    }
    first_metadata = _selection.select_batch(output_dir=first, **args)
    second_metadata = _selection.select_batch(output_dir=second, **args)

    first_frame = pd.read_csv(first / "selection_manifest.csv")
    second_frame = pd.read_csv(second / "selection_manifest.csv")
    pd.testing.assert_frame_equal(first_frame, second_frame)
    assert len(first_frame) == 50
    assert first_frame["cve_id"].is_unique
    assert first_frame.groupby("publication_year_stratum").size().eq(5).all()
    assert not first_frame["cve_id"].str.endswith("00000").any()
    assert first_frame["existing_cpe_cwe_history_status"].eq("unknown_no_valid_local_history").all()
    assert first_metadata["sample_is_probability_sample"] is False
    assert first_metadata["request_ceiling_including_retries"] == 20
    budget = _selection.DurableRequestBudget(first / "request_reservations.sqlite3", maximum=None)
    assert budget.maximum == 20
    budget.close()
    assert (
        first_metadata["selection_manifest_sha256"] == second_metadata["selection_manifest_sha256"]
    )

    with gzip.open(first / "request_input" / "selected_nvd_ids.json.gz", "rt") as source:
        request_ids = [item["cve"]["id"] for item in json.load(source)["vulnerabilities"]]
    assert request_ids == first_frame["cve_id"].tolist()
