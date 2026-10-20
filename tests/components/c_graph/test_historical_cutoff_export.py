import csv
import json

import pandas as pd

from vesper.components.c_graph.historical_cutoff_export import run_historical_cutoff_export

CVE_ACTIVE = "CVE-2022-11111"
CVE_EMPTY = "CVE-2022-22222"
CVE_FUTURE = "CVE-2024-33333"
CUTOFF = "2023-01-01T00:00:00+00:00"


def make_history(cve_id, events):
    changes = [
        {
            "change": {
                "cveId": cve_id,
                "cveChangeId": f"event-{index}",
                "created": created,
                "details": details,
            }
        }
        for index, (created, details) in enumerate(events)
    ]
    return {
        "resultsPerPage": len(changes),
        "startIndex": 0,
        "totalResults": len(changes),
        "format": "NVD_CVEHistory",
        "version": "2.0",
        "timestamp": "2026-10-15T00:00:00.000Z",
        "cveChanges": changes,
    }


def _write_case_files(tmp_path):
    histories = tmp_path / "histories"
    histories.mkdir()
    cpe = "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*"
    histories.joinpath(f"{CVE_ACTIVE}.json").write_text(
        json.dumps(
            make_history(
                CVE_ACTIVE,
                [
                    (
                        "2022-10-01T00:00:00Z",
                        [
                            {"action": "Added", "type": "CPE Configuration", "newValue": cpe},
                            {"action": "Added", "type": "CWE", "newValue": "CWE-79"},
                        ],
                    ),
                    (
                        "2023-02-01T00:00:00",
                        [
                            {
                                "action": "Changed",
                                "type": "CWE",
                                "oldValue": "CWE-79",
                                "newValue": "CWE-89",
                            }
                        ],
                    ),
                ],
            )
        ),
        encoding="utf-8",
    )
    histories.joinpath(f"{CVE_EMPTY}.json").write_text(
        json.dumps(
            make_history(
                CVE_EMPTY,
                [
                    (
                        "2022-11-01T00:00:00Z",
                        [
                            {"action": "Added", "type": "CPE Configuration", "newValue": cpe},
                            {"action": "Added", "type": "CWE", "newValue": "CWE-79"},
                        ],
                    ),
                    (
                        "2022-12-01T00:00:00Z",
                        [
                            {"action": "Removed", "type": "CPE Configuration", "oldValue": cpe},
                            {"action": "Removed", "type": "CWE", "oldValue": "CWE-79"},
                        ],
                    ),
                ],
            )
        ),
        encoding="utf-8",
    )
    histories.joinpath(f"{CVE_FUTURE}.json").write_text(
        json.dumps(make_history(CVE_FUTURE, [])), encoding="utf-8"
    )
    manifest = tmp_path / "manifest.csv"
    sample = tmp_path / "sample.csv"
    rows = [
        (CVE_ACTIVE, "2022-09-01T00:00:00+00:00"),
        (CVE_EMPTY, "2022-10-01T00:00:00+00:00"),
        (CVE_FUTURE, "2024-03-01T00:00:00+00:00"),
    ]
    for path in (manifest, sample):
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(["cve_id", "published"])
            writer.writerows(rows)
    labels = tmp_path / "labels.csv"
    with labels.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            ["cve_id", "decision_time", "horizon_days", "outcome_status", "outcome_label"]
        )
        for cve_id in (CVE_ACTIVE, CVE_EMPTY, CVE_FUTURE):
            writer.writerow([cve_id, CUTOFF, 30, "negative_full_horizon_observed", "False"])
    return histories, sample, manifest, labels


def test_cutoff_export_preserves_missingness_cutoff_and_reused_labels(tmp_path):
    histories, sample, manifest, labels = _write_case_files(tmp_path)
    output = tmp_path / "result"
    run_historical_cutoff_export(
        history_dir=histories,
        sample_frame_path=sample,
        manifest_path=manifest,
        labels_path=labels,
        output_dir=output,
        cutoffs=(CUTOFF,),
    )
    cpe = pd.read_csv(output / "2023-01-01" / "cpe" / "outcomes.csv")
    active = cpe.set_index("cve_id").loc[CVE_ACTIVE]
    empty = cpe.set_index("cve_id").loc[CVE_EMPTY]
    future = cpe.set_index("cve_id").loc[CVE_FUTURE]
    assert active["cutoff_timestamp"] == CUTOFF
    assert active["feature_status"] == "available"
    assert active["relationships_json"] == '[{"product":"widget","vendor":"example"}]'
    assert active["history_events_total"] == 2
    assert active["history_events_by_cutoff"] == 1
    assert empty["feature_status"] == "known_no_active_relationships"
    assert empty["relationships_json"] == "[]"
    assert pd.isna(empty["pagerank"])
    assert future["feature_status"] == "unavailable"
    assert future["reason"] == "not_published_at_cutoff"
    assert pd.isna(future["pagerank"])
    assert future["history_events_by_cutoff"] == 0
    assert active["kev_outcome_status"] == "negative_full_horizon_observed"
    assert not active["kev_outcome_label"]
    features = pd.read_csv(output / "2023-01-01" / "cpe" / "features.csv")
    assert features["cve_id"].tolist() == [CVE_ACTIVE]
    metadata = json.loads((output / "2023-01-01" / "cpe" / "metadata.json").read_text())
    assert metadata["graph_nodes_by_type"]["cve"] == 1
    assert metadata["event_timestamps_prove_public_availability"] is False
    cwe = pd.read_csv(output / "2023-01-01" / "cwe" / "outcomes.csv").set_index("cve_id")
    assert cwe.loc[CVE_ACTIVE, "relationships_json"] == '[{"cwe_id":"CWE-79"}]'
    assert cwe.loc[CVE_EMPTY, "relationships_json"] == "[]"
    assert cwe.loc[CVE_ACTIVE, "history_events_by_cutoff"] == 1

    second = tmp_path / "result_second_run"
    run_historical_cutoff_export(
        history_dir=histories,
        sample_frame_path=sample,
        manifest_path=manifest,
        labels_path=labels,
        output_dir=second,
        cutoffs=(CUTOFF,),
    )
    for layer in ("cpe", "cwe"):
        for filename in ("features.csv", "outcomes.csv"):
            left = output / "2023-01-01" / layer / filename
            right = second / "2023-01-01" / layer / filename
            assert left.read_bytes() == right.read_bytes()


def test_cutoff_export_refuses_overwrite(tmp_path):
    histories, sample, manifest, labels = _write_case_files(tmp_path)
    output = tmp_path / "already_exists"
    output.mkdir()
    try:
        run_historical_cutoff_export(
            history_dir=histories,
            sample_frame_path=sample,
            manifest_path=manifest,
            labels_path=labels,
            output_dir=output,
            cutoffs=(CUTOFF,),
        )
    except FileExistsError:
        pass
    else:
        raise AssertionError("Existing output directory should be protected")
