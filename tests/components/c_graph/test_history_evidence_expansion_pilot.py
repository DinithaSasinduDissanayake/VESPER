import csv
import importlib.util
import json
from pathlib import Path

import pandas as pd

_script = (
    Path(__file__).resolve().parents[3] / "scripts" / "analyze_c_graph_history_expansion_pilot.py"
)
_spec = importlib.util.spec_from_file_location("history_evidence_expansion_pilot", _script)
_analysis = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_analysis)
run_pilot_replay = _analysis.run_pilot_replay

CVE_ACTIVE = "CVE-2022-11111"
CVE_FUTURE = "CVE-2024-33333"
CUTOFF = "2023-01-01T00:00:00+00:00"


def _history(cve_id, events):
    changes = [
        {
            "change": {
                "cveId": cve_id,
                "cveChangeId": f"event-{index}",
                "created": timestamp,
                "eventName": "CVE Modified",
                "details": details,
            }
        }
        for index, (timestamp, details) in enumerate(events)
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


def _inputs(tmp_path):
    histories = tmp_path / "histories"
    histories.mkdir()
    cpe = "cpe:2.3:a:example:widget:*:*:*:*:*:*:*:*"
    for cve_id, payload in (
        (
            CVE_ACTIVE,
            _history(
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
                        "2023-02-01T00:00:00Z",
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
            ),
        ),
        (CVE_FUTURE, _history(CVE_FUTURE, [])),
    ):
        (histories / f"{cve_id}.json").write_text(json.dumps(payload), encoding="utf-8")

    manifest = tmp_path / "manifest.csv"
    rows = [
        {"cve_id": CVE_ACTIVE, "published": "2022-09-01T00:00:00+00:00"},
        {"cve_id": CVE_FUTURE, "published": "2024-03-01T00:00:00+00:00"},
    ]
    with manifest.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["cve_id", "published"])
        writer.writeheader()
        writer.writerows(rows)

    labels = tmp_path / "labels.csv"
    with labels.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            ["cve_id", "decision_time", "horizon_days", "outcome_status", "outcome_label"]
        )
        for cve_id, label in ((CVE_ACTIVE, "False"), (CVE_FUTURE, "True")):
            writer.writerow([cve_id, CUTOFF, 30, "labeled", label])

    selection = tmp_path / "selection.csv"
    selection.write_text(manifest.read_text(encoding="utf-8"), encoding="utf-8")
    return histories, selection, manifest, labels


def test_pilot_replay_preserves_cutoffs_unavailable_values_and_determinism(tmp_path):
    histories, selection, manifest, labels = _inputs(tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"
    for output in (first, second):
        run_pilot_replay(
            history_dir=histories,
            selection_path=selection,
            manifest_path=manifest,
            labels_path=labels,
            output_dir=output,
            cutoffs=(CUTOFF,),
        )

    outcomes = pd.read_csv(first / "cutoff_layer_outcomes.csv").set_index(["cve_id", "layer"])
    active = outcomes.loc[(CVE_ACTIVE, "cwe")]
    future = outcomes.loc[(CVE_FUTURE, "cpe")]
    assert active["feature_status"] == "available"
    assert active["relationships_json"] == '[{"cwe_id":"CWE-79"}]'
    assert active["history_events_total"] == 2
    assert active["history_events_by_cutoff"] == 1
    assert active["history_events_after_cutoff"] == 1
    assert future["feature_status"] == "unavailable"
    assert future["reason"] == "not_published_at_cutoff"
    assert pd.isna(future["pagerank"])
    assert pd.isna(future["degree_feature"])
    summary = pd.read_csv(first / "cutoff_summary.csv")
    assert (summary["kev_positive_labels_in_sample"] == 0).all()
    metadata = json.loads((first / "run_metadata.json").read_text(encoding="utf-8"))
    assert (
        metadata["cutoff_results"][CUTOFF]["cpe"]["analysis_type"]
        == "exploratory_offline_history_evidence_expansion_layer_analysis"
    )

    for name in (
        "cutoff_layer_outcomes.csv",
        "cutoff_features.csv",
        "cutoff_summary.csv",
        "event_details.csv",
    ):
        assert (first / name).read_bytes() == (second / name).read_bytes()
