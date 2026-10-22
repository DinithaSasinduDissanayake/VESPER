"""Evidence isolation, fail-closed diagnosis, and streaming panel contract tests."""

import csv
import hashlib
import json
from datetime import UTC, date, datetime

import pytest

from vesper.components.c_graph import historical_panel as panel
from vesper.components.c_graph.historical import reconstruct_relationships
from vesper.contracts.score import Component, Score, ScoreKind, ScoreStatus

CVE = "CVE-2020-12345"
FUTURE = "CVE-2026-12345"
AT = datetime(2025, 1, 1, tzinfo=UTC)


def history(*changes):
    return {
        "format": "NVD_CVEHistory",
        "version": "2.0",
        "timestamp": "2026-10-17T00:00:00Z",
        "startIndex": 0,
        "totalResults": len(changes),
        "resultsPerPage": len(changes),
        "cveChanges": [{"change": change} for change in changes],
    }


def change(created="2020-01-02T00:00:00Z", *, product="one", action="Added"):
    return {
        "cveId": CVE,
        "cveChangeId": created + product,
        "created": created,
        "details": [
            {
                "type": "CPE Configuration",
                "action": action,
                "newValue": f"cpe:2.3:a:vendor:{product}:*:*:*:*:*:*:*:*",
            },
            {"type": "CWE", "action": "Added", "newValue": "CWE-79"},
        ],
    }


def write_history(directory, content):
    directory.mkdir(exist_ok=True)
    path = directory / f"{CVE}.json"
    path.write_text(json.dumps(content), encoding="utf-8")
    return path


@pytest.fixture
def inputs(tmp_path):
    manifest = tmp_path / "manifest.csv"
    manifest.write_text(
        f"cve_id,published\n{CVE},2020-01-01T00:00:00Z\n{FUTURE},2026-08-15T00:00:00Z\n",
        encoding="utf-8",
    )
    directory = tmp_path / "histories"
    write_history(directory, history(change()))
    return {"manifest": manifest, "history_dirs": [directory], "output_dir": tmp_path / "new"}


def test_confirmed_grid_and_boundaries():
    grid = panel.decision_grid()
    assert len(grid) == len(set(grid)) == 44
    assert grid[0] == datetime(2023, 1, 1, tzinfo=UTC)
    assert grid[-1] == datetime(2026, 9, 1, tzinfo=UTC)
    assert datetime(2024, 12, 1, tzinfo=UTC) not in grid
    assert all(value.day == 1 and value.hour == value.minute == value.second == 0 for value in grid)
    assert all(value.tzinfo == UTC for value in grid)


@pytest.mark.parametrize(
    "options",
    [
        {"start": date(2022, 1, 1)},
        {"end": date(2026, 10, 1)},
        {"exclude_date": date(2024, 11, 1)},
        {"cutoff_time": "12:00:00Z"},
        {"mode": "numeric"},
        {"horizon_days": 31},
        {"horizon_days": True},
    ],
)
def test_release_contract_cannot_be_weakened(inputs, options):
    with pytest.raises(ValueError):
        panel.export_historical_panel(**inputs, **options)
    assert not inputs["output_dir"].exists()


def test_streamed_panel_roundtrip_metadata_and_protected_outputs(inputs, tmp_path, monkeypatch):
    # Neither direct nor indirect graph/scoring calls are allowed.
    def forbidden(*args, **kwargs):
        pytest.fail("Abstention export attempted graph or numerical score computation")

    import networkx as nx

    from vesper.components.c_graph import graph, historical, scoring, structural_disagreement

    monkeypatch.setattr(nx, "pagerank", forbidden)
    monkeypatch.setattr(graph, "build_graph", forbidden)
    monkeypatch.setattr(historical, "build_multi_cve_historical_graph", forbidden)
    monkeypatch.setattr(scoring, "calculate_graph_features", forbidden)
    monkeypatch.setattr(structural_disagreement, "percentile", forbidden)
    monkeypatch.setattr(structural_disagreement, "build_real_scores", forbidden)
    protected = tmp_path / "c_graph_scores.csv"
    protected.write_bytes(b"frozen current output\n")
    protected_hash = panel.sha256(protected)
    metadata = panel.export_historical_panel(**inputs)
    output = inputs["output_dir"] / "c_graph_historical_scores.csv"
    with output.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        assert reader.fieldnames == [
            "cve_id",
            "component",
            "decision_time",
            "horizon_days",
            "score",
            "score_kind",
            "status",
            "reason",
            "model_version",
            "trained_through",
            "snapshot_date",
        ]
        rows = list(reader)
    assert len(rows) == 2 * 44 == metadata["actual_panel_row_count"]
    assert len({(row["cve_id"], row["decision_time"]) for row in rows}) == len(rows)
    for row in rows:
        assert row["score"] == row["trained_through"] == ""
        assert row["status"] == "abstained" and row["reason"]
        assert row["component"] == "c_graph" and row["score_kind"] == "ranking_score"
        assert row["horizon_days"] == "30"
        Score(
            cve_id=row["cve_id"],
            component=Component.C_GRAPH,
            decision_time=datetime.fromisoformat(row["decision_time"]),
            horizon_days=30,
            score=None,
            score_kind=ScoreKind.RANKING_SCORE,
            status=ScoreStatus.ABSTAINED,
            reason=row["reason"],
            model_version=row["model_version"],
            trained_through=None,
            snapshot_date=date.fromisoformat(row["snapshot_date"]),
        )
    early = next(row for row in rows if row["cve_id"] == FUTURE)
    assert early["reason"] == "cve_not_published_at_decision_time"
    assert rows[-1]["reason"] == "historical_relationship_history_missing"
    assert metadata["scientifically_supported_dates"] == []
    assert metadata["percentile_population"] == metadata["pagerank_population"] == 0
    assert metadata["graph_computation"] == metadata["score_computation"] == "not_performed"
    assert metadata["unique_composite_keys_validated"] is True
    assert metadata["output_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    saved = json.loads(output.with_suffix(".csv.metadata.json").read_text())
    assert saved == metadata
    assert panel.sha256(protected) == protected_hash
    assert metadata["manifest"]["sha256"] == panel.sha256(inputs["manifest"])
    diag = metadata["per_cutoff"][0]["history_diagnostics_by_cve"][CVE]
    assert diag["feature_eligible"]
    assert diag["reasons"] == [panel.PUBLIC_REASON, panel.CONTEXT_REASON]


@pytest.mark.parametrize(
    "kind,expected",
    [
        ("invalid", "invalid_history_response"),
        ("empty", "valid_empty_history_response"),
        ("cpe_missing", "no_interpretable_cpe_events_by_cutoff"),
        ("cwe_missing", "no_interpretable_cwe_events_by_cutoff"),
        ("initial", "uncertain_initial_cpe_state"),
        ("affected", "github_reference_unrecoverable"),
    ],
)
def test_specific_diagnoses_and_concurrent_reasons(tmp_path, kind, expected):
    event = change()
    content = history(event)
    if kind == "empty":
        content = history()
    elif kind == "cpe_missing":
        event["details"] = event["details"][1:]
    elif kind == "cwe_missing":
        event["details"] = event["details"][:1]
    elif kind == "initial":
        event["details"][0]["action"] = "Changed"
        event["details"][0]["oldValue"] = event["details"][0]["newValue"]
    elif kind == "affected":
        event["details"].append(
            {
                "type": "Affected",
                "action": "Added",
                "newValue": '<a href="https://github.com/CVEProject/cvelistV5">record</a>',
            }
        )
    path = write_history(tmp_path, content)
    if kind == "invalid":
        path.write_text("{broken", encoding="utf-8")
    sources, _ = panel.discover_histories([tmp_path])
    diagnostic = panel.assess_history(sources[CVE], AT, CVE)
    assert diagnostic["reasons"][0] == expected
    assert panel.PUBLIC_REASON in diagnostic["reasons"]
    assert panel.CONTEXT_REASON in diagnostic["reasons"]
    assert not diagnostic["feature_eligible"]


def test_duplicate_copies_conflict_only_when_material_at_cutoff(tmp_path):
    first = tmp_path / "a"
    second = tmp_path / "b"
    third = tmp_path / "c"
    write_history(first, history(change()))
    later = change("2026-01-02T00:00:00Z", product="two")
    write_history(second, history(change(), later))
    write_history(third, history(change()))
    sources, inventory = panel.discover_histories([first, second, third, first])
    assert inventory["file_count"] == 3
    assert inventory["unique_historical_cve_count"] == 1
    assert inventory["duplicate_extra_copies"] == 2
    before = panel.assess_history(sources[CVE], AT, CVE)
    assert before["feature_eligible"]
    after = panel.assess_history(sources[CVE], datetime(2026, 2, 1, tzinfo=UTC), CVE)
    assert after["reasons"][0] == "historical_source_state_conflict"
    assert not after["feature_eligible"]


def test_invalid_duplicate_fails_closed(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    write_history(a, history(change()))
    path = write_history(b, history(change()))
    path.write_text("null", encoding="utf-8")
    sources, _ = panel.discover_histories([a, b])
    result = panel.assess_history(sources[CVE], AT, CVE)
    assert result["reasons"][0] == "invalid_history_response"
    assert not result["feature_eligible"]


def test_reconstruction_failure_is_explicit(tmp_path, monkeypatch):
    write_history(tmp_path, history(change()))
    sources, _ = panel.discover_histories([tmp_path])

    def fail(*args, **kwargs):
        raise ValueError("unsupported state")

    monkeypatch.setattr(panel, "reconstruct_relationships", fail)
    result = panel.assess_history(sources[CVE], AT, CVE)
    assert result["reasons"][0] == "reconstruction_failed"
    assert not result["reconstruction_succeeded"]


def test_later_events_do_not_repair_or_change_earlier_state():
    base = history(change())
    later = change("2026-06-17T00:00:00Z")
    later["details"] = [
        {
            "type": "Affected",
            "action": "Added",
            "newValue": "https://github.com/CVEProject/cvelistV5/main/record.json",
        }
    ]
    extended = history(change(), later)
    assert reconstruct_relationships(base, AT, CVE) == reconstruct_relationships(extended, AT, CVE)
    result = reconstruct_relationships(extended, datetime(2026, 7, 1, tzinfo=UTC), CVE)
    assert "github_reference_unrecoverable" in result.exclusion_reasons
    assert not result.feature_eligible


def test_graph_context_gate_has_specific_reason():
    assert panel.scientific_reasons(public_availability_verified=True) == (panel.CONTEXT_REASON,)


def test_refuses_existing_destination_and_invalid_manifest(inputs):
    inputs["output_dir"].mkdir()
    with pytest.raises(FileExistsError):
        panel.export_historical_panel(**inputs)
    inputs["output_dir"].rmdir()
    inputs["manifest"].write_text(f"cve_id,published\n{CVE},not-a-date\n")
    with pytest.raises(ValueError, match="publication timestamp"):
        panel.export_historical_panel(**inputs)
    assert not inputs["output_dir"].exists()


def test_stream_validation_detects_duplicate_key(inputs):
    panel.export_historical_panel(**inputs)
    path = inputs["output_dir"] / "c_graph_historical_scores.csv"
    lines = path.read_text().splitlines()
    lines[2] = lines[1]
    path.write_text("\n".join(lines) + "\n")
    population = panel.load_research_manifest(inputs["manifest"])
    with pytest.raises(ValueError, match="composite key"):
        panel.validate_panel(path, population, panel.decision_grid())


@pytest.mark.parametrize("fraction,future", [("", False), (".000001", True)])
def test_exact_midnight_publication_boundary(inputs, fraction, future):
    inputs["manifest"].write_text(
        f"cve_id,published\n{CVE},2023-01-01T00:00:00{fraction}Z\n", encoding="utf-8"
    )
    metadata = panel.export_historical_panel(**inputs)
    first = metadata["per_cutoff"][0]
    assert first["not_yet_published_cve_count"] == int(future)
    assert first["histories_present_published"] == int(not future)
    assert first["primary_reason_counts"] == {
        "cve_not_published_at_decision_time" if future else panel.PUBLIC_REASON: 1
    }


def test_source_mutation_fails_export_and_removes_incomplete_artifacts(inputs, monkeypatch):
    validate = panel.validate_panel

    def mutate_after_validation(*args):
        count = validate(*args)
        path = inputs["history_dirs"][0] / f"{CVE}.json"
        path.write_bytes(path.read_bytes() + b" ")
        return count

    monkeypatch.setattr(panel, "validate_panel", mutate_after_validation)
    with pytest.raises(ValueError, match="Source inputs changed"):
        panel.export_historical_panel(**inputs)
    assert not inputs["output_dir"].exists()
