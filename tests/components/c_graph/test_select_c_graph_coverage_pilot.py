"""Offline tests for the Stage 5B probability-sample selector."""

from datetime import UTC, datetime

import pytest
from scripts import select_c_graph_coverage_pilot as selector


def test_publication_strata_follow_manifest_dates_at_format_boundaries():
    assert selector.stratum_for(datetime(2026, 6, 16, 23, 59, tzinfo=UTC)) == selector.STRATA[10]
    assert selector.stratum_for(datetime(2026, 6, 17, tzinfo=UTC)) == selector.STRATA[11]
    assert selector.stratum_for(datetime(2026, 8, 25, 23, 59, tzinfo=UTC)) == selector.STRATA[11]
    assert selector.stratum_for(datetime(2026, 8, 26, tzinfo=UTC)) == selector.STRATA[12]
    with pytest.raises(ValueError, match="outside research window"):
        selector.stratum_for(datetime(2026, 10, 15, tzinfo=UTC))


def test_stratified_selection_is_reproducible_and_records_design_weights():
    rows = []
    for stratum_index, stratum in enumerate(selector.STRATA):
        year = 2016 + stratum_index if stratum_index < 10 else 2026
        for member in range(12):
            rows.append(
                {
                    "cve_id": f"CVE-{year}-{stratum_index * 100 + member + 1000}",
                    "published": f"{year}-01-01T00:00:00+00:00",
                    "stratum": stratum,
                }
            )

    first, counts = selector.select_sample(rows, seed=153, sample_per_stratum=3)
    second, _ = selector.select_sample(rows, seed=153, sample_per_stratum=3)

    assert [row["cve_id"] for row in first] == [row["cve_id"] for row in second]
    assert len(first) == 39
    assert counts == dict.fromkeys(selector.STRATA, 12)
    for stratum in selector.STRATA:
        members = [row for row in first if row["stratum"] == stratum]
        assert len(members) == 3
        assert {row["inclusion_probability"] for row in members} == {0.25}
        assert {row["analysis_weight"] for row in members} == {4.0}


def test_selector_refuses_existing_output_directory(tmp_path):
    destination = tmp_path / "already_exists"
    destination.mkdir()

    with pytest.raises(FileExistsError, match="already exists"):
        selector.write_sample(tmp_path / "manifest.csv", tmp_path / "histories", destination, 7)
