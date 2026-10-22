import math

import pytest

from vesper.components.d_fusion.knapsack import PatchCandidate, build_patch_plan


def _candidate(cve_id, risk_score, patch_hours):
    return PatchCandidate(
        cve_id=cve_id,
        risk_score=risk_score,
        model_rank=1,
        patch_hours=patch_hours,
        business_criticality=1,
    )


def test_build_patch_plan_selects_optimal_combination():
    candidates = [
        _candidate("CVE-2024-0001", 0.9, 2.0),
        _candidate("CVE-2024-0002", 0.6, 1.0),
        _candidate("CVE-2024-0003", 0.6, 1.0),
    ]

    plan = build_patch_plan(candidates, patchers=1, hours_per_patcher=2.0)

    assert {item.cve_id for item in plan.scheduled} == {
        "CVE-2024-0002",
        "CVE-2024-0003",
    }
    assert plan.total_priority_value == pytest.approx(1.2)


def test_build_patch_plan_never_exceeds_team_capacity():
    candidates = [
        _candidate("CVE-2024-0001", 0.9, 1.1),
        _candidate("CVE-2024-0002", 0.8, 1.2),
        _candidate("CVE-2024-0003", 0.7, 0.5),
    ]

    plan = build_patch_plan(candidates, patchers=2, hours_per_patcher=1.0)

    assert plan.used_hours <= plan.capacity_hours
    assert plan.capacity_hours <= 2.0


@pytest.mark.parametrize("patch_hours", [-1.0, 0.0, math.nan, math.inf])
def test_build_patch_plan_rejects_invalid_patch_hours(patch_hours):
    with pytest.raises(ValueError, match="patch_hours must be positive and finite"):
        build_patch_plan(
            [_candidate("CVE-2024-0001", 0.9, patch_hours)],
            patchers=1,
            hours_per_patcher=1.0,
        )


@pytest.mark.parametrize("patchers", [0, -1, 1.5, True])
def test_build_patch_plan_rejects_invalid_patcher_count(patchers):
    with pytest.raises(ValueError, match="patchers must be a positive integer"):
        build_patch_plan([], patchers=patchers, hours_per_patcher=1.0)


@pytest.mark.parametrize("hours", [0.0, -1.0, math.nan, math.inf])
def test_build_patch_plan_rejects_invalid_hours_per_patcher(hours):
    with pytest.raises(ValueError, match="hours_per_patcher must be a positive finite number"):
        build_patch_plan([], patchers=1, hours_per_patcher=hours)


def test_positive_sub_quarter_patch_effort_is_not_treated_as_free():
    candidate = _candidate("CVE-2024-0001", 0.9, 1e-12)

    plan = build_patch_plan([candidate], patchers=1, hours_per_patcher=0.25)

    assert len(plan.scheduled) == 1
    assert plan.capacity_hours == 0.25
