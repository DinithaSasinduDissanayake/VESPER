"""Daily patch selection for Component D."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from math import ceil, floor, isfinite
from numbers import Integral, Real


@dataclass(frozen=True)
class PatchCandidate:
    """A ranked CVE with user-supplied patching inputs."""

    cve_id: str
    risk_score: float
    model_rank: int
    patch_hours: float | None
    business_criticality: int


@dataclass(frozen=True)
class PlannedCandidate:
    """A CVE's scheduling decision and the reason for that decision."""

    cve_id: str
    risk_score: float
    model_rank: int
    patch_hours: float | None
    business_criticality: int
    priority_value: float
    selected: bool
    reason: str


@dataclass(frozen=True)
class PatchPlan:
    """The complete one-day plan, including items deferred to later days."""

    patchers: int
    hours_per_patcher: float
    capacity_hours: float
    used_hours: float
    total_priority_value: float
    scheduled: tuple[PlannedCandidate, ...]
    deferred: tuple[PlannedCandidate, ...]


def build_patch_plan(
    candidates: Sequence[PatchCandidate], patchers: int, hours_per_patcher: float
) -> PatchPlan:
    """Choose the exact 0/1 knapsack set maximizing risk × business criticality.

    Effort is conservatively rounded up to 15-minute units. The returned
    selection therefore never exceeds the daily team capacity.
    """

    if isinstance(patchers, bool) or not isinstance(patchers, Integral) or patchers <= 0:
        raise ValueError("patchers must be a positive integer")
    if (
        isinstance(hours_per_patcher, bool)
        or not isinstance(hours_per_patcher, Real)
        or not isfinite(hours_per_patcher)
        or hours_per_patcher <= 0
    ):
        raise ValueError("hours_per_patcher must be a positive finite number")

    seen_cves: set[str] = set()
    for candidate in candidates:
        if not candidate.cve_id or candidate.cve_id in seen_cves:
            raise ValueError("candidates must have unique, non-empty CVE IDs")
        seen_cves.add(candidate.cve_id)
        if candidate.patch_hours is not None and (
            isinstance(candidate.patch_hours, bool)
            or not isinstance(candidate.patch_hours, Real)
            or not isfinite(candidate.patch_hours)
            or candidate.patch_hours <= 0
        ):
            raise ValueError("patch_hours must be positive and finite when provided")
        if (
            isinstance(candidate.risk_score, bool)
            or not isinstance(candidate.risk_score, Real)
            or not isfinite(candidate.risk_score)
            or not 0 <= candidate.risk_score <= 1
        ):
            raise ValueError("risk_score must be a finite number between 0 and 1")
        if (
            isinstance(candidate.business_criticality, bool)
            or not isinstance(candidate.business_criticality, Integral)
            or candidate.business_criticality < 1
        ):
            raise ValueError("business_criticality must be a positive integer")
        if isinstance(candidate.model_rank, bool) or not isinstance(candidate.model_rank, Integral):
            raise ValueError("model_rank must be an integer")

    capacity_quarters = floor(patchers * hours_per_patcher * 4 + 1e-9)
    if capacity_quarters < 1:
        raise ValueError("team capacity must be at least 0.25 hours")
    eligible = [candidate for candidate in candidates if candidate.patch_hours is not None]
    values = [candidate.risk_score * candidate.business_criticality for candidate in eligible]
    weights = [max(1, ceil(candidate.patch_hours * 4 - 1e-9)) for candidate in eligible]

    best = [0.0] * (capacity_quarters + 1)
    decisions: list[bytearray] = []
    for value, weight in zip(values, weights, strict=True):
        previous = best.copy()
        selected_at_capacity = bytearray(capacity_quarters + 1)
        for available in range(weight, capacity_quarters + 1):
            candidate_value = previous[available - weight] + value
            if candidate_value > previous[available] + 1e-12:
                best[available] = candidate_value
                selected_at_capacity[available] = 1
        decisions.append(selected_at_capacity)

    selected_ids: set[str] = set()
    remaining = capacity_quarters
    for index in range(len(eligible) - 1, -1, -1):
        if decisions[index][remaining]:
            selected_ids.add(eligible[index].cve_id)
            remaining -= weights[index]

    scheduled: list[PlannedCandidate] = []
    deferred: list[PlannedCandidate] = []
    for candidate in candidates:
        priority_value = candidate.risk_score * candidate.business_criticality
        selected = candidate.cve_id in selected_ids
        if candidate.patch_hours is None:
            reason = "Needs patch-time estimate"
        elif selected:
            reason = "Selected within daily capacity"
        elif max(1, ceil(candidate.patch_hours * 4 - 1e-9)) > capacity_quarters:
            reason = "Effort exceeds daily capacity"
        else:
            reason = "Not selected by the daily value-maximising plan"

        planned = PlannedCandidate(
            cve_id=candidate.cve_id,
            risk_score=candidate.risk_score,
            model_rank=candidate.model_rank,
            patch_hours=candidate.patch_hours,
            business_criticality=candidate.business_criticality,
            priority_value=priority_value,
            selected=selected,
            reason=reason,
        )
        (scheduled if selected else deferred).append(planned)

    scheduled.sort(key=lambda item: item.model_rank)
    deferred.sort(key=lambda item: item.model_rank)
    return PatchPlan(
        patchers=patchers,
        hours_per_patcher=hours_per_patcher,
        capacity_hours=capacity_quarters / 4,
        used_hours=sum(item.patch_hours or 0 for item in scheduled),
        total_priority_value=sum(item.priority_value for item in scheduled),
        scheduled=tuple(scheduled),
        deferred=tuple(deferred),
    )
