"""FastAPI endpoints for Component D patch planning."""

from __future__ import annotations

import csv
import math
import os
from dataclasses import asdict
from datetime import date, timedelta
from pathlib import Path
from typing import Annotated, Literal

import pandas as pd
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from vesper.components.d_fusion.knapsack import (
    PatchCandidate,
    build_patch_plan,
)
from vesper.config import load_settings

router = APIRouter(prefix="/api/d-fusion", tags=["Component D"])
CveId = Annotated[str, StringConstraints(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")]
MAX_DYNAMIC_PROGRAMMING_STATES = 25_000_000


class CandidateOverride(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: CveId
    patch_hours: float | None = Field(default=None, gt=0, le=1000)
    business_criticality: int | None = Field(default=None, ge=1, le=3)


class PlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patchers: int = Field(ge=1, le=100)
    hours_per_patcher: float = Field(ge=0.25, le=24, multiple_of=0.25)
    planning_period: Literal["day", "week", "month"] = "day"
    start_date: date | None = None
    overrides: list[CandidateOverride] = Field(default_factory=list, max_length=250_000)

    @model_validator(mode="after")
    def require_unique_override_cves(self) -> PlanRequest:
        identifiers = [item.cve_id.upper() for item in self.overrides]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Each CVE ID may have only one planning override")
        return self


class ScheduleItem(BaseModel):
    cve_id: str
    risk_score: float
    model_rank: int
    patch_hours: float | None
    business_criticality: int
    priority_value: float
    selected: bool
    reason: str
    planned_date: str | None = None


class DailySummary(BaseModel):
    date: str
    selected_count: int
    used_hours: float
    capacity_hours: float


class PlanResponse(BaseModel):
    ranking_file: str
    ranking_model: str | None
    model_selection_status: str | None
    synthetic: bool
    total_cves: int
    patchers: int
    hours_per_patcher: float
    planning_period: str
    start_date: str
    workdays: int
    daily_capacity_hours: float
    capacity_hours: float
    used_hours: float
    total_priority_value: float
    scheduled: list[ScheduleItem]
    deferred: list[ScheduleItem]
    daily_summaries: list[DailySummary]


class RankingCandidate(BaseModel):
    cve_id: CveId
    risk_score: float = Field(ge=0, le=1)
    model_rank: int = Field(ge=1)
    patch_hours: float | None = Field(default=None, gt=0, le=1000)
    patch_hours_method: str | None = None
    patch_severity_tier: str | None = None
    business_criticality: int = Field(default=1, ge=1, le=3)
    fusion_score: float | None = Field(default=None, ge=0, le=1)
    score_a: float | None = None
    score_b: float | None = None
    score_c: float | None = None
    cvss_base_score: float | None = None
    epss_score: float | None = None
    status_a: str | None = None
    status_b: str | None = None
    status_c: str | None = None
    reason_a: str | None = None
    reason_b: str | None = None
    reason_c: str | None = None
    signals_used: int | None = None
    signal_coverage: float | None = None
    snapshot_date_a: str | None = None
    snapshot_date_b: str | None = None
    snapshot_date_c: str | None = None
    baseline_snapshot_date: str | None = None
    epss_date: str | None = None
    data_as_of: str | None = None
    ranking_model: str | None = None
    model_selection_status: str | None = None


class RankingResponse(BaseModel):
    ranking_file: str
    ranking_model: str | None
    model_selection_status: str | None
    synthetic: bool
    count: int
    vulnerabilities: list[RankingCandidate]


class VulnerabilityFacts(BaseModel):
    cve_id: CveId
    description: str
    published_at: str
    last_modified_at: str
    cvss_base_score: float | None
    cvss_version: str | None
    cvss_vector: str | None
    cwe_ids: list[str]
    affected: list[tuple[str, str]]
    nvd_status: str
    snapshot_date: str


def _ranking_path() -> Path:
    settings = load_settings()
    configured_path = os.getenv("VESPER_RANKING_CSV")
    if not configured_path:
        return (
            settings.outputs / "d_fusion" / "current_provisional" / "ranked_current_five_signal.csv"
        )
    path = Path(configured_path)
    return path if path.is_absolute() else settings.project_root / path


def _optional_float(row: dict[str, str], column: str) -> float | None:
    value = row.get(column, "")
    if not value:
        return None
    parsed = float(value)
    return parsed if math.isfinite(parsed) else None


def _load_ranking() -> RankingResponse:
    path = _ranking_path()
    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail=(
                "Component D ranking file not found. Generate the ranking first or "
                "set VESPER_RANKING_CSV to the ranking CSV path."
            ),
        )

    try:
        with path.open(encoding="utf-8-sig", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            if not reader.fieldnames:
                raise ValueError("CSV is empty or has no header")
            headers = {header.strip().lower() for header in reader.fieldnames}
            if "cve_id" not in headers or not ({"risk_score", "fusion_score"} & headers):
                raise ValueError("CSV must include cve_id and risk_score or fusion_score")

            rows: list[RankingCandidate] = []
            seen: set[str] = set()
            first_row: dict[str, str] = {}
            synthetic = False
            for row_number, raw_row in enumerate(reader, start=2):
                row = {
                    key.strip().lower(): (value or "").strip()
                    for key, value in raw_row.items()
                    if key
                }
                if not first_row:
                    first_row = row
                cve_id = row.get("cve_id", "").upper()
                if not cve_id:
                    raise ValueError(f"Missing cve_id at CSV row {row_number}")
                if cve_id in seen:
                    raise ValueError(f"Duplicate CVE ID {cve_id} at CSV row {row_number}")
                seen.add(cve_id)
                score_text = row.get("risk_score") or row.get("fusion_score", "")
                score = float(score_text)
                rank_text = row.get("risk_rank") or row.get("model_rank", "")
                model_rank = int(rank_text) if rank_text else len(rows) + 1
                criticality_text = row.get("business_criticality", "")
                rows.append(
                    RankingCandidate(
                        cve_id=cve_id,
                        risk_score=score,
                        model_rank=model_rank,
                        patch_hours=_optional_float(row, "patch_hours"),
                        patch_hours_method=row.get("patch_hours_method") or None,
                        patch_severity_tier=row.get("patch_severity_tier") or None,
                        business_criticality=int(criticality_text) if criticality_text else 1,
                        fusion_score=_optional_float(row, "fusion_score"),
                        score_a=_optional_float(row, "score_a"),
                        score_b=_optional_float(row, "score_b"),
                        score_c=_optional_float(row, "score_c"),
                        cvss_base_score=_optional_float(row, "cvss_base_score"),
                        epss_score=_optional_float(row, "epss_score"),
                        status_a=row.get("status_a") or None,
                        status_b=row.get("status_b") or None,
                        status_c=row.get("status_c") or None,
                        reason_a=row.get("reason_a") or None,
                        reason_b=row.get("reason_b") or None,
                        reason_c=row.get("reason_c") or None,
                        signals_used=int(row["signals_used"]) if row.get("signals_used") else None,
                        signal_coverage=_optional_float(row, "signal_coverage"),
                        snapshot_date_a=row.get("snapshot_date_a") or None,
                        snapshot_date_b=row.get("snapshot_date_b") or None,
                        snapshot_date_c=row.get("snapshot_date_c") or None,
                        baseline_snapshot_date=row.get("baseline_snapshot_date") or None,
                        epss_date=row.get("epss_date") or None,
                        data_as_of=row.get("data_as_of") or None,
                        ranking_model=row.get("ranking_model") or None,
                        model_selection_status=row.get("model_selection_status") or None,
                    )
                )
                synthetic |= row.get("data_origin", "").lower() == "synthetic"
                synthetic |= any(
                    key.startswith("model_version_") and "synthetic" in value.lower()
                    for key, value in row.items()
                )
    except (OSError, ValueError, csv.Error, ValidationError) as error:
        raise HTTPException(
            status_code=422, detail=f"Could not read ranking CSV: {error}"
        ) from error

    if not rows:
        raise HTTPException(status_code=422, detail="Ranking CSV contains no vulnerability rows")
    return RankingResponse(
        ranking_file=path.name,
        ranking_model=first_row.get("ranking_model") or None,
        model_selection_status=first_row.get("model_selection_status") or None,
        synthetic=synthetic,
        count=len(rows),
        vulnerabilities=rows,
    )


@router.get("/ranking", response_model=RankingResponse)
def get_ranking() -> RankingResponse:
    """Load the configured Component D ranking CSV from the backend."""

    return _load_ranking()


@router.get("/ranking.csv", response_class=FileResponse)
def download_ranking_csv() -> FileResponse:
    """Download the exact ranking CSV configured for the Sprint Planner."""

    path = _ranking_path()
    if not path.is_file():
        raise HTTPException(status_code=404, detail="The configured ranking CSV is unavailable")
    return FileResponse(path, media_type="text/csv", filename=path.name)


def _as_list(value: object) -> list:
    """Convert parquet list/array cells to ordinary Python lists."""

    if value is None:
        return []
    if hasattr(value, "tolist"):
        value = value.tolist()
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _as_optional_float(value: object) -> float | None:
    if value is None or pd.isna(value):
        return None
    parsed = float(value)
    return parsed if math.isfinite(parsed) else None


def _as_iso(value: object) -> str:
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


@router.get("/cves/{cve_id}", response_model=VulnerabilityFacts)
def get_cve_detail(cve_id: CveId) -> VulnerabilityFacts:
    """Return locally ingested NVD facts for one CVE."""

    normalized_id = cve_id.upper()
    facts_path = load_settings().data_processed / "vulnerabilities.parquet"
    if not facts_path.is_file():
        raise HTTPException(
            status_code=503,
            detail="Local NVD vulnerability details are unavailable; ingest NVD data first.",
        )
    try:
        frame = pd.read_parquet(
            facts_path,
            columns=[
                "cve_id",
                "description",
                "published_at",
                "last_modified_at",
                "cvss_base_score",
                "cvss_version",
                "cvss_vector",
                "cwe_ids",
                "affected",
                "nvd_status",
                "snapshot_date",
            ],
            filters=[("cve_id", "==", normalized_id)],
        )
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=f"Could not read local NVD vulnerability details: {error}",
        ) from error
    if frame.empty:
        raise HTTPException(
            status_code=404,
            detail="NVD details for this CVE are not present in the local vulnerability snapshot.",
        )

    row = frame.iloc[0]
    return VulnerabilityFacts(
        cve_id=normalized_id,
        description=str(row["description"] or ""),
        published_at=_as_iso(row["published_at"]),
        last_modified_at=_as_iso(row["last_modified_at"]),
        cvss_base_score=_as_optional_float(row["cvss_base_score"]),
        cvss_version=str(row["cvss_version"]) if pd.notna(row["cvss_version"]) else None,
        cvss_vector=str(row["cvss_vector"]) if pd.notna(row["cvss_vector"]) else None,
        cwe_ids=[str(value) for value in _as_list(row["cwe_ids"])],
        affected=[
            (str(pair[0]), str(pair[1]))
            for pair in map(_as_list, _as_list(row["affected"]))
            if len(pair) >= 2
        ],
        nvd_status=str(row["nvd_status"] or ""),
        snapshot_date=_as_iso(row["snapshot_date"]),
    )


@router.post("/knapsack", response_model=PlanResponse)
def create_patch_plan(request: PlanRequest) -> PlanResponse:
    """Optimize one day or a rolling 5/22-workday plan from the backend ranking."""

    ranking = _load_ranking()
    overrides = {item.cve_id.upper(): item for item in request.overrides}
    ranking_ids = {item.cve_id for item in ranking.vulnerabilities}
    unknown_ids = set(overrides) - ranking_ids
    if unknown_ids:
        raise HTTPException(
            status_code=422,
            detail=(
                "Planning overrides contain CVEs absent from the ranking: "
                f"{sorted(unknown_ids)[:5]}"
            ),
        )
    candidates = [
        PatchCandidate(
            cve_id=item.cve_id,
            risk_score=item.risk_score,
            model_rank=item.model_rank,
            patch_hours=(
                overrides[item.cve_id].patch_hours
                if item.cve_id in overrides
                and "patch_hours" in overrides[item.cve_id].model_fields_set
                else item.patch_hours
            ),
            business_criticality=(
                overrides[item.cve_id].business_criticality
                if item.cve_id in overrides
                and overrides[item.cve_id].business_criticality is not None
                else item.business_criticality
            ),
        )
        for item in ranking.vulnerabilities
    ]
    capacity_quarters = int(request.patchers * request.hours_per_patcher * 4)
    eligible_count = sum(item.patch_hours is not None for item in candidates)
    if eligible_count * capacity_quarters > MAX_DYNAMIC_PROGRAMMING_STATES:
        raise HTTPException(
            status_code=422,
            detail=(
                "This ranking and capacity exceed the exact planner's processing limit. "
                "Reduce the team capacity or configure a smaller ranked candidate list."
            ),
        )

    workday_count = {"day": 1, "week": 5, "month": 22}[request.planning_period]
    first_date = request.start_date or date.today()
    planning_dates: list[date] = []
    cursor = first_date
    while len(planning_dates) < workday_count:
        if cursor.weekday() < 5:
            planning_dates.append(cursor)
        cursor += timedelta(days=1)

    remaining = list(candidates)
    scheduled_items: list[ScheduleItem] = []
    daily_summaries: list[DailySummary] = []
    for planned_date in planning_dates:
        if not any(item.patch_hours is not None for item in remaining):
            break
        daily_plan = build_patch_plan(
            remaining,
            patchers=request.patchers,
            hours_per_patcher=request.hours_per_patcher,
        )
        selected_ids = {item.cve_id for item in daily_plan.scheduled}
        if not selected_ids:
            break
        for item in daily_plan.scheduled:
            planned_row = {**asdict(item), "planned_date": planned_date.isoformat()}
            scheduled_items.append(ScheduleItem.model_validate(planned_row))
        daily_summaries.append(
            DailySummary(
                date=planned_date.isoformat(),
                selected_count=len(daily_plan.scheduled),
                used_hours=daily_plan.used_hours,
                capacity_hours=daily_plan.capacity_hours,
            )
        )
        remaining = [item for item in remaining if item.cve_id not in selected_ids]

    deferred_items: list[ScheduleItem] = []
    for item in remaining:
        if item.patch_hours is None:
            reason = "Needs patch-time estimate"
        elif math.ceil(item.patch_hours * 4 - 1e-9) > capacity_quarters:
            reason = "Effort exceeds one workday capacity"
        else:
            reason = "Not selected within the planning horizon"
        deferred_items.append(
            ScheduleItem(
                cve_id=item.cve_id,
                risk_score=item.risk_score,
                model_rank=item.model_rank,
                patch_hours=item.patch_hours,
                business_criticality=item.business_criticality,
                priority_value=item.risk_score * item.business_criticality,
                selected=False,
                reason=reason,
            )
        )
    scheduled_items.sort(key=lambda item: (item.planned_date or "", item.model_rank))
    deferred_items.sort(key=lambda item: item.model_rank)
    return PlanResponse(
        ranking_file=ranking.ranking_file,
        ranking_model=ranking.ranking_model,
        model_selection_status=ranking.model_selection_status,
        synthetic=ranking.synthetic,
        total_cves=ranking.count,
        patchers=request.patchers,
        hours_per_patcher=request.hours_per_patcher,
        planning_period=request.planning_period,
        start_date=planning_dates[0].isoformat(),
        workdays=workday_count,
        daily_capacity_hours=capacity_quarters / 4,
        capacity_hours=(capacity_quarters / 4) * workday_count,
        used_hours=sum(item.patch_hours or 0 for item in scheduled_items),
        total_priority_value=sum(item.priority_value for item in scheduled_items),
        scheduled=scheduled_items,
        deferred=deferred_items,
        daily_summaries=daily_summaries,
    )
