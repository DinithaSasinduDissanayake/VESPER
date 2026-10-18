"""FastAPI endpoints for Component D patch planning."""

from __future__ import annotations

import csv
import os
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException
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
    business_criticality: int = Field(default=1, ge=1, le=3)


class PlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    patchers: int = Field(ge=1, le=100)
    hours_per_patcher: float = Field(ge=0.25, le=24, multiple_of=0.25)
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


class PlanResponse(BaseModel):
    ranking_file: str
    ranking_model: str | None
    model_selection_status: str | None
    synthetic: bool
    total_cves: int
    patchers: int
    hours_per_patcher: float
    capacity_hours: float
    used_hours: float
    total_priority_value: float
    scheduled: list[ScheduleItem]
    deferred: list[ScheduleItem]


class RankingCandidate(BaseModel):
    cve_id: CveId
    risk_score: float = Field(ge=0, le=1)
    model_rank: int = Field(ge=1)
    patch_hours: float | None = Field(default=None, gt=0, le=1000)
    business_criticality: int = Field(default=1, ge=1, le=3)


class RankingResponse(BaseModel):
    ranking_file: str
    ranking_model: str | None
    model_selection_status: str | None
    synthetic: bool
    count: int
    vulnerabilities: list[RankingCandidate]


def _ranking_path() -> Path:
    settings = load_settings()
    configured_path = os.getenv("VESPER_RANKING_CSV")
    if not configured_path:
        return settings.outputs / "d_fusion" / "ranked_vulnerabilities.csv"
    path = Path(configured_path)
    return path if path.is_absolute() else settings.project_root / path


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
                effort_text = row.get("patch_hours", "")
                criticality_text = row.get("business_criticality", "")
                rows.append(
                    RankingCandidate(
                        cve_id=cve_id,
                        risk_score=score,
                        model_rank=model_rank,
                        patch_hours=float(effort_text) if effort_text else None,
                        business_criticality=int(criticality_text) if criticality_text else 1,
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


@router.post("/knapsack", response_model=PlanResponse)
def create_patch_plan(request: PlanRequest) -> PlanResponse:
    """Validate the ranking and return today's selected and deferred CVEs."""

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
                else item.patch_hours
            ),
            business_criticality=(
                overrides[item.cve_id].business_criticality
                if item.cve_id in overrides
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

    plan = build_patch_plan(
        candidates,
        patchers=request.patchers,
        hours_per_patcher=request.hours_per_patcher,
    )
    return PlanResponse(
        ranking_file=ranking.ranking_file,
        ranking_model=ranking.ranking_model,
        model_selection_status=ranking.model_selection_status,
        synthetic=ranking.synthetic,
        total_cves=ranking.count,
        patchers=plan.patchers,
        hours_per_patcher=plan.hours_per_patcher,
        capacity_hours=plan.capacity_hours,
        used_hours=plan.used_hours,
        total_priority_value=plan.total_priority_value,
        scheduled=[ScheduleItem.model_validate(asdict(item)) for item in plan.scheduled],
        deferred=[ScheduleItem.model_validate(asdict(item)) for item in plan.deferred],
    )
