"""Shared description of one score given to one vulnerability by one component."""

import math
from dataclasses import dataclass
from datetime import date, datetime
from enum import StrEnum

from vesper.contracts.vulnerability import CVE_ID_PATTERN


class Component(StrEnum):
    """The four VESPER components."""

    A_TEXT = "a_text"
    B_SURVIVAL = "b_survival"
    C_GRAPH = "c_graph"
    D_FUSION = "d_fusion"


class ScoreKind(StrEnum):
    """What kind of number the score is."""

    RANKING_SCORE = "ranking_score"
    VALIDATED_PROBABILITY = "validated_probability"


class ScoreStatus(StrEnum):
    """Whether the component produced a score, and if not, why."""

    AVAILABLE = "available"
    ABSTAINED = "abstained"
    ALREADY_EXPLOITED = "already_exploited"
    NOT_ELIGIBLE = "not_eligible"


@dataclass(frozen=True)
class Score:
    """One component's answer for one CVE at one decision time.

    A score is only meaningful together with the moment it was made for and
    the time window it looks ahead. A higher score means a higher risk. The
    position in a ranked list is not stored; it comes from sorting the scores.

    trained_through is the cut-off of the model's training data: no training
    row was published, and no training label was settled, at or after it. It
    is empty for a score that needs no training, such as a CVSS baseline.
    """

    cve_id: str
    component: Component
    decision_time: datetime
    horizon_days: int
    score: float | None
    score_kind: ScoreKind
    status: ScoreStatus
    reason: str | None
    model_version: str
    trained_through: datetime | None
    snapshot_date: date

    def __post_init__(self) -> None:
        if not CVE_ID_PATTERN.match(self.cve_id):
            raise ValueError(f"Invalid CVE identifier: {self.cve_id!r}")
        if self.decision_time.tzinfo is None:
            raise ValueError("decision_time must include a time zone")
        if self.trained_through is not None:
            if self.trained_through.tzinfo is None:
                raise ValueError("trained_through must include a time zone")
            if self.trained_through > self.decision_time:
                raise ValueError("trained_through must not be after decision_time")
        if self.horizon_days <= 0:
            raise ValueError(f"horizon_days must be positive: {self.horizon_days}")
        if self.status is ScoreStatus.AVAILABLE:
            if self.score is None or not math.isfinite(self.score):
                raise ValueError("An available score must be a finite number")
        elif self.score is not None:
            raise ValueError(f"A score with status {self.status.value!r} must be empty")
