"""FastAPI endpoints for Component A: score one pasted CVE description with the text model."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from vesper.config import load_settings

router = APIRouter(prefix="/api/a-text", tags=["Component A"])
DEFAULT_CUTOFF = "2026-10-01"  # the model the demo is trained at; override with VESPER_A_MODEL
_loaded: dict[Path, dict] = {}  # one loaded model per path; failures are not cached


class ScoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=10_000)


def _model_path() -> Path:
    settings = load_settings()
    configured_path = os.getenv("VESPER_A_MODEL")
    if not configured_path:
        return settings.outputs / "a_text" / "models" / f"model_{DEFAULT_CUTOFF}.joblib"
    path = Path(configured_path)
    return path if path.is_absolute() else settings.project_root / path


def _get_model() -> dict:
    """Load the trained model on first use and keep it; 503 if it is missing or out of date."""
    path = _model_path()
    if path in _loaded:
        return _loaded[path]
    if not path.is_file():
        raise HTTPException(
            status_code=503,
            detail=(
                f"Component A model not found at {path.name}. Train it with "
                "`python -m vesper.components.a_text.train` or set VESPER_A_MODEL."
            ),
        )
    # Imported here so the rest of the API starts without loading scikit-learn.
    from vesper.components.a_text.score import load_model

    try:
        _loaded[path] = load_model(path)
    except ValueError as error:  # e.g. masking rules changed since training: retrain
        raise HTTPException(status_code=503, detail=str(error)) from error
    return _loaded[path]


@router.post("/score")
def score(request: ScoreRequest) -> dict:
    """Score one description. Out-of-scope or too-short text is 200 with status "abstained"."""
    from vesper.components.a_text.score import score_description

    return score_description(_get_model(), request.text)


@router.get("/model")
def model_info() -> dict:
    """Which model is loaded: version, training cut-off, horizon and training counts."""
    from vesper.components.a_text.score import MODEL_NAME

    meta = _get_model()["metadata"]
    return {
        "model_version": f"{MODEL_NAME}-{meta['cutoff']}",
        "trained_through": meta["cutoff"],
        "horizon_days": meta["horizon_days"],
        "n_train": meta["n_train"],
        "n_positives": meta["n_positives"],
        "trained_at": meta.get("trained_at"),
    }
