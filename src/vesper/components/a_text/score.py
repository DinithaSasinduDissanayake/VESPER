"""Score one CVE description: scope gate, masking, log-odds, ranking score and top words."""

import joblib
import numpy as np
import sklearn
from scipy.special import expit

from vesper.components.a_text.explain import contributions, locate_words, spans_of
from vesper.components.a_text.sanitise import rules_digest, sanitise_text
from vesper.components.a_text.text_gate import MIN_WORDS, WORD, text_scope
from vesper.contracts.score import ScoreKind, ScoreStatus

MODEL_NAME = "a_text-tfidf-lr"  # model_version is this plus the training cut-off
TOP_N = 10  # words listed in each direction


def ranking_score(log_odds, centre: float, scale: float):
    """Map log-odds into (0, 1) with arctan. Keeps the order; it is not a probability."""
    return 0.5 + np.arctan((log_odds - centre) / scale) / np.pi


def load_model(path) -> dict:
    """Load {"model": TextModel, "metadata": {...}} saved by train.py. Only load trusted files."""
    saved = joblib.load(path)  # joblib runs pickle code: never load a file a user uploaded
    meta = saved["metadata"]
    if "ranking_centre" not in meta:
        raise ValueError(f"{path} has no ranking reference; retrain with train.py")
    # The pipeline calls today's sanitise code, so different rules mean unseen inputs.
    if meta.get("sanitiser_digest") != rules_digest():
        raise ValueError(f"{path}: masking rules changed since training; retrain with train.py")
    if meta.get("sklearn_version") != sklearn.__version__:
        raise ValueError(f"{path} was trained with sklearn {meta.get('sklearn_version')}")
    return saved


def score_description(model: dict, text: object) -> dict:
    """Score one description, or abstain with a reason. Every key is present either way.

    log_odds is the model output after undoing negative downsampling. uncalibrated_probability
    is expit(log_odds) and is not calibrated. ranking_score is the number to show and sort by.
    top_words lists word contributions; totals adds up to log_odds (to rounding).
    """
    meta = model["metadata"]
    result = {
        "status": ScoreStatus.ABSTAINED,
        "reason": None,
        "score_kind": ScoreKind.RANKING_SCORE,
        "ranking_score": None,
        "log_odds": None,
        "uncalibrated_probability": None,
        "model_version": f"{MODEL_NAME}-{meta['cutoff']}",
        "trained_through": meta["cutoff"],
        "horizon_days": meta["horizon_days"],
        "model_text": None,  # the description after masking: what the model actually read
        "top_words": {"up": [], "down": []},
        "totals": None,
    }
    in_scope, result["reason"] = text_scope(text)
    if not in_scope:
        return result
    result["model_text"] = sanitise_text(text)
    # The topic is judged on what was pasted; the length on what the model reads.
    if len(WORD.findall(result["model_text"])) < MIN_WORDS:
        result["reason"] = "too_short_after_masking"
        return result

    text_model = model["model"]
    # One feature row (mask, TF-IDF, L2-normalise); the score and its breakdown both use it.
    row = text_model.pipeline["features"].transform([text])
    log_odds = float(text_model.pipeline["clf"].decision_function(row)[0] + text_model.offset)
    words, totals = contributions(text_model, row)
    located = locate_words(text_model, text)
    ranked = sorted(words.items(), key=lambda item: item[1])
    up = [item for item in reversed(ranked) if item[1] > 0][:TOP_N]
    down = [item for item in ranked if item[1] < 0][:TOP_N]

    def listed(items):
        return [{"term": t, "contribution": c, "spans": spans_of(t, located)} for t, c in items]

    result.update(
        status=ScoreStatus.AVAILABLE,
        ranking_score=float(ranking_score(log_odds, meta["ranking_centre"], meta["ranking_scale"])),
        log_odds=log_odds,
        uncalibrated_probability=float(expit(log_odds)),
        top_words={"up": listed(up), "down": listed(down)},
        totals=totals,
    )
    return result
