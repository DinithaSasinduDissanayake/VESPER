"""Candidate ranking models for Component D's CVE-level score table."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

FEATURES = (
    "epss_score",
    "cvss_normalized",
    "score_a",
    "score_b",
    "score_c",
)

MODEL_NAMES = ("epss", "cvss", "equal_weight", "logistic_regression")


@dataclass
class LogisticModel:
    """Small regularized logistic model with serializable preprocessing state."""

    medians: list[float]
    means: list[float]
    scales: list[float]
    coefficients: list[float]
    intercept: float


def feature_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Return the five risk inputs on a common 0-1 scale."""

    features = pd.DataFrame(index=frame.index)
    features["epss_score"] = pd.to_numeric(frame.get("epss_score"), errors="coerce")
    if "cvss_normalized" in frame:
        features["cvss_normalized"] = pd.to_numeric(
            frame["cvss_normalized"], errors="coerce"
        )
    elif "cvss_base_score" in frame:
        features["cvss_normalized"] = pd.to_numeric(
            frame["cvss_base_score"], errors="coerce"
        ).div(10.0)
    else:
        features["cvss_normalized"] = np.nan
    for column in ("score_a", "score_b", "score_c"):
        features[column] = pd.to_numeric(frame.get(column), errors="coerce")
    for column in FEATURES:
        valid = features[column].dropna()
        if not valid.between(0.0, 1.0).all():
            raise ValueError(f"{column} values must be between 0 and 1")
    return features


def _available_mean(features: pd.DataFrame) -> pd.Series:
    return features.mean(axis=1).where(features.notna().any(axis=1))


def fit_logistic(features: pd.DataFrame, labels: pd.Series) -> LogisticModel:
    """Fit a class-weighted, L2-regularized logistic model using NumPy."""

    y = labels.astype(float).to_numpy()
    if set(np.unique(y)) != {0.0, 1.0}:
        raise ValueError("Logistic regression needs both positive and negative training labels")

    values = features.loc[:, FEATURES].to_numpy(dtype=float)
    medians = np.nanmedian(values, axis=0)
    if not np.isfinite(medians).all():
        raise ValueError("Each model feature needs at least one observed training value")
    missing = np.isnan(values).astype(float)
    values = np.where(np.isnan(values), medians, values)
    means = values.mean(axis=0)
    scales = values.std(axis=0)
    scales[scales == 0.0] = 1.0
    standardized = (values - means) / scales
    design = np.column_stack((standardized, missing))

    positives = int(y.sum())
    negatives = len(y) - positives
    weights = np.where(y == 1.0, negatives / positives, 1.0)
    coefficients = np.zeros(design.shape[1], dtype=float)
    intercept = float(np.log((positives + 0.5) / (negatives + 0.5)))
    regularization = 0.1
    learning_rate = 0.1
    for _ in range(1200):
        logits = np.clip(design @ coefficients + intercept, -30.0, 30.0)
        probabilities = 1.0 / (1.0 + np.exp(-logits))
        errors = (probabilities - y) * weights
        gradient = (design.T @ errors) / weights.sum() + regularization * coefficients
        intercept_gradient = float(errors.sum() / weights.sum())
        coefficients -= learning_rate * gradient
        intercept -= learning_rate * intercept_gradient

    return LogisticModel(
        medians=medians.tolist(),
        means=means.tolist(),
        scales=scales.tolist(),
        coefficients=coefficients.tolist(),
        intercept=intercept,
    )


def score_logistic(features: pd.DataFrame, model: LogisticModel) -> pd.Series:
    values = features.loc[:, FEATURES].to_numpy(dtype=float)
    missing = np.isnan(values).astype(float)
    values = np.where(np.isnan(values), np.asarray(model.medians), values)
    standardized = (values - np.asarray(model.means)) / np.asarray(model.scales)
    design = np.column_stack((standardized, missing))
    logits = np.clip(design @ np.asarray(model.coefficients) + model.intercept, -30.0, 30.0)
    scores = 1.0 / (1.0 + np.exp(-logits))
    return pd.Series(scores, index=features.index, name="risk_score")


def score_model(
    model_name: str,
    features: pd.DataFrame,
    logistic_model: LogisticModel | None = None,
) -> pd.Series:
    """Score CVEs using a named baseline or fitted candidate model."""

    if model_name == "epss":
        scores = features["epss_score"]
    elif model_name == "cvss":
        scores = features["cvss_normalized"]
    elif model_name == "equal_weight":
        scores = _available_mean(features)
    elif model_name == "logistic_regression":
        if logistic_model is None:
            raise ValueError("Logistic regression must be fit before scoring")
        return score_logistic(features, logistic_model)
    else:
        raise ValueError(f"Unknown model {model_name!r}; choose from {MODEL_NAMES}")
    return pd.to_numeric(scores, errors="coerce").rename("risk_score")
