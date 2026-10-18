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

MODEL_NAMES = (
    "epss",
    "cvss",
    "equal_weight",
    "logistic_regression",
    "gradient_boosting",
)


@dataclass
class LogisticModel:
    """Small regularized logistic model with serializable preprocessing state."""

    medians: list[float]
    means: list[float]
    scales: list[float]
    coefficients: list[float]
    intercept: float
    feature_names: list[str] | None = None


@dataclass
class GradientBoostedStumpModel:
    """Gradient-boosted logistic model made from shallow decision trees."""

    medians: list[float]
    initial_logit: float
    learning_rate: float
    stumps: list[dict[str, float | int]]
    feature_names: list[str] | None = None


def feature_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Return the five risk inputs on a common 0-1 scale."""

    features = pd.DataFrame(index=frame.index)
    features["epss_score"] = (
        pd.to_numeric(frame["epss_score"], errors="coerce")
        if "epss_score" in frame
        else np.nan
    )
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
        features[column] = (
            pd.to_numeric(frame[column], errors="coerce") if column in frame else np.nan
        )
    for column in FEATURES:
        valid = features[column].dropna()
        if not valid.between(0.0, 1.0).all():
            raise ValueError(f"{column} values must be between 0 and 1")
    return features


def _available_mean(features: pd.DataFrame) -> pd.Series:
    return features.mean(axis=1).where(features.notna().any(axis=1))


def fit_logistic(
    features: pd.DataFrame,
    labels: pd.Series,
    feature_columns: tuple[str, ...] = FEATURES,
) -> LogisticModel:
    """Fit a class-weighted, L2-regularized logistic model using NumPy."""

    y = labels.astype(float).to_numpy()
    if set(np.unique(y)) != {0.0, 1.0}:
        raise ValueError("Logistic regression needs both positive and negative training labels")

    values = features.loc[:, feature_columns].to_numpy(dtype=float)
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
        feature_names=list(feature_columns),
    )


def score_logistic(features: pd.DataFrame, model: LogisticModel) -> pd.Series:
    feature_columns = model.feature_names or list(FEATURES)
    values = features.loc[:, feature_columns].to_numpy(dtype=float)
    missing = np.isnan(values).astype(float)
    values = np.where(np.isnan(values), np.asarray(model.medians), values)
    standardized = (values - np.asarray(model.means)) / np.asarray(model.scales)
    design = np.column_stack((standardized, missing))
    logits = np.clip(design @ np.asarray(model.coefficients) + model.intercept, -30.0, 30.0)
    scores = 1.0 / (1.0 + np.exp(-logits))
    return pd.Series(scores, index=features.index, name="risk_score")


def _tree_design(
    features: pd.DataFrame,
    medians: np.ndarray,
    feature_columns: tuple[str, ...] = FEATURES,
) -> np.ndarray:
    values = features.loc[:, feature_columns].to_numpy(dtype=float)
    missing = np.isnan(values).astype(float)
    values = np.where(np.isnan(values), medians, values)
    return np.column_stack((values, missing))


def fit_gradient_boosting(
    features: pd.DataFrame,
    labels: pd.Series,
    n_estimators: int = 80,
    learning_rate: float = 0.05,
    max_bins: int = 24,
    l2_regularization: float = 1.0,
    min_leaf: int = 20,
    feature_columns: tuple[str, ...] = FEATURES,
) -> GradientBoostedStumpModel:
    """Fit a class-weighted gradient-boosted decision-stump classifier.

    Each stump makes one split chosen by logistic-loss Newton gain. The model
    learns from labels and returns probabilities that can be sorted into a
    risk ranking. Missing features use training-only medians plus indicators.
    """

    y = labels.astype(float).to_numpy()
    if set(np.unique(y)) != {0.0, 1.0}:
        raise ValueError("Gradient boosting needs both positive and negative training labels")
    values = features.loc[:, feature_columns].to_numpy(dtype=float)
    medians = np.nanmedian(values, axis=0)
    if not np.isfinite(medians).all():
        raise ValueError("Each model feature needs at least one observed training value")
    design = _tree_design(features, medians, feature_columns)

    positives = int(y.sum())
    negatives = len(y) - positives
    weights = np.where(y == 1.0, negatives / positives, 1.0)
    weighted_positive = float(weights[y == 1.0].sum())
    weighted_negative = float(weights[y == 0.0].sum())
    initial_logit = float(np.log(weighted_positive / weighted_negative))
    logits = np.full(len(y), initial_logit, dtype=float)

    quantiles = np.linspace(0.02, 0.98, max_bins)
    thresholds = [
        np.unique(np.quantile(design[:, feature], quantiles))
        for feature in range(design.shape[1])
    ]
    stumps: list[dict[str, float | int]] = []

    for _ in range(n_estimators):
        probabilities = 1.0 / (1.0 + np.exp(-np.clip(logits, -30.0, 30.0)))
        gradients = weights * (y - probabilities)
        hessians = np.maximum(weights * probabilities * (1.0 - probabilities), 1e-8)
        best_gain = 0.0
        best_split = None

        for feature, cuts in enumerate(thresholds):
            if not len(cuts):
                continue
            bins = np.searchsorted(cuts, design[:, feature], side="left")
            bin_count = len(cuts) + 1
            gradient_bins = np.bincount(bins, weights=gradients, minlength=bin_count)
            hessian_bins = np.bincount(bins, weights=hessians, minlength=bin_count)
            row_bins = np.bincount(bins, minlength=bin_count)
            left_gradient = np.cumsum(gradient_bins)[:-1]
            left_hessian = np.cumsum(hessian_bins)[:-1]
            left_rows = np.cumsum(row_bins)[:-1]
            right_gradient = gradients.sum() - left_gradient
            right_hessian = hessians.sum() - left_hessian
            right_rows = len(y) - left_rows
            valid = (left_rows >= min_leaf) & (right_rows >= min_leaf)
            if not valid.any():
                continue
            gains = (
                left_gradient**2 / (left_hessian + l2_regularization)
                + right_gradient**2 / (right_hessian + l2_regularization)
            )
            gains[~valid] = -np.inf
            split_index = int(np.argmax(gains))
            gain = float(gains[split_index])
            if gain > best_gain:
                best_gain = gain
                best_split = (
                    feature,
                    float(cuts[split_index]),
                    float(
                        left_gradient[split_index]
                        / (left_hessian[split_index] + l2_regularization)
                    ),
                    float(
                        right_gradient[split_index]
                        / (right_hessian[split_index] + l2_regularization)
                    ),
                )

        if best_split is None:
            break
        feature, threshold, left_value, right_value = best_split
        stump = {
            "feature": feature,
            "threshold": threshold,
            "left_value": left_value,
            "right_value": right_value,
        }
        stumps.append(stump)
        logits += learning_rate * np.where(
            design[:, feature] <= threshold, left_value, right_value
        )

    if not stumps:
        raise ValueError("Gradient boosting could not find a valid split in the training data")
    return GradientBoostedStumpModel(
        medians=medians.tolist(),
        initial_logit=initial_logit,
        learning_rate=learning_rate,
        stumps=stumps,
        feature_names=list(feature_columns),
    )


def score_gradient_boosting(
    features: pd.DataFrame, model: GradientBoostedStumpModel
) -> pd.Series:
    """Return fitted gradient-boosting probabilities for ranking CVEs."""

    feature_columns = model.feature_names or list(FEATURES)
    design = _tree_design(
        features, np.asarray(model.medians, dtype=float), tuple(feature_columns)
    )
    logits = np.full(len(features), model.initial_logit, dtype=float)
    for stump in model.stumps:
        feature = int(stump["feature"])
        values = np.where(
            design[:, feature] <= float(stump["threshold"]),
            float(stump["left_value"]),
            float(stump["right_value"]),
        )
        logits += model.learning_rate * values
    probabilities = 1.0 / (1.0 + np.exp(-np.clip(logits, -30.0, 30.0)))
    return pd.Series(probabilities, index=features.index, name="risk_score")


def score_model(
    model_name: str,
    features: pd.DataFrame,
    fitted_model: LogisticModel | GradientBoostedStumpModel | None = None,
) -> pd.Series:
    """Score CVEs using a named baseline or fitted candidate model."""

    if model_name == "epss":
        scores = features["epss_score"]
    elif model_name == "cvss":
        scores = features["cvss_normalized"]
    elif model_name == "equal_weight":
        scores = _available_mean(features)
    elif model_name == "logistic_regression":
        if not isinstance(fitted_model, LogisticModel):
            raise ValueError("Logistic regression must be fit before scoring")
        return score_logistic(features, fitted_model)
    elif model_name == "gradient_boosting":
        if not isinstance(fitted_model, GradientBoostedStumpModel):
            raise ValueError("Gradient boosting must be fit before scoring")
        return score_gradient_boosting(features, fitted_model)
    else:
        raise ValueError(f"Unknown model {model_name!r}; choose from {MODEL_NAMES}")
    return pd.to_numeric(scores, errors="coerce").rename("risk_score")
