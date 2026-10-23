"""Component A text model: word + character TF-IDF into a logistic regression."""

from dataclasses import dataclass
from functools import cached_property

import numpy as np
import pandas as pd
from scipy.special import expit
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer, Normalizer

from vesper.components.a_text.sanitise import sanitise_text

SEED = 42
MIN_POSITIVES = 12
MAX_NEGATIVES = 40_000
C_GRID = (0.1, 1.0, 10.0)
# Spread of at least one log-odds unit, so a narrow reference cannot over-stretch the score.
MIN_RANKING_SCALE = 1.0
# Negation words carry meaning in CVE text ("without authentication"), so keep them.
STOP_WORDS = sorted(set(ENGLISH_STOP_WORDS) - {"no", "not", "nor", "never", "without"})


@dataclass
class TextModel:
    """A fitted pipeline plus the log-odds shift that undoes negative downsampling."""

    pipeline: Pipeline
    offset: float
    best_c: float

    def log_odds(self, texts) -> np.ndarray:
        return self.pipeline.decision_function(texts) + self.offset

    def predict_proba(self, texts) -> np.ndarray:
        return expit(self.log_odds(texts))

    @property
    def word_vectorizer(self) -> TfidfVectorizer:
        return self.pipeline["features"]["terms"].named_transformers["word"]

    @cached_property
    def word_names(self) -> np.ndarray:
        """The 65k word feature names, built once per loaded model (this takes ~60 ms)."""
        return self.word_vectorizer.get_feature_names_out()


def clean_texts(texts) -> list[str]:
    """Missing descriptions become empty strings; leak wording is deleted."""
    if isinstance(texts, str):  # a bare string would be read as one text per character
        raise TypeError("pass a list of texts, not a single string")
    return [sanitise_text("" if pd.isna(t) else str(t)) for t in texts]


def build_features() -> Pipeline:
    """Sanitise, build word (1-2) and char_wb (3-5) TF-IDF blocks, then L2-normalise."""
    word = TfidfVectorizer(
        ngram_range=(1, 2),
        stop_words=STOP_WORDS,
        min_df=2,
        max_features=65_536,
        sublinear_tf=True,
        norm=None,
        dtype=np.float32,
    )
    char = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        max_features=32_768,
        sublinear_tf=True,
        norm=None,
        dtype=np.float32,
    )
    return Pipeline(
        [
            ("clean", FunctionTransformer(clean_texts)),
            ("terms", FeatureUnion([("word", word), ("char", char)])),
            ("norm", Normalizer()),
        ]
    )


def sample_training(train: pd.DataFrame) -> tuple[pd.DataFrame, float]:
    """Keep every positive, downsample negatives, return the log-odds offset to undo it."""
    positives = train[train.label == 1]
    negatives = train[train.label == 0]
    if len(positives) < MIN_POSITIVES:
        raise ValueError(f"Need at least {MIN_POSITIVES} positives, got {len(positives)}")
    if len(negatives) < 3:
        raise ValueError("Need at least three negatives for cross-validation")
    kept = negatives.sample(min(MAX_NEGATIVES, len(negatives)), random_state=SEED)
    sampled = pd.concat([positives, kept]).sort_index()
    return sampled, float(np.log(len(kept) / len(negatives)))


def fit_pipeline(texts, y: np.ndarray) -> Pipeline:
    """Build the features on `texts`, then fit the logistic regression with the best C."""
    features = build_features()
    x = features.fit_transform(texts)
    x.sort_indices()  # same column order per row as the original code, so liblinear matches

    # C is picked by 3-fold average precision on the (already built) training features.
    search = GridSearchCV(
        LogisticRegression(solver="liblinear", max_iter=500, random_state=SEED),
        {"C": list(C_GRID)},
        scoring="average_precision",
        cv=StratifiedKFold(3, shuffle=True, random_state=SEED),
    ).fit(x, y)
    return Pipeline([("features", features), ("clf", search.best_estimator_)])


def fit_text_model(train: pd.DataFrame) -> TextModel:
    """Fit on a frame with `description` and 0/1 `label` columns."""
    sampled, offset = sample_training(train)
    pipeline = fit_pipeline(sampled.description, sampled.label.to_numpy(dtype=int))
    return TextModel(pipeline, offset, float(pipeline["clf"].C))


def held_out_log_odds(train: pd.DataFrame) -> np.ndarray:
    """Log-odds of each training row from a model fitted without it (3 folds, own vocabulary)."""
    sampled, offset = sample_training(train)
    texts = sampled.description.to_numpy()
    y = sampled.label.to_numpy(dtype=int)
    out = np.empty(len(y))
    for fit_rows, held_rows in StratifiedKFold(3, shuffle=True, random_state=SEED).split(texts, y):
        fold = fit_pipeline(texts[fit_rows], y[fit_rows])
        out[held_rows] = fold.decision_function(texts[held_rows]) + offset
    return out


def ranking_reference(held_out_log_odds) -> dict[str, float]:
    """Centre (median) and spread (inter-quartile range) of held-out training log-odds."""
    values = np.asarray(held_out_log_odds, dtype=float)
    q25, q75 = np.quantile(values, [0.25, 0.75])
    return {
        "ranking_centre": float(np.median(values)),
        "ranking_scale": max(float(q75 - q25), MIN_RANKING_SCALE),
    }
