"""Component A text model: word + character TF-IDF into a logistic regression."""

from dataclasses import dataclass

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


def clean_texts(texts) -> list[str]:
    """Missing descriptions become empty strings; leak wording is deleted."""
    return [sanitise_text("" if pd.isna(t) else str(t)) for t in texts]


def build_features() -> Pipeline:
    """Sanitise, build word (1-2) and char_wb (3-5) TF-IDF blocks, then L2-normalise."""
    word = TfidfVectorizer(
        ngram_range=(1, 2), stop_words=STOP_WORDS, min_df=2, max_features=65_536,
        sublinear_tf=True, norm=None, dtype=np.float32,
    )
    char = TfidfVectorizer(
        analyzer="char_wb", ngram_range=(3, 5), min_df=2, max_features=32_768,
        sublinear_tf=True, norm=None, dtype=np.float32,
    )
    return Pipeline([
        ("clean", FunctionTransformer(clean_texts)),
        ("terms", FeatureUnion([("word", word), ("char", char)])),
        ("norm", Normalizer()),
    ])


def sample_training(train: pd.DataFrame) -> tuple[pd.DataFrame, float]:
    """Keep every positive, downsample negatives, return the log-odds offset to undo it."""
    positives = train[train.label == 1]
    negatives = train[train.label == 0]
    if len(positives) < MIN_POSITIVES:
        raise ValueError(f"Need {MIN_POSITIVES} positives, got {len(positives)}")
    if len(negatives) < 3:
        raise ValueError("Need at least three negatives for cross-validation")
    kept = negatives.sample(min(MAX_NEGATIVES, len(negatives)), random_state=SEED)
    sampled = pd.concat([positives, kept]).sort_index()
    return sampled, float(np.log(len(kept) / len(negatives)))


def fit_text_model(train: pd.DataFrame) -> TextModel:
    """Fit on a frame with `description` and 0/1 `label` columns."""
    sampled, offset = sample_training(train)
    y = sampled.label.to_numpy(dtype=int)
    features = build_features()
    x = features.fit_transform(sampled.description)
    x.sort_indices()  # same column order per row as the original code, so liblinear matches

    # C is picked by 3-fold average precision on the (already built) training features.
    search = GridSearchCV(
        LogisticRegression(solver="liblinear", max_iter=500, random_state=SEED),
        {"C": list(C_GRID)},
        scoring="average_precision",
        cv=StratifiedKFold(3, shuffle=True, random_state=SEED),
    ).fit(x, y)
    pipeline = Pipeline([("features", features), ("clf", search.best_estimator_)])
    return TextModel(pipeline, offset, float(search.best_params_["C"]))
