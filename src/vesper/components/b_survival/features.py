"""Day-0 features for the Component B models."""

import warnings

import pandas as pd

TOP_CWE_COUNT = 10

NUMERIC_COLUMN = "cvss_base_score"
CATEGORICAL_COLUMNS = [
    "cvss_attack_vector",
    "cvss_attack_complexity",
    "cvss_privileges_required",
    "cvss_user_interaction",
]
FLAG_COLUMN = "exploit_at_publication"
CWE_COLUMN = "cwe_ids"

# Columns a model must never see (see the module docstring for the reasons)
BANNED_COLUMNS = {
    "in_kev",
    "kev_date_added",
    "exploit_first_date",
    "kev_launch_group",
    "already_exploited",
    "cvss_missing",
    "duration_days",
    "event",
}


def drop_missing_cvss(table):
    """Leave out CVEs without a CVSS score. Returns the table and the counts left out.

    The counts are {"rows": ..., "events": ...}, so they can be printed.
    """
    missing = table[NUMERIC_COLUMN].isna()
    left_out = {
        "rows": int(missing.sum()),
        "events": int(table.loc[missing, "event"].sum()) if "event" in table else 0,
    }
    return table[~missing].reset_index(drop=True), left_out


def split_cwe_ids(value):
    """'CWE-79;CWE-89' -> ['CWE-79', 'CWE-89']; an empty value -> []."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return []
    return [cwe_id for cwe_id in str(value).split(";") if cwe_id]


class FeatureEncoder:
    """Learns the feature encoding on TRAIN rows and applies it to any rows."""

    def __init__(self, top_cwe_count=TOP_CWE_COUNT):
        self.top_cwe_count = top_cwe_count
        self.fitted = False

    # --- learning (TRAIN only) -------------------------------------------------

    def fit(self, train):
        """Learn the mean and spread of the score, the levels and the top CWEs."""
        scores = train[NUMERIC_COLUMN].astype(float)
        if scores.isna().any():
            raise ValueError("Train rows without a CVSS score: use drop_missing_cvss first")
        self.score_mean = float(scores.mean())
        self.score_std = float(scores.std()) or 1.0

        # For each category: the levels seen in train. The most common level is
        # the reference and gets no dummy (otherwise the dummies add up to 1).
        self.levels, self.reference = {}, {}
        for column in CATEGORICAL_COLUMNS:
            counts = train[column].value_counts()
            self.levels[column] = sorted(counts.index)
            self.reference[column] = counts.index[0]

        counts = {}
        for value in train[CWE_COLUMN]:
            for cwe_id in set(split_cwe_ids(value)):
                counts[cwe_id] = counts.get(cwe_id, 0) + 1
        ranked = sorted(counts, key=lambda cwe_id: (-counts[cwe_id], cwe_id))
        self.top_cwes = ranked[: self.top_cwe_count]

        # A feature that never changes in train cannot be estimated; drop it
        features = self._encode(train, warn=False)
        self.columns = [column for column in features if features[column].nunique() > 1]
        self.dropped_constant = [column for column in features if column not in self.columns]
        self.fitted = True
        return self

    # --- applying (any rows) ----------------------------------------------------

    def transform(self, rows):
        """Encode rows with what was learned in fit(). Returns only feature columns."""
        if not self.fitted:
            raise RuntimeError("FeatureEncoder.fit must be called before transform")
        return self._encode(rows, warn=True)[self.columns]

    def _encode(self, rows, warn):
        features = pd.DataFrame(index=rows.index)
        scores = rows[NUMERIC_COLUMN].astype(float)
        features["cvss_score_std"] = (scores - self.score_mean) / self.score_std

        for column in CATEGORICAL_COLUMNS:
            values = rows[column]
            unknown = ~values.isin(self.levels[column])
            if warn and unknown.any():
                # A level never seen in train has no coefficient. The reference
                # level is the safe default: it adds nothing to the risk.
                seen = sorted(set(values[unknown].astype(str)))
                warnings.warn(
                    f"{column}: unknown value(s) {seen} in {int(unknown.sum())} row(s); "
                    f"using the reference level {self.reference[column]!r}",
                    stacklevel=3,
                )
            values = values.where(~unknown, self.reference[column])
            for level in self.levels[column]:
                if level != self.reference[column]:
                    features[f"{column}={level}"] = (values == level).astype(int)

        features[FLAG_COLUMN] = rows[FLAG_COLUMN].astype(bool).astype(int)

        # An unknown CWE, or no CWE, gets no dummy: it is "other" (the reference)
        cwe_lists = rows[CWE_COLUMN].map(split_cwe_ids)
        for cwe_id in self.top_cwes:
            features[f"cwe={cwe_id}"] = cwe_lists.map(lambda ids, c=cwe_id: int(c in ids))
        return features
