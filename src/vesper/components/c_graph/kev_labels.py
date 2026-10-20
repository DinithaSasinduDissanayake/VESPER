"""Explicit outcome-state classification for KEV catalog additions."""

from __future__ import annotations

from datetime import date, datetime

import pandas as pd

KEV_CATALOG_START = pd.Timestamp("2021-11-03T00:00:00Z")


def _utc(value: str | datetime | pd.Timestamp) -> pd.Timestamp:
    result = pd.Timestamp(value)
    if result.tzinfo is None:
        raise ValueError(f"Timestamp must include a timezone: {value!r}")
    return result.tz_convert("UTC")


def classify_outcome(
    *,
    published: str | datetime | pd.Timestamp,
    date_added: str | date | pd.Timestamp | None,
    decision_time: str | datetime | pd.Timestamp,
    horizon_days: int,
    catalog_as_of: str | datetime | pd.Timestamp,
) -> tuple[str, bool | None, pd.Timestamp]:
    """Classify observed KEV-addition outcome without imputing unknowns.

    CISA's date-only ``dateAdded`` is interpreted at UTC midnight. A catalog
    addition at or before the decision timestamp is already listed. A negative
    requires the full horizon to be covered by the catalog's release date.
    """
    if isinstance(horizon_days, bool) or not isinstance(horizon_days, int) or horizon_days <= 0:
        raise ValueError("horizon_days must be a positive integer")
    decision = _utc(decision_time)
    publication = _utc(published)
    as_of = _utc(catalog_as_of)
    horizon_end = decision + pd.Timedelta(days=horizon_days)
    if publication >= decision:
        return "not_published_at_cutoff", None, horizon_end
    if decision < KEV_CATALOG_START:
        return "catalog_not_yet_operational", None, horizon_end
    if date_added is not None:
        added = pd.Timestamp(date_added)
        added = added.tz_localize("UTC") if added.tzinfo is None else added.tz_convert("UTC")
        if added <= decision:
            return "already_in_kev_at_cutoff", None, horizon_end
        if added <= horizon_end:
            return "positive_within_horizon", True, horizon_end
    if horizon_end > as_of:
        return "censored_horizon_not_fully_observed", None, horizon_end
    return "negative_full_horizon_observed", False, horizon_end
