"""Build the Component A training cohort and its 0/1 labels at a cut-off date."""

import pandas as pd

HORIZON_DAYS = 90  # label = added to KEV within this many days of the decision time
DECISION_DAYS = 0  # the decision time is the publication date itself
# KEV started on this date and listed its whole backlog with this date, so a KEV date
# says when a CVE was listed only for CVEs published from here on.
KEV_START_DATE = pd.Timestamp("2021-11-03", tz="UTC")


def build_training_cohort(frame: pd.DataFrame, cutoff) -> pd.DataFrame:
    """CVEs whose label was already known before `cutoff`, with a 0/1 `label` column.

    `frame` needs `published_date` and `kev_date_added`, both UTC datetimes
    (`kev_date_added` is missing for CVEs that were never in KEV). Other columns
    are kept. A row is kept when the CVE was published from KEV_START_DATE and
    before `cutoff`, its whole label window ended strictly before `cutoff`, and it
    was not already in KEV at its decision time.
    """
    cutoff = pd.Timestamp(cutoff, tz="UTC")
    decision = frame.published_date + pd.Timedelta(days=DECISION_DAYS)
    window_end = decision + pd.Timedelta(days=HORIZON_DAYS)

    already_in_kev = frame.kev_date_added <= decision
    keep = (
        (frame.published_date >= KEV_START_DATE)
        & (frame.published_date < cutoff)
        & (window_end < cutoff)  # the label is settled: the window closed before the cut-off
        & ~already_in_kev
    )

    cohort = frame[keep].copy()
    # Missing KEV dates compare as False, so never-listed CVEs get label 0.
    cohort["label"] = (cohort.kev_date_added <= window_end[keep]).astype(int)
    return cohort
