import pandas as pd

from vesper.components.a_text.labels import build_training_cohort

CUTOFF = "2023-01-01"


def labels(published, kev):
    """Labels of the cohort built from one CVE; [] means the CVE was left out."""
    frame = pd.DataFrame(
        {
            "published_date": pd.to_datetime([published], utc=True),
            "kev_date_added": pd.to_datetime([kev], utc=True),
        }
    )
    return list(build_training_cohort(frame, CUTOFF).label)


def test_kev_within_90_days_is_positive():
    assert labels("2022-03-01", "2022-04-01") == [1]
    assert labels("2022-03-01", "2022-05-30") == [1]  # exactly day 90 still counts


def test_kev_after_90_days_is_negative():
    assert labels("2022-03-01", "2022-05-31") == [0]  # day 91
    assert labels("2022-03-01", "2022-08-01") == [0]


def test_never_in_kev_is_negative():
    assert labels("2022-03-01", None) == [0]


def test_already_in_kev_at_publication_is_excluded():
    assert labels("2022-03-01", "2022-02-01") == []
    assert labels("2022-03-01", "2022-03-01") == []


def test_unsettled_window_is_excluded():
    assert labels("2022-10-15", None) == []  # window ends 2023-01-13, after the cut-off
    assert labels("2022-10-15", "2022-11-01") == []  # even though the KEV date is known
    assert labels("2022-10-03", None) == []  # window ends on the cut-off itself
    assert labels("2022-10-02", None) == [0]  # window ends the day before


def test_published_after_cutoff_or_before_kev_start_is_excluded():
    assert labels("2023-02-01", None) == []
    assert labels("2021-06-01", None) == []
