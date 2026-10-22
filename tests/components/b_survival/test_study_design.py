"""Tests for the study dates of Component B."""

from datetime import date, timedelta

from vesper.components.b_survival.study_design import (
    CUTOFF_DATES,
    MAIN_CUTOFF,
    MATURITY_DAYS,
    SNAPSHOT_DATE,
    STUDY_START,
)


def test_snapshot_date_is_the_day_kev_was_downloaded():
    assert SNAPSHOT_DATE == date(2026, 10, 1)


def test_study_starts_on_the_first_day_of_2016():
    assert STUDY_START == date(2016, 1, 1)


def test_study_starts_before_the_snapshot():
    assert STUDY_START < SNAPSHOT_DATE


def test_proposed_cutoff_dates():
    assert CUTOFF_DATES == (
        date(2022, 1, 1),
        date(2022, 7, 1),
        date(2023, 1, 1),
        date(2024, 1, 1),
        date(2024, 7, 1),
    )


def test_the_main_cutoff_is_a_cutoff_with_a_full_test_window_before_the_snapshot():
    assert MAIN_CUTOFF in CUTOFF_DATES
    assert MAIN_CUTOFF == max(CUTOFF_DATES)
    assert MAIN_CUTOFF + timedelta(days=MATURITY_DAYS) < SNAPSHOT_DATE


def test_cutoff_dates_are_in_order_and_inside_the_study():
    assert list(CUTOFF_DATES) == sorted(CUTOFF_DATES)
    assert all(STUDY_START < cutoff < SNAPSHOT_DATE for cutoff in CUTOFF_DATES)


def test_proposed_maturity_days():
    assert MATURITY_DAYS == 365
