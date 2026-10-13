"""
The study dates of Component B, kept in one place.

Every step reads these values from here, so that each one is written only once.
The reasons are in data_decisions.md and data_snapshot.md.
"""

from datetime import date

# The censoring date: the day the KEV catalogue was downloaded. A CVE that is
# not in KEV is only known to be unexploited up to this day, and no record
# dated after it may be used.
SNAPSHOT_DATE = date(2026, 10, 1)

# The first publication day included in the study. CVEs published in 2015 are
# left out because 96.4% of them have no CVSS 3.x score. The cleaning steps do
# not filter on this date; the survival table step will.
STUDY_START = date(2016, 1, 1)

# Proposed, waiting for team agreement: the cut-off dates of the chronological
# split. For each one, the model is trained on CVEs published before the date
# and tested on CVEs published on or after it.
CUTOFF_DATES = (date(2022, 1, 1), date(2022, 7, 1), date(2023, 1, 1), date(2024, 1, 1))

# Proposed, waiting for team agreement: the label-maturity filter. A CVE is
# used for testing only if it was published at least this many days before
# the snapshot date, so that its outcome has had time to be observed.
MATURITY_DAYS = 365

# Component B's own subfolder inside the shared processed-data folder
# (load_settings().data_processed / PROCESSED_SUBFOLDER)
PROCESSED_SUBFOLDER = "b_survival"
