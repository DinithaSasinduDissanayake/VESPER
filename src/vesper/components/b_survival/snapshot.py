"""
Values that every Component B step must agree on.

They are kept in one place so that the snapshot date is written only once.
See data_snapshot.md for how the snapshot date was chosen.
"""

from datetime import date

# The censoring date: the day the KEV catalogue was downloaded. A CVE that is
# not in KEV is only known to be unexploited up to this day, and no record
# dated after it may be used.
SNAPSHOT_DATE = date(2026, 10, 1)

# Component B's own subfolder inside the shared processed-data folder
# (load_settings().data_processed / PROCESSED_SUBFOLDER)
PROCESSED_SUBFOLDER = "b_survival"
