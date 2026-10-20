import json
from pathlib import Path
from datetime import datetime, timezone

from vesper.components.c_graph.historical import parse_cpe_events

history_dir = Path("data/raw/nvd/history")
cutoff = datetime(2025, 1, 1, tzinfo=timezone.utc)
inspected = 0

for path in sorted(history_dir.glob("CVE-*.json")):
    history = json.loads(path.read_text(encoding="utf-8"))
    events = parse_cpe_events(history)

    if any(event.created_at <= cutoff for event in events):
        continue

    print(f"\nFILE: {path.name}")

    for item in history.get("cveChanges", []):
        change = item.get("change", {})

        for detail in change.get("details", []):
            if "CPE" in str(detail.get("type", "")).upper():
                print("TYPE:", repr(detail.get("type")))
                print("ACTION:", repr(detail.get("action")))
                print("OLD:", repr(detail.get("oldValue", detail.get("previousValue"))))
                print("NEW:", repr(detail.get("newValue")))

    inspected += 1
    if inspected == 3:
        break

print(f"\nCases inspected: {inspected}")
