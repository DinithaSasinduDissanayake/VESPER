
import json
from pathlib import Path
from collections import Counter

history_dir = Path("data/raw/nvd/history")
targets = [
    "CVE-2022-29409",
    "CVE-2022-43375",
    "CVE-2022-45791",
]

for cve_id in targets:
    path = history_dir / f"{cve_id}.json"

    if not path.exists():
        print(f"\n{cve_id}: history file not found")
        continue

    history = json.loads(path.read_text(encoding="utf-8"))
    types = Counter()
    actions = Counter()

    for item in history.get("cveChanges", []):
        change = item.get("change", {})
        for detail in change.get("details", []):
            types[str(detail.get("type", "<missing>"))] += 1
            actions[str(detail.get("action", "<missing>"))] += 1

    print(f"\n--- {cve_id} ---")
    print("Event types:", dict(types))
    print("Actions:", dict(actions))
