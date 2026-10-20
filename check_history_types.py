
import json
from pathlib import Path
from collections import Counter

folder = Path("data/raw/nvd/history")

for cve in [
    "CVE-2022-29409",
    "CVE-2022-43375",
    "CVE-2022-45791",
]:
    path = folder / f"{cve}.json"
    history = json.loads(path.read_text(encoding="utf-8"))

    details = [
        detail
        for event in history.get("cveChanges", [])
        for detail in event.get("change", {}).get("details", [])
    ]

    print(f"\n--- {cve} ---")
    print("Event types:", dict(Counter(
        detail.get("type", "<missing>") for detail in details
    )))
    print("Actions:", dict(Counter(
        detail.get("action", "<missing>") for detail in details
    )))
