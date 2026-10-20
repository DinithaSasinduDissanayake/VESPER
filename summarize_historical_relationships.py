
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from vesper.components.c_graph.historical import reconstruct_relationships

history_dir = Path("data/raw/nvd/history")
cutoff = datetime(2025, 1, 1, tzinfo=timezone.utc)

counts = Counter()
total = 0

for path in sorted(history_dir.glob("CVE-*.json")):
    history = json.loads(path.read_text(encoding="utf-8"))
    relationships = reconstruct_relationships(history, cutoff)

    has_products = bool(relationships.affected)
    has_cwes = bool(relationships.cwe_ids)

    if has_products and has_cwes:
        category = "Both products and CWEs"
    elif has_products:
        category = "Products only"
    elif has_cwes:
        category = "CWEs only"
    else:
        category = "Neither products nor CWEs"

    counts[category] += 1
    total += 1

print(f"Total histories processed: {total}")
for category in (
    "Both products and CWEs",
    "Products only",
    "CWEs only",
    "Neither products nor CWEs",
):
    print(f"{category}: {counts[category]}")
