"""Select a reproducible sample of CVEs for Component C history validation."""

import gzip
import json
import random
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
NVD_DIR = PROJECT_ROOT / "data" / "raw" / "nvd"
OUTPUT_PATH = PROJECT_ROOT / "data" / "processed" / "c_graph_history_sample_2015_2026.json"

START_YEAR = 2015
END_YEAR = 2026
SAMPLE_PER_YEAR = 20
RANDOM_SEED = 344


def main() -> None:
    by_year: dict[int, dict[str, str]] = defaultdict(dict)

    for path in sorted(NVD_DIR.glob("nvd_*.json.gz")):
        with gzip.open(path, "rt", encoding="utf-8") as file:
            data = json.load(file)

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            published = cve.get("published", "")

            if (
                not isinstance(cve_id, str)
                or not cve_id.startswith("CVE-")
                or not isinstance(published, str)
                or len(published) < 4
            ):
                continue

            try:
                year = int(published[:4])
            except ValueError:
                continue

            if START_YEAR <= year <= END_YEAR:
                by_year[year][cve_id] = published

    rng = random.Random(RANDOM_SEED)
    selected = []

    for year in range(START_YEAR, END_YEAR + 1):
        candidates = sorted(by_year.get(year, {}).items())
        count = min(SAMPLE_PER_YEAR, len(candidates))
        sample = rng.sample(candidates, count)

        for cve_id, published in sorted(sample):
            selected.append({"cve_id": cve_id, "published": published, "year": year})

        print(f"{year}: {count} selected from {len(candidates):,} CVEs")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(
            {
                "description": (
                    "Reproducible validation sample; not a complete "
                    "or statistically powered research dataset."
                ),
                "start_year": START_YEAR,
                "end_year": END_YEAR,
                "sample_per_year": SAMPLE_PER_YEAR,
                "random_seed": RANDOM_SEED,
                "selected_count": len(selected),
                "cves": selected,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    print(f"\nTotal selected: {len(selected)}")
    print(f"Manifest saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
