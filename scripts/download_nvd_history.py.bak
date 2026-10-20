"""Download NVD CVE change histories with retry and resume support."""

import argparse
import gzip
import json
import os
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

NVD_HISTORY_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = PROJECT_ROOT / "data/raw/nvd/"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/raw/nvd/history"
DEFAULT_ENV = PROJECT_ROOT / ".env"


def load_env_file(env_path: Path) -> None:
    """Load .env variables without overwriting existing environment values."""
    if not env_path.is_file():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        if key and key not in os.environ:
            os.environ[key] = value


def load_cve_ids(input_path: Path) -> list[str]:
    """Read unique CVE IDs from a gzip NVD file or a directory of monthly files."""
    cve_ids: set[str] = set()

    if input_path.is_dir():
        input_files = sorted(input_path.glob("nvd_*.json.gz"))
        if not input_files:
            raise ValueError(f"No monthly NVD files found in {input_path}")
    else:
        input_files = [input_path]

    for path in input_files:
        with gzip.open(path, "rt", encoding="utf-8") as file:
            data = json.load(file)

        records = data.get("vulnerabilities")
        if not isinstance(records, list):
            raise ValueError(f"Input dataset {path} must contain a vulnerabilities list")

        for record in records:
            if not isinstance(record, dict):
                continue

            cve = record.get("cve", {})
            if not isinstance(cve, dict):
                continue

            cve_id = cve.get("id")
            if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
                cve_ids.add(cve_id)

    return sorted(cve_ids)


def load_saved_history(path: Path) -> dict[str, Any] | None:
    """Return a valid saved history response, or None if it needs fetching."""
    if not path.is_file():
        return None

    try:
        with path.open("r", encoding="utf-8") as file:
            history = json.load(file)

        if isinstance(history, dict) and isinstance(history.get("cveChanges"), list):
            return history

    except (OSError, json.JSONDecodeError):
        pass

    return None


def fetch_history(
    cve_id: str,
    api_key: str | None,
    timeout: int = 30,
    max_attempts: int = 6,
) -> dict[str, Any]:
    """Fetch one NVD history response with retries."""
    query = urllib.parse.urlencode({"cveId": cve_id})
    url = f"{NVD_HISTORY_URL}?{query}"

    headers = {"User-Agent": "VESPER research project"}
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(max_attempts):
        request = urllib.request.Request(url, headers=headers)

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                result = json.load(response)

            if not isinstance(result, dict) or not isinstance(result.get("cveChanges"), list):
                raise ValueError(f"NVD returned an invalid history response for {cve_id}")

            return result

        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise RuntimeError(f"NVD returned HTTP 404 for {cve_id}") from exc

            if exc.code not in (429, 500, 502, 503, 504):
                raise RuntimeError(f"NVD returned HTTP {exc.code} for {cve_id}") from exc

            if attempt == max_attempts - 1:
                raise RuntimeError(f"NVD retries exhausted for {cve_id} (HTTP {exc.code})") from exc

            retry_after = exc.headers.get("Retry-After")
            try:
                delay = float(retry_after) if retry_after else 0
            except ValueError:
                delay = 0

            delay = max(
                delay,
                min(60, 2**attempt + random.random()),
            )

            print(f"Retryable HTTP {exc.code} for {cve_id}; retrying in {delay:.1f}s")
            time.sleep(delay)

        except (
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError,
        ) as exc:
            if attempt == max_attempts - 1:
                raise RuntimeError(
                    f"Network/JSON retries exhausted for {cve_id}: {type(exc).__name__}"
                ) from exc

            delay = min(60, 2**attempt + random.random())
            print(f"Temporary error for {cve_id}; retrying in {delay:.1f}s")
            time.sleep(delay)

    raise RuntimeError(f"Unable to fetch history for {cve_id}")


def save_history(path: Path, history: dict[str, Any]) -> None:
    """Atomically save a history response."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(".json.tmp")

    try:
        temporary_path.write_text(
            json.dumps(history, indent=2),
            encoding="utf-8",
        )
        temporary_path.replace(path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def count_valid_histories(
    cve_ids: list[str],
    output_dir: Path,
) -> int:
    """Count valid saved history files for the supplied CVEs."""
    return sum(load_saved_history(output_dir / f"{cve_id}.json") is not None for cve_id in cve_ids)


def download_histories(
    input_path: Path,
    output_dir: Path,
    env_path: Path,
    limit: int | None = None,
) -> None:
    """Download missing histories and report accurate progress."""
    load_env_file(env_path)
    api_key = os.environ.get("NVD_API_KEY")

    cve_ids = load_cve_ids(input_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    completed = [
        cve_id
        for cve_id in cve_ids
        if load_saved_history(output_dir / f"{cve_id}.json") is not None
    ]
    pending = [cve_id for cve_id in cve_ids if cve_id not in set(completed)]

    if limit is not None:
        if limit < 1:
            raise ValueError("--limit must be at least 1")
        pending = pending[:limit]

    print(f"CVEs in dataset: {len(cve_ids)}")
    print(f"Valid history files already saved: {len(completed)}")
    print(f"Histories to download this run: {len(pending)}")
    print(f"API key configured: {'yes' if api_key else 'no'}")
    print(f"Output folder: {output_dir}")

    if not pending:
        print("No missing histories to download.")
        return

    # Conservative request intervals to reduce rate-limit errors.
    request_interval = 0.7 if api_key else 6.5

    successful = 0
    failed: list[tuple[str, str]] = []

    for index, cve_id in enumerate(pending, start=1):
        path = output_dir / f"{cve_id}.json"

        try:
            history = fetch_history(cve_id, api_key)
            save_history(path, history)
            successful += 1

            print(f"[{index}/{len(pending)}] Saved {cve_id} ({len(history['cveChanges'])} events)")

        except (
            RuntimeError,
            OSError,
            ValueError,
            urllib.error.URLError,
        ) as exc:
            failed.append((cve_id, str(exc)))
            print(f"[{index}/{len(pending)}] FAILED {cve_id}: {exc}")

        if index < len(pending):
            time.sleep(request_interval)

    valid_history_count = count_valid_histories(cve_ids, output_dir)

    print("\nDownload summary")
    print(f"New histories saved: {successful}")
    print(f"Failed CVEs this run: {len(failed)}")
    print(f"Valid history files now present: {valid_history_count}")
    print(f"CVEs still missing valid history: {len(cve_ids) - valid_history_count}")

    if failed:
        failure_path = output_dir / "download_failures.json"
        failure_path.write_text(
            json.dumps(
                [{"cve_id": cve_id, "error": error} for cve_id, error in failed],
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"Failure details saved to: {failure_path}")
        print("Run the downloader again later to retry missing histories.")


def main() -> None:
    """Parse arguments and start the downloader."""
    parser = argparse.ArgumentParser(
        description="Download and cache NVD CVE change-history responses."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV)
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Download at most this many missing histories in this run.",
    )
    args = parser.parse_args()

    download_histories(
        input_path=args.input,
        output_dir=args.output_dir,
        env_path=args.env_file,
        limit=args.limit,
    )


if __name__ == "__main__":
    main()
