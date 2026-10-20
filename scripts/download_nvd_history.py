"""Download NVD CVE change histories with retry and resume support."""

import argparse
import email.utils
import gzip
import hashlib
import json
import os
import random
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

NVD_HISTORY_URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = PROJECT_ROOT / "data/raw/nvd"
DEFAULT_OUTPUT = PROJECT_ROOT / "data/raw/nvd/history"
DEFAULT_ENV = PROJECT_ROOT / ".env"

# Research period: 2016-01-01 through 2026-10-14 inclusive, UTC.
START_DATE = datetime(2016, 1, 1, tzinfo=UTC)
END_DATE_EXCLUSIVE = datetime(2026, 10, 15, tzinfo=UTC)
HISTORY_PAGE_SIZE = 5000
NVD_REQUESTS_PER_WINDOW = 5
NVD_REQUEST_WINDOW_SECONDS = 30.0
NVD_KEYED_REQUESTS_PER_WINDOW = 50
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


class RequestBudgetExceeded(RuntimeError):
    """Raised before sending a request that would exceed the run-wide ceiling."""


class RequestBudget:
    """Thread-safe global budget for page requests, including retries."""

    def __init__(self, maximum: int | None):
        if maximum is not None and maximum < 1:
            raise ValueError("--max-page-requests must be at least 1")
        self.maximum = maximum
        self.used = 0
        self._lock = threading.Lock()

    def reserve(self) -> None:
        with self._lock:
            if self.maximum is not None and self.used >= self.maximum:
                raise RequestBudgetExceeded(f"Global page-request ceiling reached ({self.maximum})")
            self.used += 1


class DurableRequestBudget:
    """SQLite-backed request ceiling shared by standard-runner invocations."""

    def __init__(
        self,
        ledger_path: Path,
        maximum: int | None,
        request_ledger_path: Path | None = None,
    ):
        if maximum is not None and maximum < 1:
            raise ValueError("--max-page-requests must be at least 1")
        ledger_entries = (
            read_request_ledger(request_ledger_path) if request_ledger_path is not None else []
        )
        self.ledger_path = ledger_path
        self.context = "unknown"
        self.connection = sqlite3.connect(ledger_path, timeout=30)
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS reservations ("
            "request_id INTEGER PRIMARY KEY AUTOINCREMENT, reserved_at_utc TEXT NOT NULL, "
            "context TEXT NOT NULL)"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        existing = self.connection.execute(
            "SELECT value FROM config WHERE key='maximum'"
        ).fetchone()
        if existing is not None:
            configured_maximum = int(existing[0])
            if maximum is not None and configured_maximum != maximum:
                self.connection.close()
                raise ValueError(
                    "request ceiling cannot change when resuming this output directory"
                )
            maximum = configured_maximum
        elif maximum is None:
            self.connection.close()
            raise ValueError("durable request budget has no configured ceiling")
        else:
            self.connection.execute(
                "INSERT INTO config(key, value) VALUES('maximum', ?)", (str(maximum),)
            )
        self.maximum = maximum
        if existing is None and request_ledger_path is not None and request_ledger_path.is_file():
            prior_starts = sum(entry["event"] == "request_started" for entry in ledger_entries)
            for _ in range(prior_starts):
                self.connection.execute(
                    "INSERT INTO reservations(reserved_at_utc, context) VALUES(?, ?)",
                    (datetime.now(UTC).isoformat(), "preexisting-request-ledger"),
                )
        self.connection.commit()

    @property
    def used(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM reservations").fetchone()[0])

    def reserve(self) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        used = self.used
        if used >= self.maximum:
            self.connection.rollback()
            raise RequestBudgetExceeded(f"Durable page-request ceiling reached ({self.maximum})")
        self.connection.execute(
            "INSERT INTO reservations(reserved_at_utc, context) VALUES(?, ?)",
            (datetime.now(UTC).isoformat(), self.context),
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()


class RunDirectoryLock:
    """Exclusive cross-process lock for all writers targeting one run directory.

    The lock is created atomically with O_EXCL. A process killed without cleanup
    leaves a stale lock; it is never removed automatically because doing so could
    admit a second writer while the first process is merely delayed.
    """

    def __init__(self, output_dir: Path):
        self.path = output_dir / ".collection.lock"
        self.token = uuid.uuid4().hex
        self.acquired = False

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"pid": os.getpid(), "token": self.token})
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as error:
            raise RuntimeError(
                f"Collection run is locked by {self.path}; inspect the recorded PID and "
                "remove the lock only after confirming that process is no longer running"
            ) from error
        self.acquired = True
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass
            self.acquired = False
            raise
        return self

    def __exit__(self, *_exc):
        if self.acquired:
            try:
                owner = json.loads(self.path.read_text(encoding="utf-8"))
                if owner.get("token") == self.token:
                    self.path.unlink()
            except FileNotFoundError:
                pass
            self.acquired = False


class RequestRateLimiter:
    """Serialize request starts at the documented NVD rate limit."""

    def __init__(self, api_key: str | None, clock=time.monotonic, sleep=time.sleep):
        requests = NVD_KEYED_REQUESTS_PER_WINDOW if api_key else NVD_REQUESTS_PER_WINDOW
        self.interval = NVD_REQUEST_WINDOW_SECONDS / requests
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next_request_at = 0.0

    def acquire(self) -> None:
        with self._lock:
            now = self._clock()
            wait = max(0.0, self._next_request_at - now)
            self._next_request_at = max(now, self._next_request_at) + self.interval
        if wait:
            self._sleep(wait)

    def defer(self, seconds: float) -> None:
        """Apply Retry-After/backoff to every subsequent request via shared state."""
        with self._lock:
            self._next_request_at = max(self._next_request_at, self._clock() + max(0.0, seconds))


_RATE_LIMITERS: dict[bool, RequestRateLimiter] = {}
_RATE_LIMITERS_LOCK = threading.Lock()


def _shared_limiter(api_key: str | None) -> RequestRateLimiter:
    keyed = bool(api_key)
    with _RATE_LIMITERS_LOCK:
        if keyed not in _RATE_LIMITERS:
            _RATE_LIMITERS[keyed] = RequestRateLimiter(api_key)
        return _RATE_LIMITERS[keyed]


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


def parse_timestamp(value: Any) -> datetime | None:
    """Parse a timestamp and normalize it to UTC, assuming UTC if offset is absent.

    NVD history event strings without an offset are retained verbatim in the raw
    response. The UTC interpretation is a project normalization assumption, not
    an NVD-documented timezone guarantee.
    """
    if not isinstance(value, str) or not value.strip():
        return None

    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    return parsed.astimezone(UTC)


def timestamp_timezone_status(value: Any) -> str:
    """Describe timestamp timezone evidence without changing the source string."""
    parsed = parse_timestamp(value)
    if parsed is None:
        return "invalid"
    if not isinstance(value, str):
        return "invalid"
    normalized = value.strip()
    if normalized.endswith("Z") or "+" in normalized[10:] or "-" in normalized[10:]:
        return "explicit_offset"
    return "naive_assumed_utc"


def load_cve_ids(input_path: Path) -> list[str]:
    """Read unique CVE IDs published within the research period."""
    cve_ids: set[str] = set()

    if input_path.is_dir():
        input_files = sorted(input_path.glob("nvd_*.json.gz"))
        if not input_files:
            raise ValueError(f"No monthly NVD files found in {input_path}")
    elif input_path.is_file():
        input_files = [input_path]
    else:
        raise FileNotFoundError(f"Input path not found: {input_path}")

    for path in input_files:
        with gzip.open(path, "rt", encoding="utf-8") as file:
            data = json.load(file)

        records = data.get("vulnerabilities")
        if not isinstance(records, list):
            raise ValueError(f"Input dataset {path} must contain a vulnerabilities list")

        for record in records:
            if not isinstance(record, dict):
                continue

            cve = record.get("cve")
            if not isinstance(cve, dict):
                continue

            cve_id = cve.get("id")
            published = parse_timestamp(cve.get("published"))

            if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
                continue

            if published is None:
                continue

            if START_DATE <= published < END_DATE_EXCLUSIVE:
                cve_ids.add(cve_id)

    return sorted(cve_ids)


def load_saved_history(path: Path) -> dict[str, Any] | None:
    """Return a complete, structurally valid saved response, or None."""
    if not path.is_file():
        return None

    try:
        with path.open("r", encoding="utf-8") as file:
            history = json.load(file)

        if isinstance(history, dict):
            _validate_aggregated_history(history, path.stem)
            return history
    except (OSError, json.JSONDecodeError, ValueError):
        pass

    return None


def _validate_history_page(
    page: Any,
    changes: Any,
    expected_start: int,
    expected_total: int | None,
    cve_id: str | None = None,
) -> tuple[int, int]:
    """Validate NVD page metadata, event structure, and any available identity."""
    if not isinstance(page, dict) or not isinstance(changes, list):
        raise ValueError("NVD returned an invalid history response structure")
    if page.get("format") != "NVD_CVEHistory" or page.get("version") != "2.0":
        raise ValueError("NVD history response has an unexpected format or version")
    if parse_timestamp(page.get("timestamp")) is None:
        raise ValueError("NVD history response has an invalid timestamp")

    metadata = ("resultsPerPage", "startIndex", "totalResults")
    if any(type(page.get(key)) is not int for key in metadata):
        raise ValueError("NVD history response is missing integer pagination metadata")

    results_per_page = page["resultsPerPage"]
    start_index = page["startIndex"]
    total_results = page["totalResults"]
    if min(results_per_page, start_index, total_results) < 0:
        raise ValueError("NVD history response contains negative pagination metadata")
    if results_per_page > HISTORY_PAGE_SIZE:
        raise ValueError("NVD history response exceeds the 5,000-event page limit")
    if start_index != expected_start:
        raise ValueError(f"NVD history page starts at {start_index}; expected {expected_start}")
    if expected_total is not None and total_results != expected_total:
        raise ValueError("NVD history totalResults changed during pagination")
    if results_per_page != len(changes):
        raise ValueError("NVD history resultsPerPage does not match cveChanges length")
    if start_index + results_per_page > total_results:
        raise ValueError("NVD history page extends beyond totalResults")
    if total_results > start_index and results_per_page == 0:
        raise ValueError("NVD history pagination made no progress")
    if results_per_page != min(HISTORY_PAGE_SIZE, total_results - start_index):
        raise ValueError("NVD history page size is inconsistent with totalResults")
    if total_results == 0 and (start_index != 0 or results_per_page != 0):
        raise ValueError("NVD empty history has inconsistent pagination metadata")

    for item in changes:
        if not isinstance(item, dict) or not isinstance(item.get("change"), dict):
            raise ValueError("NVD history contains a malformed change record")
        change = item["change"]
        if not isinstance(change.get("cveId"), str) or not CVE_ID_PATTERN.fullmatch(
            change["cveId"]
        ):
            raise ValueError("NVD history change record has no valid CVE identity")
        if cve_id is not None and change["cveId"] != cve_id:
            raise ValueError(f"NVD returned history for {change['cveId']}, expected {cve_id}")
        if not isinstance(change.get("created"), str) or parse_timestamp(change["created"]) is None:
            raise ValueError("NVD history change record has an invalid created timestamp")
        if not isinstance(change.get("details"), list) or any(
            not isinstance(detail, dict) for detail in change["details"]
        ):
            raise ValueError("NVD history change record has malformed details")

    event_ids = [item["change"].get("cveChangeId") for item in changes]
    if any(not isinstance(event_id, str) or not event_id for event_id in event_ids):
        raise ValueError("NVD history change record has no cveChangeId")
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("NVD history page contains duplicate cveChangeId values")

    return results_per_page, total_results


def _validate_aggregated_history(history: Any, cve_id: str | None = None) -> int:
    """Validate a saved NVD-shaped aggregate, including histories over 5,000 events."""
    if not isinstance(cve_id, str) or not CVE_ID_PATTERN.fullmatch(cve_id):
        raise ValueError("Saved history requires a valid expected CVE ID")
    if not isinstance(history, dict) or not isinstance(history.get("cveChanges"), list):
        raise ValueError("Saved aggregate has an invalid response structure")
    changes = history["cveChanges"]
    if len(changes) <= HISTORY_PAGE_SIZE:
        _validate_history_page(history, changes, 0, None, cve_id)
        if history["totalResults"] != len(changes):
            raise ValueError("Saved history response is incomplete")
        return len(changes)
    if history.get("format") != "NVD_CVEHistory" or history.get("version") != "2.0":
        raise ValueError("Saved aggregate has an unexpected format or version")
    if parse_timestamp(history.get("timestamp")) is None:
        raise ValueError("Saved aggregate has an invalid timestamp")
    if (
        type(history.get("startIndex")) is not int
        or history["startIndex"] != 0
        or history.get("resultsPerPage") != len(changes)
        or history.get("totalResults") != len(changes)
    ):
        raise ValueError("Saved aggregate has inconsistent event counts")
    pagination = history.get("vesperPagination")
    if pagination is not None:
        if not isinstance(pagination, dict):
            raise ValueError("Saved aggregate has invalid legacy pagination metadata")
        if (
            pagination.get("page_size") != HISTORY_PAGE_SIZE
            or type(pagination.get("page_count")) is not int
            or pagination.get("source_total_results") != len(changes)
        ):
            raise ValueError("Saved aggregate has invalid legacy pagination metadata")
        expected_pages = max(1, (len(changes) + HISTORY_PAGE_SIZE - 1) // HISTORY_PAGE_SIZE)
        if pagination["page_count"] != expected_pages:
            raise ValueError("Saved aggregate page count does not match its events")
    event_ids: set[str] = set()
    for item in changes:
        if not isinstance(item, dict) or not isinstance(item.get("change"), dict):
            raise ValueError("Saved aggregate contains a malformed change record")
        change = item["change"]
        if not isinstance(cve_id, str) or not CVE_ID_PATTERN.fullmatch(cve_id):
            raise ValueError("Saved aggregate has no valid expected CVE ID")
        if change.get("cveId") != cve_id:
            raise ValueError("Saved aggregate contains an unexpected CVE ID")
        event_id = change.get("cveChangeId")
        if not isinstance(event_id, str) or not event_id or event_id in event_ids:
            raise ValueError("Saved aggregate contains duplicate or missing event IDs")
        event_ids.add(event_id)
        if (
            parse_timestamp(change.get("created")) is None
            or not isinstance(change.get("details"), list)
            or any(not isinstance(detail, dict) for detail in change["details"])
        ):
            raise ValueError("Saved aggregate contains malformed event data")
    return len(changes)


def has_complete_raw_provenance(
    history: dict[str, Any], cve_id: str, attempts: list[dict[str, Any]]
) -> bool:
    """Verify ledger hashes and raw NVD pages fully reproduce the saved history."""
    if (
        not isinstance(attempts, list)
        or not attempts
        or any(not isinstance(attempt, dict) for attempt in attempts)
    ):
        return False
    raw_pages: dict[int, list[tuple[str, dict[str, Any]]]] = {}
    for attempt in attempts:
        if attempt.get("cve_id") != cve_id or attempt.get("source_endpoint") != NVD_HISTORY_URL:
            return False
        if type(attempt.get("start_index")) is not int:
            return False
        if attempt.get("event") == "request_started":
            continue
        if attempt.get("event") != "request_completed":
            return False
        path_value = attempt.get("raw_response_path")
        if not isinstance(path_value, str) or not path_value:
            return False
        raw_path = Path(path_value)
        try:
            body = raw_path.read_bytes()
        except OSError:
            return False
        if (
            type(attempt.get("http_status")) is not int
            or attempt.get("response_bytes") != len(body)
            or attempt.get("response_sha256") != hashlib.sha256(body).hexdigest()
        ):
            return False
        if attempt["http_status"] != 200:
            continue
        try:
            page = json.loads(body)
            changes = page["cveChanges"]
            _validate_history_page(page, changes, attempt["start_index"], None, cve_id)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            # A 200 response that failed page validation may be a retry attempt.
            continue
        raw_pages.setdefault(attempt["start_index"], []).append(
            (hashlib.sha256(body).hexdigest(), page)
        )

    first_candidates = raw_pages.get(0, [])
    if not first_candidates:
        return False
    hashes = {digest for digest, _ in first_candidates}
    if len(hashes) != 1:
        return False
    first_page = first_candidates[0][1]
    expected_total = first_page["totalResults"]
    combined: list[dict[str, Any]] = []
    expected_index = 0
    while True:
        candidates = raw_pages.get(expected_index, [])
        if not candidates or len({digest for digest, _ in candidates}) != 1:
            return False
        page = candidates[0][1]
        try:
            _validate_history_page(page, page["cveChanges"], expected_index, expected_total, cve_id)
        except (KeyError, TypeError, ValueError):
            return False
        combined.extend(page["cveChanges"])
        if expected_total == 0 or expected_index + len(page["cveChanges"]) == expected_total:
            break
        if not page["cveChanges"]:
            return False
        expected_index += len(page["cveChanges"])

    expected_starts = set(range(0, expected_total, HISTORY_PAGE_SIZE)) or {0}
    return (
        set(raw_pages) == expected_starts
        and history.get("totalResults") == expected_total
        and history.get("cveChanges") == combined
    )


def _retry_after_seconds(value: str | None) -> float:
    """Parse Retry-After as either delay-seconds or an HTTP date."""
    if not value:
        return 0.0
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            retry_at = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError, OverflowError):
            return 0.0
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        return max(0.0, (retry_at - datetime.now(UTC)).total_seconds())


def _append_jsonl(path: Path, item: dict[str, Any]) -> None:
    """Append and flush a request-ledger event before proceeding."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as log:
        log.write(json.dumps(item, sort_keys=True, ensure_ascii=False) + "\n")
        log.flush()
        os.fsync(log.fileno())


def read_request_ledger(path: Path) -> list[dict[str, Any]]:
    """Read and validate every ledger record; never repair malformed evidence."""
    if not path.is_file():
        return []
    entries: list[dict[str, Any]] = []
    starts_by_id: dict[str, dict[str, Any]] = {}
    completed_ids: set[str] = set()
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            raise ValueError(f"Malformed request ledger {path} at line {line_number}: blank record")
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as error:
            suffix = (
                " (truncated final record; preserve it for manual recovery)"
                if line_number == len(lines) and not line.endswith(("\n", "\r"))
                else ""
            )
            raise ValueError(
                f"Malformed request ledger {path} at line {line_number}{suffix}: {error}"
            ) from error
        if not isinstance(entry, dict) or not isinstance(entry.get("event"), str):
            raise ValueError(
                f"Malformed request ledger {path} at line {line_number}: expected event object"
            )
        if entry.get("event") not in {"request_started", "request_completed"}:
            raise ValueError(
                f"Malformed request ledger {path} at line {line_number}: unknown event"
            )
        if not isinstance(entry.get("request_id"), str) or not isinstance(entry.get("cve_id"), str):
            raise ValueError(
                f"Malformed request ledger {path} at line {line_number}: missing request identity"
            )
        if (
            not entry["request_id"]
            or not CVE_ID_PATTERN.fullmatch(entry["cve_id"])
            or entry.get("source_endpoint") != NVD_HISTORY_URL
            or type(entry.get("start_index")) is not int
            or entry["start_index"] < 0
            or type(entry.get("attempt")) is not int
            or entry["attempt"] < 1
            or type(entry.get("is_retry")) is not bool
            or parse_timestamp(entry.get("request_started_at_utc")) is None
        ):
            raise ValueError(
                f"Malformed request ledger {path} at line {line_number}: invalid request metadata"
            )
        request_id = entry["request_id"]
        if entry["event"] == "request_started":
            if request_id in starts_by_id:
                raise ValueError(
                    f"Malformed request ledger {path} at line {line_number}: "
                    f"duplicate request_started for {request_id}"
                )
            starts_by_id[request_id] = entry
        else:
            if (
                parse_timestamp(entry.get("request_ended_at_utc")) is None
                or (
                    entry.get("http_status") is not None
                    and type(entry.get("http_status")) is not int
                )
                or type(entry.get("response_bytes")) is not int
                or entry["response_bytes"] < 0
                or not isinstance(entry.get("response_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", entry["response_sha256"])
                or not isinstance(entry.get("raw_response_path"), str)
            ):
                raise ValueError(
                    f"Malformed request ledger {path} at line {line_number}: "
                    "invalid response metadata"
                )
            started = starts_by_id.get(request_id)
            if started is None:
                raise ValueError(
                    f"Malformed request ledger {path} at line {line_number}: "
                    f"request_completed without request_started for {request_id}"
                )
            if request_id in completed_ids:
                raise ValueError(
                    f"Malformed request ledger {path} at line {line_number}: "
                    f"duplicate request_completed for {request_id}"
                )
            identity_fields = (
                "cve_id",
                "source_endpoint",
                "start_index",
                "attempt",
                "is_retry",
                "request_started_at_utc",
            )
            if any(entry.get(key) != started.get(key) for key in identity_fields):
                raise ValueError(
                    f"Malformed request ledger {path} at line {line_number}: "
                    f"request identity changed for {request_id}"
                )
            completed_ids.add(request_id)
        entries.append(entry)
    return entries


def request_attempts_from_ledger(path: Path, cve_id: str) -> list[dict[str, Any]]:
    """Return durable request start/completion records for one CVE, including
    reservations interrupted before a response was recorded.
    """
    attempts_by_id: dict[str, dict[str, Any]] = {}
    for entry in read_request_ledger(path):
        if entry.get("cve_id") == cve_id:
            attempts_by_id.setdefault(entry["request_id"], {}).update(entry)
    return sorted(attempts_by_id.values(), key=lambda item: item.get("request_started_at_utc", ""))


def _save_raw_body(path: Path, body: bytes) -> None:
    """Create a byte-exact response file without replacing existing evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    try:
        with temporary.open("xb") as raw_file:
            raw_file.write(body)
            raw_file.flush()
            os.fsync(raw_file.fileno())
        os.link(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def fetch_history_page(
    cve_id: str,
    api_key: str | None,
    start_index: int,
    timeout: int = 30,
    max_attempts: int = 6,
    metrics: dict[str, int] | None = None,
    limiter: RequestRateLimiter | None = None,
    request_budget: RequestBudget | None = None,
    *,
    raw_response_dir: Path | None = None,
    request_ledger_path: Path | None = None,
    page_captures: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Fetch one history page with retries and page-level validation."""
    query = urllib.parse.urlencode(
        {"cveId": cve_id, "resultsPerPage": HISTORY_PAGE_SIZE, "startIndex": start_index}
    )
    url = f"{NVD_HISTORY_URL}?{query}"

    headers = {"User-Agent": "VESPER research project"}
    if api_key:
        headers["apiKey"] = api_key
    limiter = limiter or _shared_limiter(api_key)

    for attempt in range(max_attempts):
        limiter.acquire()
        if request_budget is not None:
            request_budget.reserve()
        if metrics is not None:
            if attempt > 0:
                metrics["retries"] = metrics.get("retries", 0) + 1
            metrics["page_requests"] = metrics.get("page_requests", 0) + 1
        request = urllib.request.Request(url, headers=headers)
        request_id = f"{cve_id}:{start_index}:{attempt + 1}:{time.time_ns()}"
        request_started = datetime.now(UTC)
        request_metadata = {
            "request_id": request_id,
            "cve_id": cve_id,
            "source_endpoint": NVD_HISTORY_URL,
            "start_index": start_index,
            "attempt": attempt + 1,
            "is_retry": attempt > 0,
            "request_started_at_utc": request_started.isoformat(),
        }
        if request_ledger_path is not None:
            _append_jsonl(request_ledger_path, {"event": "request_started", **request_metadata})

        def record_response(
            body: bytes,
            status: int | None,
            error_type: str | None = None,
            *,
            request_id: str = request_id,
            attempt: int = attempt,
            request_metadata: dict[str, Any] = request_metadata,
        ) -> None:
            ended = datetime.now(UTC)
            raw_path = None
            if raw_response_dir is not None:
                raw_path = (
                    raw_response_dir
                    / cve_id
                    / (
                        f"page_{start_index:08d}_attempt_{attempt + 1}_"
                        f"{request_id.rsplit(':', 1)[-1]}.body"
                    )
                )
                _save_raw_body(raw_path, body)
            capture = {
                **request_metadata,
                "request_ended_at_utc": ended.isoformat(),
                "http_status": status,
                "response_bytes": len(body),
                "response_sha256": hashlib.sha256(body).hexdigest(),
                "raw_response_path": str(raw_path) if raw_path else "",
                "error_type": error_type or "",
            }
            if page_captures is not None:
                page_captures.append(capture)
            if request_ledger_path is not None:
                _append_jsonl(request_ledger_path, {"event": "request_completed", **capture})

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw_body = response.read()
                status = getattr(response, "status", None)
                if status is None:
                    status = response.getcode() if hasattr(response, "getcode") else 200
            record_response(raw_body, status)
            result = json.loads(raw_body)

            _validate_history_page(
                result,
                result.get("cveChanges") if isinstance(result, dict) else None,
                start_index,
                None,
                cve_id,
            )

            return result

        except urllib.error.HTTPError as exc:
            error_body = exc.read()
            record_response(error_body, exc.code, type(exc).__name__)
            if exc.code == 404:
                raise RuntimeError(f"NVD returned HTTP 404 for {cve_id}") from exc

            if exc.code not in (408, 429, 500, 502, 503, 504):
                raise RuntimeError(f"NVD returned HTTP {exc.code} for {cve_id}") from exc

            if attempt == max_attempts - 1:
                raise RuntimeError(f"NVD retries exhausted for {cve_id} (HTTP {exc.code})") from exc

            retry_after = _retry_after_seconds(exc.headers.get("Retry-After"))
            delay = max(retry_after, min(60, 2**attempt + random.random()))

            print(f"Retryable HTTP {exc.code} for {cve_id}; retrying in {delay:.1f}s")
            limiter.defer(delay)

        except (
            urllib.error.URLError,
            TimeoutError,
            json.JSONDecodeError,
            UnicodeDecodeError,
            ValueError,
        ) as exc:
            # urlopen failures have no response body; a response-body decoding or
            # validation failure has already been captured above.
            if isinstance(exc, (urllib.error.URLError, TimeoutError)):
                record_response(b"", None, type(exc).__name__)
            if attempt == max_attempts - 1:
                raise RuntimeError(
                    f"Network/JSON retries exhausted for {cve_id}: {type(exc).__name__}"
                ) from exc

            delay = min(60, 2**attempt + random.random())
            print(f"Temporary error for {cve_id}; retrying in {delay:.1f}s")
            limiter.defer(delay)

    raise RuntimeError(f"Unable to fetch history for {cve_id}")


def fetch_history(
    cve_id: str,
    api_key: str | None,
    timeout: int = 30,
    max_attempts: int = 6,
    metrics: dict[str, int] | None = None,
    limiter: RequestRateLimiter | None = None,
    request_budget: RequestBudget | None = None,
    *,
    raw_response_dir: Path | None = None,
    request_ledger_path: Path | None = None,
    page_captures: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Fetch and validate every page for one CVE history response."""
    limiter = limiter or _shared_limiter(api_key)
    first = fetch_history_page(
        cve_id,
        api_key,
        0,
        timeout,
        max_attempts,
        metrics,
        limiter,
        request_budget,
        raw_response_dir=raw_response_dir,
        request_ledger_path=request_ledger_path,
        page_captures=page_captures,
    )
    first_changes = first["cveChanges"]
    page_size, total_results = _validate_history_page(first, first_changes, 0, None, cve_id)
    all_changes = list(first_changes)
    event_ids = {item["change"]["cveChangeId"] for item in all_changes}
    next_index = page_size

    while next_index < total_results:
        page = fetch_history_page(
            cve_id,
            api_key,
            next_index,
            timeout,
            max_attempts,
            metrics,
            limiter,
            request_budget,
            raw_response_dir=raw_response_dir,
            request_ledger_path=request_ledger_path,
            page_captures=page_captures,
        )
        changes = page["cveChanges"]
        page_count, _ = _validate_history_page(page, changes, next_index, total_results, cve_id)
        if page_count == 0:
            raise ValueError("NVD history pagination made no progress")
        page_ids = [item["change"]["cveChangeId"] for item in changes]
        if event_ids.intersection(page_ids):
            raise ValueError("NVD history pagination returned duplicate events")
        event_ids.update(page_ids)
        all_changes.extend(changes)
        next_index += page_count

    if len(all_changes) != total_results:
        raise ValueError("NVD history pagination did not retrieve totalResults events")

    # Store an NVD-shaped aggregate; VESPER provenance is written separately.
    complete = dict(first)
    complete.update(
        resultsPerPage=len(all_changes),
        startIndex=0,
        totalResults=total_results,
        cveChanges=all_changes,
    )
    _validate_aggregated_history(complete, cve_id)
    return complete


def save_history(path: Path, history: dict[str, Any]) -> None:
    """Atomically create a validated history file without replacing existing data."""
    _validate_aggregated_history(history, path.stem)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(".json.tmp")

    try:
        temporary_path.write_text(
            json.dumps(history, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        # A hard link publishes the complete temporary file atomically and fails
        # when a destination already exists, preserving valid or invalid evidence.
        os.link(temporary_path, path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def count_valid_histories(
    cve_ids: list[str],
    output_dir: Path,
) -> int:
    """Count saved histories with both a valid response and complete provenance."""
    return sum(is_complete_capture(output_dir, cve_id) for cve_id in cve_ids)


def is_complete_capture(output_dir: Path, cve_id: str) -> bool:
    """Require a valid history and a sidecar that is not marked incomplete."""
    history = load_saved_history(output_dir / f"{cve_id}.json")
    if history is None:
        return False
    sidecar_path = output_dir / "request_metadata" / f"{cve_id}.json"
    if not sidecar_path.is_file():
        return False
    try:
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(sidecar, dict):
        return False
    return (
        sidecar.get("retrieval_disposition") == "valid_response"
        and sidecar.get("provenance_status") in {None, "complete", "reconciled"}
        and has_complete_raw_provenance(history, cve_id, sidecar.get("request_attempts", []))
    )


def reconcile_saved_history(
    history_path: Path, metadata_path: Path, ledger_path: Path, cve_id: str
) -> dict[str, Any] | None:
    """Create a missing sidecar from matching complete ledger evidence, or mark incomplete."""
    history = load_saved_history(history_path)
    if history is None:
        return None
    if metadata_path.exists():
        return json.loads(metadata_path.read_text(encoding="utf-8"))
    attempts = request_attempts_from_ledger(ledger_path, cve_id)
    confident = has_complete_raw_provenance(history, cve_id, attempts)
    timestamps = [item["change"]["created"] for item in history["cveChanges"]]
    sidecar = {
        "cve_id": cve_id,
        "retrieval_disposition": "valid_response" if confident else "incomplete_provenance",
        "provenance_status": "reconciled" if confident else "incomplete",
        "source_endpoint": NVD_HISTORY_URL,
        "request_attempts": attempts,
        "page_request_count": len({item.get("start_index") for item in attempts}),
        "http_request_attempt_count": len(attempts),
        "retry_count": sum(bool(item.get("is_retry")) for item in attempts),
        "request_started_at_utc": min(
            (item.get("request_started_at_utc", "") for item in attempts), default=""
        ),
        "request_ended_at_utc": max(
            (item.get("request_ended_at_utc", "") for item in attempts), default=""
        ),
        "http_statuses": [item.get("http_status") for item in attempts],
        "unresolved_request_attempts": sum(
            item.get("event") == "request_started" for item in attempts
        ),
        "event_count": len(timestamps),
        "event_timestamp_timezone_policy": {
            "original_strings_preserved_in_raw_response": confident,
            "naive_event_timestamp_count": sum(
                timestamp_timezone_status(value) == "naive_assumed_utc" for value in timestamps
            ),
            "explicit_offset_event_timestamp_count": sum(
                timestamp_timezone_status(value) == "explicit_offset" for value in timestamps
            ),
            "normalization": "Naive event timestamps are interpreted as UTC by project code.",
            "documentation_status": (
                "NVD documentation reviewed; no explicit timezone guarantee found for naive "
                "CVE history event timestamps. This is an unverified project assumption."
            ),
        },
    }
    temporary = metadata_path.with_suffix(".json.tmp")
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    temporary.write_text(json.dumps(sidecar, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, metadata_path)
    return sidecar


def _download_histories_impl(
    input_path: Path,
    output_dir: Path,
    env_path: Path,
    limit: int | None,
    request_budget: RequestBudget | DurableRequestBudget,
) -> None:
    """Download missing histories for CVEs published within the study period."""
    if limit is not None and limit < 1:
        raise ValueError("--limit must be at least 1")
    load_env_file(env_path)
    api_key = os.environ.get("NVD_API_KEY")

    cve_ids = load_cve_ids(input_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    request_ledger_path = output_dir / "request_ledger.jsonl"
    read_request_ledger(request_ledger_path)

    # A saved response is a completed capture only when its provenance sidecar
    # is present. Rebuild sidecars from complete ledger evidence where possible.
    for cve_id in cve_ids:
        history_path = output_dir / f"{cve_id}.json"
        metadata_path = output_dir / "request_metadata" / f"{cve_id}.json"
        if load_saved_history(history_path) is None or metadata_path.exists():
            continue
        reconcile_saved_history(history_path, metadata_path, request_ledger_path, cve_id)

    completed_set = {cve_id for cve_id in cve_ids if is_complete_capture(output_dir, cve_id)}
    invalid_existing = []
    for cve_id in cve_ids:
        history_path = output_dir / f"{cve_id}.json"
        if history_path.exists() and cve_id not in completed_set:
            error = (
                "existing history has incomplete or unverified provenance; preserved"
                if load_saved_history(history_path) is not None
                else "existing history file is invalid; preserved"
            )
            invalid_existing.append({"cve_id": cve_id, "error": error})
    pending = [
        cve_id
        for cve_id in cve_ids
        if cve_id not in completed_set and not (output_dir / f"{cve_id}.json").exists()
    ]

    total_target = len(cve_ids)
    initial_completed = len(completed_set)

    if limit is not None:
        pending = pending[:limit]

    print(
        f"Research period: {START_DATE.isoformat()} to {END_DATE_EXCLUSIVE.isoformat()} (exclusive)"
    )
    print(
        f"Monthly NVD files available: "
        f"{len(list(input_path.glob('nvd_*.json.gz')) if input_path.is_dir() else [input_path])}"
    )
    print(f"Unique CVEs in target period: {total_target}")
    print(f"Valid history responses already saved: {initial_completed}")
    print(f"Histories to attempt this run: {len(pending)}")
    print(f"API key configured: {'yes' if api_key else 'no'}")
    print(f"Output folder: {output_dir}")

    if not pending:
        if invalid_existing:
            report_path = output_dir / "download_report.json"
            failure_path = output_dir / "download_failures.json"
            report = {
                "target_cve_count": total_target,
                "max_page_requests": request_budget.maximum,
                "page_requests": 0,
                "request_budget_exhausted": (
                    request_budget.maximum is not None
                    and request_budget.used >= request_budget.maximum
                ),
                "request_budget_persistent": isinstance(request_budget, DurableRequestBudget),
                "valid_history_responses_before_run": initial_completed,
                "valid_history_responses_after_run": initial_completed,
                "invalid_existing_files": invalid_existing,
                "failed_this_run": len(invalid_existing),
                "interrupted": False,
                "failures": [],
            }
            temporary = report_path.with_suffix(".json.tmp")
            temporary.write_text(json.dumps(report, indent=2), encoding="utf-8")
            os.replace(temporary, report_path)
            temporary = failure_path.with_suffix(".json.tmp")
            temporary.write_text(json.dumps(invalid_existing, indent=2), encoding="utf-8")
            os.replace(temporary, failure_path)
            print(f"Invalid existing files preserved and reported: {len(invalid_existing)}")
        print("No missing histories to download.")
        return

    limiter = _shared_limiter(api_key)

    successful = 0
    empty_histories = 0
    failed: list[dict[str, str]] = []
    succeeded: list[dict[str, Any]] = []
    page_requests = 0
    retries = 0
    started_at = time.monotonic()
    started_at_utc = datetime.now(UTC)
    report_path = output_dir / "download_report.json"
    failure_path = output_dir / "download_failures.json"
    interrupted = False
    stopped_reason: str | None = None
    attempted = 0
    current_cve_id: str | None = None
    current_request_metrics: dict[str, int] = {}

    def atomic_json(path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        try:
            temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

    raw_response_dir = output_dir / "raw_responses"
    request_metadata_dir = output_dir / "request_metadata"

    def save_request_metadata(
        cve_id: str,
        captures: list[dict[str, Any]],
        disposition: str,
        history: dict[str, Any] | None = None,
    ) -> None:
        recorded_attempts = request_attempts_from_ledger(request_ledger_path, cve_id)
        provenance_complete = history is not None and has_complete_raw_provenance(
            history, cve_id, recorded_attempts
        )
        events = (history or {}).get("cveChanges", [])
        timestamps = [
            item.get("change", {}).get("created")
            for item in events
            if isinstance(item, dict) and isinstance(item.get("change"), dict)
        ]
        metadata = {
            "cve_id": cve_id,
            "retrieval_disposition": (
                "incomplete_provenance"
                if disposition == "valid_response" and not provenance_complete
                else disposition
            ),
            "provenance_status": "complete" if provenance_complete else "incomplete",
            "source_endpoint": NVD_HISTORY_URL,
            "request_attempts": recorded_attempts,
            "page_request_count": len({item.get("start_index") for item in recorded_attempts}),
            "http_request_attempt_count": len(recorded_attempts),
            "retry_count": sum(bool(item.get("is_retry")) for item in recorded_attempts),
            "request_started_at_utc": min(
                (item.get("request_started_at_utc", "") for item in recorded_attempts), default=""
            ),
            "request_ended_at_utc": max(
                (item.get("request_ended_at_utc", "") for item in recorded_attempts), default=""
            ),
            "http_statuses": [item.get("http_status") for item in recorded_attempts],
            "unresolved_request_attempts": sum(
                item.get("event") == "request_started" for item in recorded_attempts
            ),
            "event_count": len(events),
            "event_timestamp_timezone_policy": {
                "original_strings_preserved_in_raw_response": provenance_complete,
                "naive_event_timestamp_count": sum(
                    timestamp_timezone_status(value) == "naive_assumed_utc" for value in timestamps
                ),
                "explicit_offset_event_timestamp_count": sum(
                    timestamp_timezone_status(value) == "explicit_offset" for value in timestamps
                ),
                "normalization": "Naive event timestamps are interpreted as UTC by project code.",
                "documentation_status": (
                    "NVD documentation reviewed; no explicit timezone guarantee found for naive "
                    "CVE history event timestamps. This is an unverified project assumption."
                ),
            },
        }
        atomic_json(request_metadata_dir / f"{cve_id}.json", metadata)

    def checkpoint(include_success_details: bool = False) -> None:
        valid_count = initial_completed + successful
        report = {
            "research_start_utc": START_DATE.isoformat(),
            "research_end_exclusive_utc": END_DATE_EXCLUSIVE.isoformat(),
            "target_cve_count": total_target,
            "run_started_at_utc": started_at_utc.isoformat(),
            "api_key_configured": bool(api_key),
            "attempted_this_run": attempted,
            "page_requests": page_requests,
            "max_page_requests": request_budget.maximum,
            "request_budget_persistent": isinstance(request_budget, DurableRequestBudget),
            "request_budget_ledger": (
                str(request_budget.ledger_path)
                if isinstance(request_budget, DurableRequestBudget)
                else None
            ),
            "request_budget_exhausted": (
                request_budget.maximum is not None and request_budget.used >= request_budget.maximum
            ),
            "stopped_reason": stopped_reason,
            "retries": retries,
            "valid_history_responses_before_run": initial_completed,
            "new_responses_saved": successful,
            "successful_responses": succeeded if include_success_details else [],
            "empty_history_responses_this_run": empty_histories,
            "failed_this_run": len(failed) + len(invalid_existing),
            "invalid_existing_files": invalid_existing,
            "interrupted": interrupted,
            "valid_history_responses_after_run": valid_count,
            "missing_valid_responses_after_run": total_target - valid_count,
            "elapsed_seconds": round(time.monotonic() - started_at, 2),
            "last_processed_cve_id": current_cve_id,
            "failure_log": str(failure_log_path),
        }
        atomic_json(report_path, report)

    failure_log_path = output_dir / "download_failures.jsonl"
    failure_log_path.touch(exist_ok=True)

    def write_failure_report() -> None:
        """Materialize a conventional JSON failure report at run end/interruption."""
        all_failures = invalid_existing + failed
        atomic_json(failure_path, all_failures)

    try:
        for index, cve_id in enumerate(pending, start=1):
            attempted += 1
            current_cve_id = cve_id
            path = output_dir / f"{cve_id}.json"
            request_metrics: dict[str, int] = {}
            current_request_metrics = request_metrics
            page_captures: list[dict[str, Any]] = []

            try:
                history = fetch_history(
                    cve_id,
                    api_key,
                    metrics=request_metrics,
                    limiter=limiter,
                    request_budget=request_budget,
                    raw_response_dir=raw_response_dir,
                    request_ledger_path=request_ledger_path,
                    page_captures=page_captures,
                )
                save_history(path, history)
                save_request_metadata(cve_id, page_captures, "valid_response", history)
                successful += 1
                page_requests += request_metrics.get("page_requests", 0)
                retries += request_metrics.get("retries", 0)

                event_count = len(history["cveChanges"])
                if event_count == 0:
                    empty_histories += 1
                succeeded.append(
                    {
                        "cve_id": cve_id,
                        "event_count": event_count,
                        "page_requests": request_metrics.get("page_requests", 0),
                        "retries": request_metrics.get("retries", 0),
                        "response_kind": "valid_empty" if event_count == 0 else "with_events",
                    }
                )
                print(f"[{index}/{len(pending)}] Saved {cve_id} ({event_count} events)")

            except RequestBudgetExceeded as exc:
                save_request_metadata(cve_id, page_captures, "request_budget_exhausted")
                page_requests += request_metrics.get("page_requests", 0)
                retries += request_metrics.get("retries", 0)
                failed.append(
                    {
                        "cve_id": cve_id,
                        "error": str(exc),
                        "page_requests": request_metrics.get("page_requests", 0),
                        "retries": request_metrics.get("retries", 0),
                    }
                )
                with failure_log_path.open("a", encoding="utf-8") as log_file:
                    log_file.write(json.dumps(failed[-1], ensure_ascii=False) + "\n")
                    log_file.flush()
                interrupted = True
                stopped_reason = "global_page_request_ceiling_reached"
                current_cve_id = None
                checkpoint()
                break
            except (
                RuntimeError,
                OSError,
                ValueError,
                urllib.error.URLError,
            ) as exc:
                save_request_metadata(cve_id, page_captures, "failed_response")
                page_requests += request_metrics.get("page_requests", 0)
                retries += request_metrics.get("retries", 0)
                failed.append(
                    {
                        "cve_id": cve_id,
                        "error": str(exc),
                        "page_requests": request_metrics.get("page_requests", 0),
                        "retries": request_metrics.get("retries", 0),
                    }
                )
                with failure_log_path.open("a", encoding="utf-8") as log_file:
                    log_file.write(json.dumps(failed[-1], ensure_ascii=False) + "\n")
                    log_file.flush()
                print(f"[{index}/{len(pending)}] FAILED {cve_id}: {exc}")
            current_cve_id = None
            checkpoint()
    except KeyboardInterrupt:
        interrupted = True
        stopped_reason = "keyboard_interrupt"
        page_requests += current_request_metrics.get("page_requests", 0)
        retries += current_request_metrics.get("retries", 0)
        if current_cve_id is not None:
            interrupted_failure = {
                "cve_id": current_cve_id,
                "error": "interrupted during request",
            }
            failed.append(interrupted_failure)
            with failure_log_path.open("a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(interrupted_failure, ensure_ascii=False) + "\n")
                log_file.flush()
        checkpoint()
        write_failure_report()
        print("Download interrupted; progress and failures checkpointed.")
        raise

    valid_history_count = count_valid_histories(cve_ids, output_dir)
    elapsed = time.monotonic() - started_at

    print("\nDownload summary")
    print(f"New responses saved: {successful}")
    print(f"Responses with zero events: {empty_histories}")
    print(f"Failed CVEs this run: {len(failed)}")
    print(f"Valid history responses present: {valid_history_count}")
    print(f"CVEs without a valid local response: {total_target - valid_history_count}")
    print(f"Elapsed time: {elapsed:.1f} seconds")

    # Always save a run report so progress remains auditable.
    checkpoint(include_success_details=True)
    write_failure_report()
    print(f"Run report saved to: {report_path}")

    if failed or invalid_existing:
        print(f"Failure details saved to: {failure_path}")


def _download_histories_locked(
    input_path: Path,
    output_dir: Path,
    env_path: Path,
    limit: int | None,
    max_page_requests: int | None,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    budget_path = output_dir / "request_reservations.sqlite3"
    if max_page_requests is not None or budget_path.exists():
        request_budget: RequestBudget | DurableRequestBudget = DurableRequestBudget(
            budget_path,
            max_page_requests,
            output_dir / "request_ledger.jsonl",
        )
        try:
            _download_histories_impl(input_path, output_dir, env_path, limit, request_budget)
        finally:
            request_budget.close()
    else:
        request_budget = RequestBudget(None)
        _download_histories_impl(input_path, output_dir, env_path, limit, request_budget)


def download_histories(
    input_path: Path,
    output_dir: Path,
    env_path: Path,
    limit: int | None = None,
    max_page_requests: int | None = None,
) -> None:
    """Run one exclusive collection against this output directory."""
    with RunDirectoryLock(output_dir):
        _download_histories_locked(input_path, output_dir, env_path, limit, max_page_requests)


def main() -> None:
    """Parse command-line arguments and start the downloader."""
    parser = argparse.ArgumentParser(
        description="Download NVD CVE history responses for the study period."
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
    parser.add_argument(
        "--max-page-requests",
        type=int,
        default=None,
        help="Hard run-wide ceiling for all page requests and retries.",
    )
    args = parser.parse_args()

    try:
        download_histories(
            input_path=args.input,
            output_dir=args.output_dir,
            env_path=args.env_file,
            limit=args.limit,
            max_page_requests=args.max_page_requests,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
