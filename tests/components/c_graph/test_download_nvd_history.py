"""Tests for paginated NVD CVE history collection."""

import gzip
import hashlib
import io
import json
import subprocess
import sys
import urllib.error
import urllib.parse
from datetime import UTC, datetime, timedelta
from email.message import Message
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from scripts import download_nvd_history as downloader


@pytest.fixture(autouse=True)
def no_shared_waits(monkeypatch):
    """Keep network-free downloader tests independent of process-wide pacing."""

    class NoWaitLimiter:
        def acquire(self):
            pass

        def defer(self, _seconds):
            pass

    monkeypatch.setattr(downloader, "_shared_limiter", lambda _api_key: NoWaitLimiter())


def event(cve_id="CVE-2024-12345", index=0):
    return {
        "change": {
            "cveId": cve_id,
            "cveChangeId": f"event-{index}",
            "created": "2024-01-01T00:00:00.000",
            "details": [{"action": "Added", "type": "CWE", "newValue": "CWE-79"}],
        }
    }


def response(changes, start=0, total=None):
    if total is None:
        total = len(changes)
    return {
        "resultsPerPage": len(changes),
        "startIndex": start,
        "totalResults": total,
        "format": "NVD_CVEHistory",
        "version": "2.0",
        "timestamp": "2026-10-15T00:00:00.000",
        "cveChanges": changes,
    }


class JsonResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def api_error(code, retry_after=None):
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return urllib.error.HTTPError(
        "https://services.nvd.nist.gov/rest/json/cvehistory/2.0",
        code,
        "error",
        headers,
        None,
    )


def test_fetches_and_validates_complete_single_page(monkeypatch):
    payload = response([event()])
    seen = []

    def fake_urlopen(request, timeout):
        seen.append((request, timeout))
        return JsonResponse(json.dumps(payload).encode())

    monkeypatch.setattr(downloader.urllib.request, "urlopen", fake_urlopen)

    result = downloader.fetch_history("CVE-2024-12345", "secret-for-test")

    assert result["cveChanges"] == payload["cveChanges"]
    request, timeout = seen[0]
    query = urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)
    assert query["startIndex"] == ["0"]
    assert query["resultsPerPage"] == [str(downloader.HISTORY_PAGE_SIZE)]
    assert any(
        name.casefold() == "apikey" and value == "secret-for-test"
        for name, value in request.header_items()
    )
    assert timeout == 30


def test_saves_exact_raw_response_bytes_and_request_provenance(tmp_path, monkeypatch):
    body = (
        b'{ "format":"NVD_CVEHistory", "version":"2.0", '
        b'"timestamp":"2026-10-15T00:00:00.000", "resultsPerPage":0, '
        b'"startIndex":0, "totalResults":0, "cveChanges":[] }\n'
    )
    monkeypatch.setattr(
        downloader.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: JsonResponse(body),
    )
    captures = []
    ledger = tmp_path / "request_ledger.jsonl"
    result = downloader.fetch_history_page(
        "CVE-2024-12345",
        "secret-must-not-be-logged",
        0,
        raw_response_dir=tmp_path / "raw",
        request_ledger_path=ledger,
        page_captures=captures,
    )

    assert Path(captures[0]["raw_response_path"]).read_bytes() == body
    assert captures[0]["response_sha256"] == hashlib.sha256(body).hexdigest()
    assert captures[0]["http_status"] == 200
    assert captures[0]["request_started_at_utc"] <= captures[0]["request_ended_at_utc"]
    assert result["cveChanges"] == []
    ledger_text = ledger.read_text(encoding="utf-8")
    assert "secret-must-not-be-logged" not in ledger_text
    assert '"event": "request_started"' in ledger_text
    assert '"event": "request_completed"' in ledger_text


def test_preserves_invalid_response_body_before_rejecting(tmp_path, monkeypatch):
    invalid_body = b"{\nnot json\n"
    monkeypatch.setattr(
        downloader.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: JsonResponse(invalid_body),
    )
    captures = []

    with pytest.raises(RuntimeError, match="retries exhausted"):
        downloader.fetch_history_page(
            "CVE-2024-12345",
            None,
            0,
            max_attempts=1,
            raw_response_dir=tmp_path / "raw",
            page_captures=captures,
        )

    assert len(captures) == 1
    assert Path(captures[0]["raw_response_path"]).read_bytes() == invalid_body
    assert captures[0]["http_status"] == 200


def test_timestamp_parser_marks_naive_utc_as_assumption():
    naive = "2024-01-02T03:04:05.123"
    assert downloader.timestamp_timezone_status(naive) == "naive_assumed_utc"
    assert downloader.parse_timestamp(naive) == datetime(2024, 1, 2, 3, 4, 5, 123000, tzinfo=UTC)
    assert downloader.timestamp_timezone_status("2024-01-02T03:04:05Z") == "explicit_offset"
    assert downloader.timestamp_timezone_status("not-a-timestamp") == "invalid"


def test_fetches_all_pages_when_total_exceeds_page_size(monkeypatch):
    monkeypatch.setattr(downloader, "HISTORY_PAGE_SIZE", 2)
    requests = []
    changes = [event(index=i) for i in range(3)]

    def fake_urlopen(request, timeout):
        start = int(
            urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)["startIndex"][0]
        )
        requests.append(start)
        page_changes = changes[start : start + 2]
        return JsonResponse(json.dumps(response(page_changes, start, 3)).encode())

    monkeypatch.setattr(downloader.urllib.request, "urlopen", fake_urlopen)

    result = downloader.fetch_history("CVE-2024-12345", None)

    assert requests == [0, 2]
    assert result["startIndex"] == 0
    assert result["resultsPerPage"] == result["totalResults"] == 3
    assert result["cveChanges"] == changes


def test_global_request_budget_counts_page_requests_and_blocks_next_page(monkeypatch):
    monkeypatch.setattr(downloader, "HISTORY_PAGE_SIZE", 1)
    calls = []
    changes = [event(index=i) for i in range(2)]

    def fake_urlopen(request, timeout):
        start = int(
            urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)["startIndex"][0]
        )
        calls.append(start)
        return JsonResponse(json.dumps(response(changes[start : start + 1], start, 2)).encode())

    monkeypatch.setattr(downloader.urllib.request, "urlopen", fake_urlopen)
    metrics = {}

    with pytest.raises(downloader.RequestBudgetExceeded, match="ceiling reached"):
        downloader.fetch_history(
            "CVE-2024-12345",
            None,
            metrics=metrics,
            request_budget=downloader.RequestBudget(1),
        )

    assert calls == [0]
    assert metrics == {"page_requests": 1}


def test_global_request_budget_includes_retry_attempts(monkeypatch):
    calls = []
    monkeypatch.setattr(
        downloader.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: calls.append(None) or (_ for _ in ()).throw(api_error(429, "0")),
    )
    metrics = {}
    budget = downloader.RequestBudget(1)

    with pytest.raises(downloader.RequestBudgetExceeded, match="ceiling reached"):
        downloader.fetch_history(
            "CVE-2024-12345",
            None,
            max_attempts=3,
            metrics=metrics,
            request_budget=budget,
        )

    assert len(calls) == 1
    assert budget.used == metrics["page_requests"] == 1
    assert metrics.get("retries", 0) == 0


def test_rejects_total_results_change_between_pages(monkeypatch):
    monkeypatch.setattr(downloader, "HISTORY_PAGE_SIZE", 1)
    calls = 0

    def fake_urlopen(_request, **_kwargs):
        nonlocal calls
        calls += 1
        payload = response([event(index=calls)], start=calls - 1, total=2 + (calls > 1))
        return JsonResponse(json.dumps(payload).encode())

    monkeypatch.setattr(downloader.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(ValueError, match="totalResults changed"):
        downloader.fetch_history("CVE-2024-12345", None)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            {
                "format": "NVD_CVEHistory",
                "version": "2.0",
                "timestamp": "2026-10-15T00:00:00.000",
                "startIndex": 0,
                "totalResults": 0,
                "cveChanges": [],
            },
            "pagination metadata",
        ),
        (response([event()], start=1, total=2), "starts at"),
        (response([event()], total=0), "extends beyond"),
        (response([event("CVE-2024-99999")]), "expected CVE-2024-12345"),
        (response([{"change": {"cveId": "CVE-2024-12345"}}]), "created timestamp"),
    ],
)
def test_rejects_incomplete_or_malformed_responses(monkeypatch, payload, message):
    monkeypatch.setattr(
        downloader.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: JsonResponse(json.dumps(payload).encode()),
    )

    with pytest.raises(RuntimeError, match="retries exhausted"):
        downloader.fetch_history("CVE-2024-12345", None)


def test_valid_empty_history_is_accepted():
    empty = response([])

    assert downloader._validate_history_page(empty, [], 0, 0, "CVE-2024-12345") == (0, 0)


def test_invalid_json_is_not_saved_or_accepted(monkeypatch):
    monkeypatch.setattr(
        downloader.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: JsonResponse(b"{"),
    )

    with pytest.raises(RuntimeError, match="retries exhausted"):
        downloader.fetch_history("CVE-2024-12345", None, max_attempts=1)


def test_http_429_honors_retry_after_and_retries(monkeypatch):
    calls = []
    sleeps = []
    metrics = {}

    def fake_urlopen(*_args, **_kwargs):
        calls.append(None)
        if len(calls) == 1:
            raise api_error(429, "7")
        return JsonResponse(json.dumps(response([])).encode())

    monkeypatch.setattr(downloader.urllib.request, "urlopen", fake_urlopen)

    class RecordingLimiter:
        def __init__(self):
            self.acquires = 0

        def acquire(self):
            self.acquires += 1

        def defer(self, seconds):
            sleeps.append(seconds)

    limiter = RecordingLimiter()
    captures = []
    result = downloader.fetch_history(
        "CVE-2024-12345",
        None,
        max_attempts=2,
        metrics=metrics,
        limiter=limiter,
        page_captures=captures,
    )

    assert result["totalResults"] == 0
    assert len(calls) == 2
    assert sleeps[0] >= 7
    assert limiter.acquires == 2
    assert metrics == {"page_requests": 2, "retries": 1}
    assert [capture["http_status"] for capture in captures] == [429, 200]
    assert [capture["is_retry"] for capture in captures] == [False, True]
    assert all(
        capture["request_started_at_utc"] and capture["request_ended_at_utc"]
        for capture in captures
    )


def test_retry_after_http_date_is_parsed(monkeypatch):
    future = datetime.now(UTC) + timedelta(seconds=20)
    value = future.strftime("%a, %d %b %Y %H:%M:%S GMT")

    assert downloader._retry_after_seconds(value) >= 18


def test_retryable_server_error_retries_and_client_error_does_not(monkeypatch):
    calls = []

    def server_then_success(*_args, **_kwargs):
        calls.append(None)
        if len(calls) == 1:
            raise api_error(503)
        return JsonResponse(json.dumps(response([])).encode())

    monkeypatch.setattr(downloader.urllib.request, "urlopen", server_then_success)
    monkeypatch.setattr(downloader.time, "sleep", lambda *_args: None)
    downloader.fetch_history("CVE-2024-12345", None, max_attempts=2)
    assert len(calls) == 2

    calls.clear()
    monkeypatch.setattr(
        downloader.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(api_error(400)),
    )
    with pytest.raises(RuntimeError, match="HTTP 400"):
        downloader.fetch_history("CVE-2024-12345", None, max_attempts=2)


def test_saved_history_requires_complete_valid_response(tmp_path):
    path = tmp_path / "CVE-2024-12345.json"
    path.write_text(json.dumps(response([event()])), encoding="utf-8")
    assert downloader.load_saved_history(path) is not None

    path.write_text(json.dumps(response([event()], total=2)), encoding="utf-8")
    assert downloader.load_saved_history(path) is None

    path.write_text(json.dumps(response([event("CVE-2024-99999")])), encoding="utf-8")
    assert downloader.load_saved_history(path) is None


def test_saves_atomically_and_cleans_temporary_file(tmp_path):
    path = tmp_path / "history" / "CVE-2024-12345.json"

    downloader.save_history(path, response([event()]))

    assert json.loads(path.read_text(encoding="utf-8"))["totalResults"] == 1
    assert not path.with_suffix(".json.tmp").exists()


def test_atomic_save_cleans_temporary_file_after_link_error(tmp_path, monkeypatch):
    path = tmp_path / "CVE-2024-12345.json"
    path.write_text("previous response", encoding="utf-8")

    def fail_link(_source, _target):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(downloader.os, "link", fail_link)
    with pytest.raises(OSError, match="simulated"):
        downloader.save_history(path, response([event()]))

    assert path.read_text(encoding="utf-8") == "previous response"
    assert not path.with_suffix(".json.tmp").exists()


def test_limit_only_attempts_requested_number_and_reports_counts(tmp_path, monkeypatch):
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    snapshot = snapshots / "nvd_2024-01.json.gz"
    records = {
        "vulnerabilities": [
            {"cve": {"id": f"CVE-2024-1234{i}", "published": "2024-01-01T00:00:00Z"}}
            for i in (5, 6)
        ]
    }
    with gzip.open(snapshot, "wt", encoding="utf-8") as file:
        json.dump(records, file)

    attempted = []

    def fake_fetch(cve_id, api_key, metrics=None, limiter=None, request_budget=None, **_kwargs):
        attempted.append(cve_id)
        if metrics is not None:
            metrics.update(page_requests=1, retries=0)
        return response([event(cve_id)])

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(downloader, "fetch_history", fake_fetch)
    monkeypatch.setattr(downloader.time, "sleep", lambda *_args: None)
    output_dir = tmp_path / "history"

    downloader.download_histories(snapshots, output_dir, tmp_path / "missing.env", limit=1)

    assert len(attempted) == 1
    assert len(list(output_dir.glob("CVE-*.json"))) == 1
    report = json.loads((output_dir / "download_report.json").read_text(encoding="utf-8"))
    assert report["target_cve_count"] == 2
    assert report["new_responses_saved"] == 1


def test_download_stops_at_global_request_ceiling_and_checkpoints(tmp_path, monkeypatch):
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    with gzip.open(snapshots / "nvd_2024-01.json.gz", "wt", encoding="utf-8") as file:
        json.dump(
            {
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2024-12345", "published": "2024-01-01T00:00:00Z"}},
                    {"cve": {"id": "CVE-2024-12346", "published": "2024-01-01T00:00:00Z"}},
                ]
            },
            file,
        )
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    attempted = []

    def fake_fetch(cve_id, api_key, metrics=None, limiter=None, request_budget=None, **_kwargs):
        attempted.append(cve_id)
        request_budget.reserve()
        if metrics is not None:
            metrics["page_requests"] = 1
        return response([event(cve_id)])

    monkeypatch.setattr(downloader, "fetch_history", fake_fetch)
    output_dir = tmp_path / "history"
    downloader.download_histories(
        snapshots,
        output_dir,
        tmp_path / "missing.env",
        max_page_requests=1,
    )

    report = json.loads((output_dir / "download_report.json").read_text(encoding="utf-8"))
    assert attempted == ["CVE-2024-12345", "CVE-2024-12346"]
    assert report["page_requests"] == 1
    assert report["max_page_requests"] == 1
    assert report["request_budget_exhausted"] is True
    assert report["interrupted"] is True
    assert report["stopped_reason"] == "global_page_request_ceiling_reached"
    assert report["new_responses_saved"] == 1
    assert report["missing_valid_responses_after_run"] == 1
    assert len(list(output_dir.glob("CVE-*.json"))) == 1
    assert report["missing_valid_responses_after_run"] == 1
    assert report["page_requests"] == 1
    assert report["new_responses_saved"] == 1


def test_resume_skips_valid_saved_history(tmp_path, monkeypatch):
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    with gzip.open(snapshots / "nvd_2024-01.json.gz", "wt", encoding="utf-8") as file:
        json.dump(
            {
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2024-12345", "published": "2024-01-01T00:00:00Z"}}
                ]
            },
            file,
        )
    output_dir = tmp_path / "history"
    output_dir.mkdir()
    (output_dir / "CVE-2024-12345.json").write_text(
        json.dumps(response([event()])), encoding="utf-8"
    )
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    def unexpected_fetch(*_args, **_kwargs):
        pytest.fail("valid saved history should be resumed without a request")

    monkeypatch.setattr(downloader, "fetch_history", unexpected_fetch)
    downloader.download_histories(snapshots, output_dir, tmp_path / "missing.env")


def test_collection_writes_separate_raw_and_metadata_files_and_resumes(tmp_path, monkeypatch):
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    with gzip.open(snapshots / "nvd_2024-01.json.gz", "wt", encoding="utf-8") as file:
        json.dump(
            {
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2024-12345", "published": "2024-01-01T00:00:00Z"}}
                ]
            },
            file,
        )
    payload = response([event()])
    raw_body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    monkeypatch.setattr(
        downloader.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: JsonResponse(raw_body),
    )
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(downloader.time, "sleep", lambda *_args: None)
    output_dir = tmp_path / "collection"

    downloader.download_histories(snapshots, output_dir, tmp_path / "missing.env")

    raw_files = list((output_dir / "raw_responses" / "CVE-2024-12345").glob("*.body"))
    assert len(raw_files) == 1
    assert raw_files[0].read_bytes() == raw_body
    sidecar = json.loads(
        (output_dir / "request_metadata" / "CVE-2024-12345.json").read_text(encoding="utf-8")
    )
    assert sidecar["retrieval_disposition"] == "valid_response"
    assert sidecar["http_statuses"] == [200]
    assert sidecar["event_timestamp_timezone_policy"]["naive_event_timestamp_count"] == 1
    assert (
        "unverified project assumption"
        in sidecar["event_timestamp_timezone_policy"]["documentation_status"]
    )
    ledger = (output_dir / "request_ledger.jsonl").read_text(encoding="utf-8")
    assert '"event": "request_started"' in ledger
    assert '"event": "request_completed"' in ledger

    monkeypatch.setattr(
        downloader.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: pytest.fail("valid history must resume without a request"),
    )
    downloader.download_histories(snapshots, output_dir, tmp_path / "missing.env")
    assert raw_files[0].read_bytes() == raw_body


def test_interrupted_request_remains_unresolved_and_is_preserved_on_resume(tmp_path, monkeypatch):
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    with gzip.open(snapshots / "nvd_2024-01.json.gz", "wt", encoding="utf-8") as file:
        json.dump(
            {
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2024-12345", "published": "2024-01-01T00:00:00Z"}}
                ]
            },
            file,
        )
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    output_dir = tmp_path / "collection"

    def interrupt_request(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(downloader.urllib.request, "urlopen", interrupt_request)
    with pytest.raises(KeyboardInterrupt):
        downloader.download_histories(snapshots, output_dir, tmp_path / "missing.env")

    first_ledger = (output_dir / "request_ledger.jsonl").read_text(encoding="utf-8")
    assert '"event": "request_started"' in first_ledger
    assert '"event": "request_completed"' not in first_ledger

    raw_body = json.dumps(response([event()]), separators=(",", ":")).encode("utf-8")
    monkeypatch.setattr(
        downloader.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: JsonResponse(raw_body),
    )
    monkeypatch.setattr(downloader.time, "sleep", lambda *_args: None)
    downloader.download_histories(snapshots, output_dir, tmp_path / "missing.env")

    sidecar = json.loads(
        (output_dir / "request_metadata" / "CVE-2024-12345.json").read_text(encoding="utf-8")
    )
    assert sidecar["http_request_attempt_count"] == 2
    assert sidecar["unresolved_request_attempts"] == 1
    assert sidecar["http_statuses"] == [None, 200]
    raw_files = list((output_dir / "raw_responses" / "CVE-2024-12345").glob("*.body"))
    assert len(raw_files) == 1
    assert raw_files[0].read_bytes() == raw_body


def test_large_aggregate_saves_validates_and_resumes(tmp_path, monkeypatch):
    monkeypatch.setattr(downloader, "HISTORY_PAGE_SIZE", 2)
    changes = [event(index=index) for index in range(5)]

    def fake_urlopen(request, timeout):
        start = int(
            urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)["startIndex"][0]
        )
        return JsonResponse(
            json.dumps(response(changes[start : start + 2], start=start, total=5)).encode()
        )

    monkeypatch.setattr(downloader.urllib.request, "urlopen", fake_urlopen)

    class CountingLimiter:
        def __init__(self):
            self.acquires = 0

        def acquire(self):
            self.acquires += 1

        def defer(self, _seconds):
            pass

    limiter = CountingLimiter()
    aggregate = downloader.fetch_history("CVE-2024-12345", None, limiter=limiter)
    assert limiter.acquires == 3
    assert aggregate["resultsPerPage"] == 5
    assert "vesperPagination" not in aggregate

    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    with gzip.open(snapshots / "nvd_2024-01.json.gz", "wt", encoding="utf-8") as file:
        json.dump(
            {
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2024-12345", "published": "2024-01-01T00:00:00Z"}}
                ]
            },
            file,
        )
    output_dir = tmp_path / "history"
    output_dir.mkdir()
    path = output_dir / "CVE-2024-12345.json"
    downloader.save_history(path, aggregate)
    assert downloader.load_saved_history(path) == aggregate

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(
        downloader,
        "fetch_history",
        lambda *_args, **_kwargs: pytest.fail("valid large history should be resumed"),
    )
    downloader.download_histories(snapshots, output_dir, tmp_path / "missing.env")


def test_invalid_existing_history_is_reported_and_preserved(tmp_path, monkeypatch):
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    with gzip.open(snapshots / "nvd_2024-01.json.gz", "wt", encoding="utf-8") as file:
        json.dump(
            {
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2024-12345", "published": "2024-01-01T00:00:00Z"}}
                ]
            },
            file,
        )
    output_dir = tmp_path / "history"
    output_dir.mkdir()
    existing = output_dir / "CVE-2024-12345.json"
    existing.write_text("corrupt but preserved", encoding="utf-8")
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(
        downloader,
        "fetch_history",
        lambda *_args, **_kwargs: pytest.fail("invalid existing file must not be overwritten"),
    )
    downloader.download_histories(snapshots, output_dir, tmp_path / "missing.env")
    assert existing.read_text(encoding="utf-8") == "corrupt but preserved"
    failures = json.loads((output_dir / "download_failures.json").read_text())
    assert failures[0]["error"] == "existing history file is invalid; preserved"


def test_duplicate_event_across_pages_is_rejected(monkeypatch):
    monkeypatch.setattr(downloader, "HISTORY_PAGE_SIZE", 1)
    payloads = [response([event(index=1)], total=2), response([event(index=1)], start=1, total=2)]
    monkeypatch.setattr(
        downloader.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: JsonResponse(json.dumps(payloads.pop(0)).encode()),
    )
    with pytest.raises(ValueError, match="duplicate events"):
        downloader.fetch_history("CVE-2024-12345", None)


def test_missing_pagination_page_is_rejected(monkeypatch):
    monkeypatch.setattr(downloader, "HISTORY_PAGE_SIZE", 1)

    def fake_urlopen(request, **_kwargs):
        start = int(
            urllib.parse.parse_qs(urllib.parse.urlparse(request.full_url).query)["startIndex"][0]
        )
        payload = (
            response([event(index=1)], total=3)
            if start == 0
            else response([event(index=3)], start=2, total=3)
        )
        return JsonResponse(json.dumps(payload).encode())

    monkeypatch.setattr(
        downloader.urllib.request,
        "urlopen",
        fake_urlopen,
    )
    with pytest.raises(RuntimeError, match="retries exhausted"):
        downloader.fetch_history("CVE-2024-12345", None)


def test_limiter_applies_interval_before_every_request_and_retry_after():
    now = [0.0]
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    limiter = downloader.RequestRateLimiter(None, clock=lambda: now[0], sleep=sleep)
    limiter.acquire()
    limiter.acquire()
    assert sleeps == [pytest.approx(6.0)]
    limiter.defer(12.0)
    limiter.acquire()
    assert sleeps[-1] >= 12.0

    keyed = downloader.RequestRateLimiter("test-key", clock=lambda: 0.0, sleep=lambda _s: None)
    assert keyed.interval == pytest.approx(0.6)


def test_interrupt_checkpoints_progress_and_failures(tmp_path, monkeypatch):
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    with gzip.open(snapshots / "nvd_2024-01.json.gz", "wt", encoding="utf-8") as file:
        json.dump(
            {
                "vulnerabilities": [
                    {"cve": {"id": f"CVE-2024-1234{i}", "published": "2024-01-01T00:00:00Z"}}
                    for i in (5, 6)
                ]
            },
            file,
        )
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(
        downloader,
        "fetch_history",
        lambda cve_id, *_args, **_kwargs: (
            response([event(cve_id)])
            if cve_id.endswith("5")
            else (_ for _ in ()).throw(KeyboardInterrupt())
        ),
    )
    with pytest.raises(KeyboardInterrupt):
        downloader.download_histories(snapshots, tmp_path / "history", tmp_path / "missing.env")
    report = json.loads((tmp_path / "history" / "download_report.json").read_text())
    assert report["interrupted"] is True
    assert report["valid_history_responses_after_run"] == 1
    assert report["new_responses_saved"] == 1


@pytest.mark.parametrize("contents", ["{broken}\n", '{"event":"request_started"}\nnot-json'])
def test_ledger_rejects_malformed_records_with_path_and_line(tmp_path, contents):
    ledger = tmp_path / "request_ledger.jsonl"
    ledger.write_text(contents, encoding="utf-8")
    with pytest.raises(ValueError, match=r"request_ledger\.jsonl at line"):
        downloader.request_attempts_from_ledger(ledger, "CVE-2024-12345")


def test_ledger_identifies_truncated_final_record_and_preserves_bytes(tmp_path):
    ledger = tmp_path / "request_ledger.jsonl"
    first_record = {
        "event": "request_started",
        "request_id": "x",
        "cve_id": "CVE-2024-12345",
        "source_endpoint": downloader.NVD_HISTORY_URL,
        "start_index": 0,
        "attempt": 1,
        "is_retry": False,
        "request_started_at_utc": "2026-10-16T00:00:00+00:00",
    }
    original = (json.dumps(first_record) + "\n{" + '"event":').encode()
    ledger.write_bytes(original)
    with pytest.raises(ValueError, match="truncated final record"):
        downloader.request_attempts_from_ledger(ledger, "CVE-2024-12345")
    assert ledger.read_bytes() == original


@pytest.mark.parametrize("failure", ["duplicate_start", "orphan_completion", "identity_change"])
def test_ledger_rejects_inconsistent_request_event_pairs(tmp_path, failure):
    ledger = tmp_path / "request_ledger.jsonl"
    started = {
        "event": "request_started",
        "request_id": "request-1",
        "cve_id": "CVE-2024-12345",
        "source_endpoint": downloader.NVD_HISTORY_URL,
        "start_index": 0,
        "attempt": 1,
        "is_retry": False,
        "request_started_at_utc": "2026-10-16T00:00:00+00:00",
    }
    if failure == "duplicate_start":
        records = [started, started]
    elif failure == "orphan_completion":
        records = [{**started, "event": "request_completed"}]
    else:
        records = [started, {**started, "event": "request_completed", "start_index": 1}]
    original = ("\n".join(json.dumps(item) for item in records) + "\n").encode()
    ledger.write_bytes(original)
    with pytest.raises(ValueError, match=r"request_ledger\.jsonl at line"):
        downloader.request_attempts_from_ledger(ledger, "CVE-2024-12345")
    assert ledger.read_bytes() == original


def test_run_directory_lock_excludes_another_process_and_releases_on_exception(tmp_path):
    lock = downloader.RunDirectoryLock(tmp_path)
    with lock:
        script = (
            "import sys; sys.path.insert(0, sys.argv[2]); "
            "import download_nvd_history as d; "
            "d.RunDirectoryLock(__import__('pathlib').Path(sys.argv[1])).__enter__()"
        )
        child = subprocess.run(
            [sys.executable, "-c", script, str(tmp_path), str(Path(downloader.__file__).parent)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert child.returncode != 0
        assert "locked" in child.stderr
    assert not lock.path.exists()

    with pytest.raises(KeyboardInterrupt), downloader.RunDirectoryLock(tmp_path):
        raise KeyboardInterrupt
    assert not (tmp_path / ".collection.lock").exists()


def test_run_directory_lock_cleans_up_when_lock_persistence_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(downloader.os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("disk")))
    with pytest.raises(OSError, match="disk"):
        downloader.RunDirectoryLock(tmp_path).__enter__()
    assert not (tmp_path / ".collection.lock").exists()


def test_standard_request_budget_persists_across_invocations(tmp_path):
    database = tmp_path / "request_reservations.sqlite3"
    ledger = tmp_path / "request_ledger.jsonl"
    budget = downloader.DurableRequestBudget(database, 2, ledger)
    budget.reserve()
    assert budget.used == 1
    budget.close()

    resumed = downloader.DurableRequestBudget(database, None, ledger)
    assert resumed.maximum == 2
    assert resumed.used == 1
    resumed.reserve()
    resumed.close()

    exhausted = downloader.DurableRequestBudget(database, 2, ledger)
    with pytest.raises(downloader.RequestBudgetExceeded, match="Durable page-request ceiling"):
        exhausted.reserve()
    exhausted.close()


def test_standard_request_budget_serializes_concurrent_reservations(tmp_path):
    database = tmp_path / "request_reservations.sqlite3"
    initializer = downloader.DurableRequestBudget(database, 1, tmp_path / "request_ledger.jsonl")
    initializer.close()
    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "sys.path.insert(0, sys.argv[2])\n"
        "import download_nvd_history as d\n"
        "b = d.DurableRequestBudget(Path(sys.argv[1]), 1)\n"
        "try:\n"
        "    b.reserve()\n"
        "    print('reserved')\n"
        "except d.RequestBudgetExceeded:\n"
        "    print('exhausted')\n"
        "finally:\n"
        "    b.close()\n"
    )
    command = [sys.executable, "-c", script, str(database), str(Path(downloader.__file__).parent)]
    first = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    second = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    first_out, first_err = first.communicate(timeout=20)
    second_out, second_err = second.communicate(timeout=20)
    assert first.returncode == second.returncode == 0, first_err + second_err
    assert sorted([first_out.strip(), second_out.strip()]) == ["exhausted", "reserved"]


def test_standard_downloader_retains_ceiling_across_resume_invocations(tmp_path, monkeypatch):
    snapshots = _write_snapshot_for_resume(tmp_path)
    output = tmp_path / "history"
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    consumed = []

    def fail_after_reservation(_cve_id, _api_key, request_budget=None, **_kwargs):
        request_budget.reserve()
        consumed.append(True)
        raise RuntimeError("mocked offline failure")

    monkeypatch.setattr(downloader, "fetch_history", fail_after_reservation)
    downloader.download_histories(snapshots, output, tmp_path / "missing.env", max_page_requests=1)
    downloader.download_histories(snapshots, output, tmp_path / "missing.env")

    assert len(consumed) == 1
    budget = downloader.DurableRequestBudget(
        output / "request_reservations.sqlite3", None, output / "request_ledger.jsonl"
    )
    assert budget.maximum == budget.used == 1
    budget.close()


def test_standard_budget_bootstrap_fails_closed_on_malformed_ledger(tmp_path):
    ledger = tmp_path / "request_ledger.jsonl"
    first_record = {
        "event": "request_started",
        "request_id": "x",
        "cve_id": "CVE-2024-12345",
        "source_endpoint": downloader.NVD_HISTORY_URL,
        "start_index": 0,
        "attempt": 1,
        "is_retry": False,
        "request_started_at_utc": "2026-10-16T00:00:00+00:00",
    }
    original = (json.dumps(first_record) + "\n{" + '"event":').encode()
    ledger.write_bytes(original)
    with pytest.raises(
        ValueError, match=r"request_ledger\.jsonl at line 2.*truncated final record"
    ):
        downloader.DurableRequestBudget(tmp_path / "budget.sqlite3", 2, ledger)
    assert ledger.read_bytes() == original


def test_standard_budget_bootstrap_counts_existing_ledger_starts(tmp_path):
    ledger = tmp_path / "request_ledger.jsonl"
    start = {
        "event": "request_started",
        "request_id": "old-request",
        "cve_id": "CVE-2024-12345",
        "source_endpoint": downloader.NVD_HISTORY_URL,
        "start_index": 0,
        "attempt": 1,
        "is_retry": False,
        "request_started_at_utc": "2026-10-16T00:00:00+00:00",
    }
    ledger.write_text(json.dumps(start) + "\n", encoding="utf-8")
    budget = downloader.DurableRequestBudget(tmp_path / "budget.sqlite3", 1, ledger)
    assert budget.used == 1
    with pytest.raises(downloader.RequestBudgetExceeded):
        budget.reserve()
    budget.close()


def _write_snapshot_for_resume(root: Path) -> Path:
    snapshots = root / "snapshots"
    snapshots.mkdir()
    with gzip.open(snapshots / "nvd_2024-01.json.gz", "wt", encoding="utf-8") as stream:
        json.dump(
            {
                "vulnerabilities": [
                    {"cve": {"id": "CVE-2024-12345", "published": "2024-01-01T00:00:00Z"}}
                ]
            },
            stream,
        )
    return snapshots


def test_resume_reconciles_saved_history_using_complete_ledger_idempotently(tmp_path, monkeypatch):
    snapshots = _write_snapshot_for_resume(tmp_path)
    output = tmp_path / "history"
    output.mkdir()
    (output / "CVE-2024-12345.json").write_text(json.dumps(response([event()])), encoding="utf-8")
    raw_dir = output / "raw_responses" / "CVE-2024-12345"
    raw_dir.mkdir(parents=True)
    raw = raw_dir / "saved.body"
    raw_body = json.dumps(response([event()]), separators=(",", ":")).encode("utf-8")
    raw.write_bytes(raw_body)
    attempt = {
        "request_id": "request-1",
        "cve_id": "CVE-2024-12345",
        "source_endpoint": downloader.NVD_HISTORY_URL,
        "start_index": 0,
        "attempt": 1,
        "is_retry": False,
        "request_started_at_utc": "2026-10-16T00:00:00+00:00",
        "request_ended_at_utc": "2026-10-16T00:00:01+00:00",
        "http_status": 200,
        "raw_response_path": str(raw),
        "response_bytes": len(raw_body),
        "response_sha256": hashlib.sha256(raw_body).hexdigest(),
    }
    ledger = output / "request_ledger.jsonl"
    ledger.write_text(
        json.dumps({"event": "request_started", **attempt})
        + "\n"
        + json.dumps({"event": "request_completed", **attempt})
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    downloader.download_histories(snapshots, output, tmp_path / "missing.env")
    sidecar = output / "request_metadata" / "CVE-2024-12345.json"
    reconciled = sidecar.read_bytes()
    data = json.loads(reconciled)
    assert data["provenance_status"] == "reconciled"
    assert data["retrieval_disposition"] == "valid_response"
    downloader.download_histories(snapshots, output, tmp_path / "missing.env")
    assert sidecar.read_bytes() == reconciled


def test_resume_rejects_raw_response_that_does_not_match_ledger_hash(tmp_path, monkeypatch):
    snapshots = _write_snapshot_for_resume(tmp_path)
    output = tmp_path / "history"
    output.mkdir()
    history = response([event()])
    (output / "CVE-2024-12345.json").write_text(json.dumps(history), encoding="utf-8")
    raw_dir = output / "raw_responses" / "CVE-2024-12345"
    raw_dir.mkdir(parents=True)
    raw = raw_dir / "response.body"
    raw.write_text("unaltered body does not match ledger", encoding="utf-8")
    expected_body = json.dumps(response([event()]), separators=(",", ":")).encode("utf-8")
    attempt = {
        "request_id": "request-1",
        "cve_id": "CVE-2024-12345",
        "source_endpoint": downloader.NVD_HISTORY_URL,
        "start_index": 0,
        "attempt": 1,
        "is_retry": False,
        "request_started_at_utc": "2026-10-16T00:00:00+00:00",
        "request_ended_at_utc": "2026-10-16T00:00:01+00:00",
        "http_status": 200,
        "raw_response_path": str(raw),
        "response_bytes": len(expected_body),
        "response_sha256": hashlib.sha256(expected_body).hexdigest(),
    }
    (output / "request_ledger.jsonl").write_text(
        json.dumps({"event": "request_started", **attempt})
        + "\n"
        + json.dumps({"event": "request_completed", **attempt})
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    downloader.download_histories(snapshots, output, tmp_path / "missing.env")
    sidecar = json.loads(
        (output / "request_metadata" / "CVE-2024-12345.json").read_text(encoding="utf-8")
    )
    assert sidecar["provenance_status"] == "incomplete"
    assert sidecar["retrieval_disposition"] == "incomplete_provenance"


def test_resume_marks_history_incomplete_when_provenance_is_unrecoverable(tmp_path, monkeypatch):
    snapshots = _write_snapshot_for_resume(tmp_path)
    output = tmp_path / "history"
    output.mkdir()
    (output / "CVE-2024-12345.json").write_text(json.dumps(response([event()])), encoding="utf-8")
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    downloader.download_histories(snapshots, output, tmp_path / "missing.env")
    data = json.loads((output / "request_metadata" / "CVE-2024-12345.json").read_text())
    assert data["provenance_status"] == "incomplete"
    assert data["retrieval_disposition"] == "incomplete_provenance"
