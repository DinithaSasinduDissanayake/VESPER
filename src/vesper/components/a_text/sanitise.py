"""Remove wording from CVE descriptions that gives away the exploited-or-not label."""

import hashlib
import json
import re

# Each group is a list of case-insensitive regex patterns.
RULES: dict[str, list[str]] = {
    # Says outright that the CVE was exploited, which is the label itself.
    "exploitation": [
        r"\bexploited\b",
        r"\b(?:actively\s+)?exploited\s+in\s+the\s+wild\b",
        r"\b(?:active|ongoing)\s+exploitation\b",
        r"\bexploitation\s+has\s+been\s+observed\b",
        r"\b(?:observed|confirmed|reported)\s+exploitation\b",
        r"\bexploited\s+by\s+(?:attackers|threat\s+actors)\b",
    ],
    # Names the CISA KEV list, whose membership is the label.
    "catalog": [
        r"\bCISA\s+(?:KEV|known\s+exploited\s+vulnerabilities?)\b",
        r"\bknown\s+exploited\s+vulnerabilit(?:y|ies)\b",
        r"\b(?:KEV|known\s+exploited)\s+catalog(?:ue)?\b",
        r"\badded\s+to\s+(?:the\s+)?(?:CISA\s+)?KEV\b",
    ],
    # Mentions a public exploit, which only exists for later-exploited CVEs.
    "poc_ref": [
        r"\bproof[\s-]*of[\s-]*concept\b",
        r"\b(?:public|available)\s+(?:exploit|poc)\b",
        r"\bpoc\b",
        r"\bexploit\s+code\s+(?:is\s+)?(?:public|available)\b",
        r"\b(?:github|metasploit)\s+(?:exploit|module)\b",
    ],
    # Links and advisory ids point to write-ups added after the fact.
    "url": [
        r"\bhttps?://[^\s)\]>]+",
        r"\b(?:CVE|BID|CERT|GHSA)-[A-Z0-9._:-]+\b",
    ],
    # Patch notes only appear once a fix and its follow-up attention exist.
    "patch_note": [
        r"\b(?:fixed|patched|addressed)\s+in\s+(?:version|v?\d)",
        r"\b(?:apply|install)\s+(?:the\s+)?(?:latest\s+)?(?:patch|update)\b",
        r"\bvendor\s+(?:has\s+)?(?:released|provided)\s+(?:a\s+)?(?:patch|fix)\b",
        r"\bupdate\s+to\s+(?:the\s+)?latest\s+version\b",
    ],
}

_PATTERNS = [re.compile(p, re.IGNORECASE) for group in RULES.values() for p in group]


def rules_digest() -> str:
    """Fingerprint of the masking rules; a saved model records the one it was trained with."""
    return hashlib.sha256(json.dumps(RULES, sort_keys=True).encode()).hexdigest()


def leak_spans(text: str) -> list[tuple[int, int]]:
    """(start, end) of every leaking phrase in the text, without overlaps, left to right."""
    spans = [m.span() for pattern in _PATTERNS for m in pattern.finditer(text)]
    # Earliest start first; for the same start the longer match wins.
    spans.sort(key=lambda s: (s[0], s[0] - s[1]))
    kept: list[tuple[int, int]] = []
    end = -1
    for start, stop in spans:
        if start >= end:
            kept.append((start, stop))
            end = stop
    return kept


def sanitise_text(text: str | None) -> str:
    """Delete every leaking phrase from the text and tidy the whitespace."""
    value = "" if text is None else str(text)
    for start, stop in reversed(leak_spans(value)):
        value = value[:start] + " " + value[stop:]
    return re.sub(r"\s+", " ", value).strip()
