import pytest

from vesper.components.a_text import sanitise
from vesper.components.a_text.sanitise import leak_spans, rules_digest, sanitise_text


def test_leak_phrases_are_removed():
    out = sanitise_text("Flaw is actively exploited in the wild; a proof of concept is public.")
    assert "exploited" not in out.lower()
    assert "proof" not in out.lower()
    assert "wild" not in out.lower()


def test_neutral_technical_words_are_kept():
    text = "The wildcard handler is exploitable; exploitation of a buffer overflow is possible."
    assert sanitise_text(text) == text


def test_none_and_empty():
    assert sanitise_text(None) == ""
    assert sanitise_text("") == ""


def test_url_and_cve_id_removed():
    out = sanitise_text("See https://example.com/x and CVE-2020-1234 for details.")
    assert out == "See and for details."


def test_overlap_is_one_span():
    assert sanitise_text("Bug actively exploited in the wild today") == "Bug today"


@pytest.mark.parametrize(
    ("text", "kept"),
    [
        ("Bug exploited by attackers in the parser.", "Bug in the parser."),  # exploitation
        ("Bug is in the known exploited vulnerabilities list.", "Bug is in the list."),  # catalog
        ("Bug with a public exploit for the parser.", "Bug with a for the parser."),  # poc_ref
        ("Bug, see GHSA-abcd-1234 for details.", "Bug, see for details."),  # url
        ("Bug fixed in version 2.1 of the parser.", "Bug 2.1 of the parser."),  # patch_note
        ("Bug; apply the latest patch now.", "Bug; now."),  # patch_note
    ],
)
def test_one_example_per_rule_group(text, kept):
    assert sanitise_text(text) == kept


def test_leak_spans_are_the_deleted_phrases():
    text = "See https://example.com/x and CVE-2020-1234."
    assert [text[a:b] for a, b in leak_spans(text)] == ["https://example.com/x", "CVE-2020-1234"]


def test_rules_digest_changes_when_a_rule_changes(monkeypatch):
    before = rules_digest()
    assert before == rules_digest()
    monkeypatch.setitem(sanitise.RULES, "demo", [r"\bfoo\b"])
    assert rules_digest() != before
