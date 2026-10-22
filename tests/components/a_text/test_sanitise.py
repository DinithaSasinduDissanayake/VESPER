from vesper.components.a_text.sanitise import sanitise_text


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
