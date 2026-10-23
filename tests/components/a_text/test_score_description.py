import joblib
import numpy as np
import pandas as pd
import pytest
from scipy.special import expit

from vesper.components.a_text import explain, sanitise, score, train

UP = "unauthenticated remote attacker can execute arbitrary code on the server {}"
DOWN = "authenticated user can store cross site scripting in plugin settings {}"
CVE_TEXT = (
    "Unauthenticated remote attacker can execute arbitrary code on the server, "
    "exploited in the wild, see https://example.com/advisory for the plugin settings fix."
)


@pytest.fixture(scope="module")
def model_path(tmp_path_factory):
    """A tiny model trained by train.py on synthetic CVE-like text."""
    folder = tmp_path_factory.mktemp("a_text")
    n = 120
    published = pd.date_range("2022-01-01", periods=n, freq="D", tz="UTC")
    exploited = [i % 8 == 0 for i in range(n)]
    pd.DataFrame(
        {
            "published_date": published,
            "description": [(UP if e else DOWN).format(i % 3) for i, e in enumerate(exploited)],
            "kev_date_added": [
                d + pd.Timedelta(days=10) if e else pd.NaT
                for d, e in zip(published, exploited, strict=True)
            ],
        }
    ).to_parquet(folder / "cves.parquet")
    out = folder / "model.joblib"
    train.train(folder / "cves.parquet", pd.Timestamp("2022-12-01").date(), out)
    return out


@pytest.fixture(scope="module")
def model(model_path):
    return score.load_model(model_path)


def test_scores_cve_like_text(model):
    result = score.score_description(model, CVE_TEXT)
    assert result["status"] == "available"
    assert result["reason"] == "security_cue"
    assert result["score_kind"] == "ranking_score"
    assert 0 < result["ranking_score"] < 1
    assert result["uncalibrated_probability"] == pytest.approx(expit(result["log_odds"]))
    assert result["model_version"] == "a_text-tfidf-lr-2022-12-01"
    assert "exploited in the wild" not in result["model_text"]
    assert "https" not in result["model_text"]


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("", "missing_text"),
        ("   ", "missing_text"),
        (None, "missing_text"),
        ("hello there", "too_short"),
        (
            "Mix the flour, eggs and milk, then whisk in sugar and fry the pancakes.",
            "recipe_without_software_or_security_context",
        ),
        (
            "A peaceful walk in the garden among the flowers.",
            "ordinary_prose_without_software_or_security_context",
        ),
        ("CVE-2024-1111 CVE-2024-2222 CVE-2024-3333", "too_short_after_masking"),
        # The raw text passes the gate only through words the sanitiser deletes.
        ("Exploited in the wild: CVE-2024-1234 https://x.y/z attack", "too_short_after_masking"),
    ],
)
def test_abstains_on_off_topic_or_empty_text(model, text, reason):
    result = score.score_description(model, text)
    assert result["status"] == "abstained"
    assert result["reason"] == reason
    assert result["ranking_score"] is None and result["log_odds"] is None
    assert result["top_words"] == {"up": [], "down": []}


def test_output_keys_are_the_same_when_abstaining(model):
    scored = score.score_description(model, CVE_TEXT)
    abstained = score.score_description(model, "")
    assert scored.keys() == abstained.keys()
    assert set(scored["totals"]) == {"words", "char_ngrams", "intercept", "offset"}


def test_one_row_gives_the_same_log_odds_as_the_pipeline(model):
    result = score.score_description(model, CVE_TEXT)
    assert result["log_odds"] == model["model"].log_odds([CVE_TEXT])[0]


def test_contributions_add_up_to_log_odds(model):
    result = score.score_description(model, CVE_TEXT)
    assert sum(result["totals"].values()) == pytest.approx(result["log_odds"], abs=1e-9)
    row = model["model"].pipeline["features"].transform([CVE_TEXT])
    words, totals = explain.contributions(model["model"], row)
    assert sum(words.values()) == pytest.approx(totals["words"], abs=1e-9)
    # The first columns of the row are the word block: every name is a term of the masked text.
    analyse = model["model"].word_vectorizer.build_analyzer()
    assert set(words) <= set(analyse(result["model_text"]))


def test_top_words_are_signed_and_sorted(model):
    top = score.score_description(model, CVE_TEXT)["top_words"]
    up = [w["contribution"] for w in top["up"]]
    down = [w["contribution"] for w in top["down"]]
    assert up and down
    assert all(c > 0 for c in up) and up == sorted(up, reverse=True)
    assert all(c < 0 for c in down) and down == sorted(down)
    assert len(up) <= score.TOP_N and len(down) <= score.TOP_N


def test_spans_point_at_the_words_in_the_original_text(model):
    result = score.score_description(model, CVE_TEXT)
    deleted = CVE_TEXT.index("exploited"), CVE_TEXT.index(", see")
    for word in result["top_words"]["up"] + result["top_words"]["down"]:
        assert word["spans"], word["term"]
        for start, end in word["spans"]:
            shown = CVE_TEXT[start:end].lower()
            assert shown.startswith(word["term"].split()[0])
            assert shown.endswith(word["term"].split()[-1])
            assert end <= deleted[0] or start >= deleted[1]


def test_a_deleted_word_reused_later_is_highlighted_outside_the_deleted_phrase(model):
    text = (
        "Remote attacker can crash the server; "
        "see https://example.com/attacker-guide for attacker details."
    )
    url = text.index("https"), text.index(" for attacker")
    located = explain.locate_words(model["model"], text)
    analyse = model["model"].word_vectorizer.build_analyzer()
    read = [t for t in analyse(sanitise.sanitise_text(text)) if " " not in t]  # single words
    assert [w for w, _, _ in located] == read
    attacker = [(s, e) for w, s, e in located if w == "attacker"]
    assert len(attacker) == 2
    assert all(e <= url[0] or s >= url[1] for s, e in attacker)
    assert all(text[s:e].lower() == w for w, s, e in located)


def test_masking_happens_inside_the_model_at_scoring_time(model):
    base = "Unauthenticated remote attacker can execute arbitrary code on the server"
    log_odds = model["model"].log_odds
    # No punctuation is left behind, so the masked text and the log-odds are identical.
    assert log_odds([base + " exploited in the wild"])[0] == log_odds([base])[0]
    # Deleting a phrase can leave punctuation behind; only those leftovers count, not the words.
    leaked = base + " Exploited in the wild, see CVE-2024-1234."
    assert log_odds([leaked])[0] == log_odds([base + " , see ."])[0]


def test_load_model_refuses_when_masking_rules_changed(model_path, monkeypatch):
    monkeypatch.setitem(sanitise.RULES, "demo", [r"\bfoo\b"])
    with pytest.raises(ValueError, match="masking rules changed"):
        score.load_model(model_path)


def test_load_model_refuses_another_sklearn_version(model_path, monkeypatch):
    monkeypatch.setattr(score.sklearn, "__version__", "0.0.0")
    with pytest.raises(ValueError, match="sklearn"):
        score.load_model(model_path)


def test_ranking_score_keeps_the_order_and_stays_in_0_1():
    log_odds = np.linspace(-30, 30, 601)
    ranked = score.ranking_score(log_odds, centre=-6.0, scale=2.0)
    assert np.all(np.diff(ranked) > 0)
    assert np.all((ranked > 0) & (ranked < 1))
    assert score.ranking_score(-6.0, centre=-6.0, scale=2.0) == 0.5


def test_load_model_rejects_a_model_without_ranking_reference(tmp_path):
    joblib.dump({"model": None, "metadata": {"cutoff": "2022-12-01"}}, tmp_path / "old.joblib")
    with pytest.raises(ValueError, match="ranking reference"):
        score.load_model(tmp_path / "old.joblib")
