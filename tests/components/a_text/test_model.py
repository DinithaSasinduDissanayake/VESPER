import numpy as np
import pandas as pd
import pytest

from vesper.components.a_text import model as m


def toy_frame(n_pos=15, n_neg=60):
    pos = [f"remote code execution in parser module {i % 3}" for i in range(n_pos)]
    neg = [f"minor display glitch in settings page {i % 4}" for i in range(n_neg)]
    return pd.DataFrame({"description": pos + neg, "label": [1] * n_pos + [0] * n_neg})


def test_fit_and_rank():
    fitted = m.fit_text_model(toy_frame())
    texts = ["remote code execution in parser module", "display glitch in settings"]
    p = fitted.predict_proba(texts)
    assert p[0] > p[1]
    assert fitted.best_c in m.C_GRID


def test_offset_is_negative_when_negatives_dropped(monkeypatch):
    monkeypatch.setattr(m, "MAX_NEGATIVES", 20)
    sampled, offset = m.sample_training(toy_frame())
    assert offset == pytest.approx(np.log(20 / 60))
    assert offset < 0
    assert (sampled.label == 1).sum() == 15 and len(sampled) == 35


def test_no_offset_without_downsampling():
    _, offset = m.sample_training(toy_frame())
    assert offset == 0.0


def test_deterministic_with_seed(monkeypatch):
    monkeypatch.setattr(m, "MAX_NEGATIVES", 30)
    texts = toy_frame().description
    a = m.fit_text_model(toy_frame()).log_odds(texts)
    b = m.fit_text_model(toy_frame()).log_odds(texts)
    np.testing.assert_array_equal(a, b)


def test_too_few_positives_rejected():
    with pytest.raises(ValueError):
        m.sample_training(toy_frame(n_pos=3))


def test_missing_description_is_empty():
    assert m.clean_texts([None, float("nan")]) == ["", ""]


def test_bare_string_is_rejected():
    with pytest.raises(TypeError, match="list of texts"):
        m.clean_texts("remote code execution in the parser")


def test_held_out_log_odds_cover_every_sampled_row(monkeypatch):
    monkeypatch.setattr(m, "MAX_NEGATIVES", 30)
    held = m.held_out_log_odds(toy_frame())
    assert held.shape == (45,) and np.isfinite(held).all()
    sampled, _ = m.sample_training(toy_frame())
    is_pos = sampled.label.to_numpy() == 1
    assert held[is_pos].mean() > held[~is_pos].mean()


def test_ranking_reference_is_median_and_iqr_with_a_floor():
    assert m.ranking_reference(np.arange(101.0)) == {"ranking_centre": 50.0, "ranking_scale": 50.0}
    assert m.ranking_reference([0.0, 0.0, 0.1, 0.2])["ranking_scale"] == m.MIN_RANKING_SCALE
