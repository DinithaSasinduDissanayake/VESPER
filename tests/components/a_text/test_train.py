import joblib
import pandas as pd

from vesper.components.a_text import train
from vesper.config import load_settings


def test_cli_saves_a_model_that_loads_and_scores(tmp_path, monkeypatch):
    n = 120
    published = pd.date_range("2022-01-01", periods=n, freq="D", tz="UTC")
    exploited = [i % 8 == 0 for i in range(n)]
    pd.DataFrame(
        {
            "published_date": published,
            "description": [
                "remote code execution in parser" if e else "minor display glitch in page"
                for e in exploited
            ],
            "kev_date_added": [
                d + pd.Timedelta(days=10) if e else pd.NaT
                for d, e in zip(published, exploited, strict=True)
            ],
        }
    ).to_parquet(tmp_path / "cves.parquet")
    # Without --out the model goes under the outputs folder of vesper.config.
    monkeypatch.setattr(train, "load_settings", lambda: load_settings(tmp_path))

    out = train.main(["--data", str(tmp_path / "cves.parquet"), "--cutoff", "2022-12-01"])

    assert out == tmp_path / "outputs" / "a_text" / "models" / "model_2022-12-01.joblib"
    saved = joblib.load(out)
    assert saved["metadata"]["n_train"] == n
    assert saved["metadata"]["n_positives"] == 15
    assert saved["metadata"]["cutoff"] == "2022-12-01"
    p = saved["model"].predict_proba(["remote code execution in parser", "minor display glitch"])
    assert p[0] > p[1]
