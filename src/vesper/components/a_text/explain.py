"""Split one feature row's log-odds into word contributions and find those words in the text."""

import re

from vesper.components.a_text.model import TextModel
from vesper.components.a_text.sanitise import leak_spans


def contributions(model: TextModel, row) -> tuple[dict[str, float], dict[str, float]]:
    """Per-word contributions (TF-IDF value x coefficient) and the totals that make the log-odds.

    `row` is the model's feature row for one text. The model is linear, so log_odds = sum of
    all feature contributions + intercept + offset. Word and word-pair features are returned
    one by one; character n-grams only as a total.
    """
    clf = model.pipeline["clf"]
    parts = row.data * clf.coef_[0, row.indices]
    is_word = row.indices < len(model.word_vectorizer.vocabulary_)  # word columns come first
    names = model.word_names[row.indices[is_word]]
    words = dict(zip(names.tolist(), parts[is_word].tolist(), strict=True))
    totals = {
        "words": float(parts[is_word].sum()),
        "char_ngrams": float(parts[~is_word].sum()),  # not itemised: fragments are unreadable
        "intercept": float(clf.intercept_[0]),
        "offset": model.offset,
    }
    return words, totals


def locate_words(model: TextModel, original: str) -> list[tuple[str, int, int]]:
    """Each single word the model read, with its start and end offset in the original text.

    Leak phrases are overwritten with the same number of spaces, so no offset moves and the
    words left are exactly the words the model read from the masked text.
    """
    word = model.word_vectorizer
    blanked = original
    for start, stop in leak_spans(original):
        blanked = blanked[:start] + " " * (stop - start) + blanked[stop:]
    stop_words = word.get_stop_words()
    return [
        (m.group().lower(), m.start(), m.end())
        for m in re.finditer(word.token_pattern, blanked)
        if m.group().lower() not in stop_words
    ]


def spans_of(term: str, located: list[tuple[str, int, int]]) -> list[tuple[int, int]]:
    """Every (start, end) of a word or word pair; a pair spans the stop-words between them."""
    words = term.split()
    n = len(words)
    return [
        (located[i][1], located[i + n - 1][2])
        for i in range(len(located) - n + 1)
        if [t[0] for t in located[i : i + n]] == words
    ]
