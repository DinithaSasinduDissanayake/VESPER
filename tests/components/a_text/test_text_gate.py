import pytest

from vesper.components.a_text.text_gate import text_scope


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (42, (False, "missing_text")),
        ("XSS", (False, "too_short")),
        ("SQL injection in the login form", (True, "security_cue")),
        ("The firmware update tool crashes on start", (True, "software_cue")),
        ("Some text we cannot place either way", (True, "uncertain_scope_retained")),
        (
            "Bake the dough with butter and sugar",
            (False, "recipe_without_software_or_security_context"),
        ),
        (
            "Dear mom, the trip was lovely",
            (False, "ordinary_prose_without_software_or_security_context"),
        ),
        # Software context wins over cooking words: a recipe app bug stays in scope.
        ("Recipe app stores flour and sugar amounts in a database", (True, "software_cue")),
    ],
)
def test_text_scope(text, expected):
    assert text_scope(text) == expected
