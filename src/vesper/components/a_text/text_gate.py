"""Decide whether a text is in scope for the model before scoring it (the off-topic gate)."""

import re

# Fewer word tokens than this is not a description (e.g. "## Summary").
MIN_WORDS = 3
# Same token pattern as the word vectorizer (two or more letters, digits or underscores);
# unlike the vectorizer, stop words still count here.
WORD = re.compile(r"\b\w\w+\b")

# Any one of these words says the text is about security.
SECURITY_WORDS = [
    r"vulnerab\w*", r"security", r"exploit\w*", r"attack\w*", r"CVE[- ]?\d+", r"CWE[- ]?\d+",
    r"malicious", r"unauthori[sz]\w*", r"authenticat\w*", r"privileg\w*", r"bypass\w*", r"denial",
    r"arbitrary", r"overflow", r"underflow", r"inject\w*", r"traversal", r"disclos\w*",
    r"leak\w*", r"corrupt\w*", r"out[ -]of[ -]bounds", r"use[ -]after[ -]free", r"cross[ -]site",
    r"cross[ -]origin", r"XSS", r"CSRF", r"XSRF", r"XXE", r"SSRF", r"race[ -]condition",
    r"unsafe", r"untrust\w*", r"unrestrict\w*", r"uncontrol\w*", r"improper", r"insufficien\w*",
    r"unsanit\w*", r"hard[ -]?cod\w*", r"backdoor", r"certificate", r"cryptograph\w*",
    r"decrypt\w*", r"encrypt\w*", r"password\w*", r"credential\w*", r"exfiltrat\w*", r"shell",
    r"executable", r"remote", r"deseriali[sz]\w*", r"escalat\w*", r"flaw\w*", r"weakness\w*",
    r"insecure", r"DoS", r"RCE", r"execution", r"validation", r"saniti[sz]\w*",
    r"misconfigur\w*", r"forgery", r"impersonat\w*", r"hijack\w*", r"spoof\w*",
    r"uninitiali[sz]\w*", r"double[ -]free", r"unprotect\w*", r"MITM",
]  # fmt: skip
# Any one of these words says the text is about software or hardware.
SOFTWARE_WORDS = [
    r"application", r"software", r"hardware", r"firmware", r"browser", r"server", r"kernel",
    r"driver", r"program", r"plug[ -]?in", r"library", r"libraries", r"protocol", r"API",
    r"module", r"component", r"function", r"device", r"database", r"package", r"network",
    r"router", r"operating system", r"Linux", r"Windows", r"macOS", r"Android", r"JavaScript",
    r"PHP", r"Python", r"Chrome", r"Mozilla", r"Apache", r"Cisco", r"Microsoft", r"client",
    r"web", r"HTTP\w*", r"SSH", r"SSL", r"TLS", r"HTML", r"file", r"buffer", r"pointer",
    r"socket", r"version", r"command",
]  # fmt: skip
SECURITY_CUE = re.compile(r"\b(?:" + "|".join(SECURITY_WORDS) + r")\b", re.IGNORECASE)
SOFTWARE_CUE = re.compile(r"\b(?:" + "|".join(SOFTWARE_WORDS) + r")\b", re.IGNORECASE)

# Clearly off-topic text: a recipe, or everyday prose.
INGREDIENTS = frozenset({
    "flour", "eggs", "egg", "milk", "sugar", "butter", "honey", "salt", "pepper", "onion",
    "garlic", "rice", "chicken", "carrots", "potatoes", "dough", "batter", "pancakes",
})  # fmt: skip
COOKING = frozenset({
    "mix", "stir", "whisk", "bake", "fry", "boil", "simmer", "roast", "knead", "recipe", "cook",
    "cooking",
})  # fmt: skip
OUTDOORS = frozenset(
    {"peaceful", "walk", "garden", "flowers", "sunshine", "forest", "picnic", "scenery"}
)
PERSONAL_PROSE = re.compile(
    r"\b(?:dear (?:mom|dad|friend)|hello world|once upon a time)\b", re.IGNORECASE
)


def text_scope(text: object) -> tuple[bool, str]:
    """Return (in scope?, reason). Refuse only clearly off-topic text; keep uncertain text."""
    value = text if isinstance(text, str) else ""
    if not value.strip():
        return False, "missing_text"
    if len(WORD.findall(value)) < MIN_WORDS:
        return False, "too_short"
    if SECURITY_CUE.search(value):
        return True, "security_cue"
    if SOFTWARE_CUE.search(value):
        return True, "software_cue"
    words = set(re.findall(r"\b[a-z]+\b", value.lower()))
    if len(words & INGREDIENTS) >= 2 and words & COOKING:
        return False, "recipe_without_software_or_security_context"
    if len(words & OUTDOORS) >= 2 or PERSONAL_PROSE.search(value):
        return False, "ordinary_prose_without_software_or_security_context"
    return True, "uncertain_scope_retained"
