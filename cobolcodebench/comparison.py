"""Strict file equality plus upstream's diagnostic mean of EM and fuzz.ratio.

Pin the dependency-free fuzzywuzzy backend (difflib.SequenceMatcher). Upstream
does not pin its optional python-Levenshtein accelerator; it can change ratios.
"""
from difflib import SequenceMatcher


def fuzz_ratio(actual: str, expected: str) -> int:
    if actual == expected:
        return 100
    if not actual or not expected:
        return 0
    return int(round(100 * SequenceMatcher(None, actual, expected).ratio()))


def compare_outputs(actual: dict[str, bytes | None], expected: dict[str, str]) -> tuple[bool, float, int]:
    exact_count = 0
    total = 0.0
    missing = False
    for name, text in expected.items():
        content = actual.get(name)
        if content is None:
            missing = True
            continue
        exact = content == text.encode('utf-8')
        exact_count += int(exact)
        try:
            decoded = content.decode('utf-8')
        except UnicodeError:
            missing = True  # Upstream's text-file decoding exception returns zero.
            continue
        # Upstream open(..., 'r') normalizes newlines for its diagnostic only.
        decoded = decoded.replace('\r\n', '\n').replace('\r', '\n')
        upstream_em = decoded == text
        total += (float(upstream_em) + fuzz_ratio(decoded, text) / 100) / 2
    diagnostic = 0.0 if missing or not expected else total / len(expected)
    return bool(expected) and exact_count == len(expected), diagnostic, exact_count
