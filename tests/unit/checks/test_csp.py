from hypothesis import given
from hypothesis import strategies as st

from civicshield.engine.checks.headers.csp import analyze_csp, parse_csp


def kinds(header: str) -> set[str]:
    return {w.kind for w in analyze_csp(parse_csp(header))}


def test_strict_policy_has_no_weaknesses() -> None:
    assert kinds("default-src 'self'; script-src 'self' 'nonce-abc'; object-src 'none'") == set()


def test_fallback_to_default_src() -> None:
    assert kinds("default-src 'self' 'unsafe-inline'") == {"unsafe_inline"}
    # script-src overrides default-src entirely
    assert kinds("default-src 'unsafe-inline'; script-src 'self'") == set()


def test_nonce_neutralizes_unsafe_inline() -> None:
    assert kinds("script-src 'unsafe-inline' 'nonce-r4nd0m'") == set()
    assert kinds("script-src 'unsafe-inline' 'sha256-abc='") == set()


def test_unsafe_eval_and_wildcards() -> None:
    assert kinds("script-src 'self' 'unsafe-eval' https:") == {"unsafe_eval", "wildcard"}
    assert kinds("script-src * 'strict-dynamic' 'nonce-x'") == set()


def test_no_script_restriction() -> None:
    assert kinds("img-src 'self'; frame-ancestors 'none'") == {"no_script_restriction"}


def test_parser_is_case_insensitive_for_keywords_and_first_directive_wins() -> None:
    p = parse_csp("SCRIPT-SRC 'SELF'; script-src *")
    assert p.sources("script-src") == ("'self'",)


@given(st.text(max_size=300))
def test_parser_never_crashes_on_arbitrary_input(header: str) -> None:
    analyze_csp(parse_csp(header))  # property: total function over any string
