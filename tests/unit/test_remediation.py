from __future__ import annotations

import ast
from pathlib import Path

import pytest

from civicshield.remediation import EFFORT_MINUTES, get_entry, load_library, render, render_text

CHECKS_DIR = Path(__file__).resolve().parents[2] / "src" / "civicshield" / "engine" / "checks"

# Fact names the checks attach to findings (see each check's analyze()). A template may
# use these besides {{asset}} and {{zone}}; anything else is a typo.
KNOWN_FACTS = {
    "not_after",
    "days_to_expiry",
    "software",
    "header",
    "cookie",
    "record_count",
    "all_qualifier",
    "limit",
    "lookups",
    "include",
    "policy",
    "selector",
    "key_bits",
}


def _literals(node: ast.expr) -> set[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.IfExp):
        return _literals(node.body) | _literals(node.orelse)
    raise AssertionError(f"remediation key must be a literal, got {ast.dump(node)}")


def emitted_remediation_keys() -> set[str]:
    """Every remediation key the checks can emit.

    All checks build findings through a local ``add(ftype, title, severity, rkey, ...)``
    helper, so the 4th positional argument of each ``add(...)`` call is a remediation key.
    Reading the source keeps the checks free of a second, hand-maintained key list.
    """
    keys: set[str] = set()
    for path in CHECKS_DIR.glob("*/check.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "add"
                and len(node.args) >= 4
            ):
                keys |= _literals(node.args[3])
    return keys


def test_ast_scan_finds_keys_from_every_check() -> None:
    keys = emitted_remediation_keys()
    assert {k.split(".", 1)[0] for k in keys} == {"tls", "headers", "email"}
    assert "email.enforce_dmarc" in keys and "email.lock_down_no_mail" in keys


def test_every_emitted_key_has_an_entry_and_no_entry_is_dead() -> None:
    library = load_library()
    emitted = emitted_remediation_keys()
    assert emitted - library.keys() == set(), "write library entries for these keys"
    assert library.keys() - emitted == set(), "no check emits these keys"


@pytest.mark.parametrize("key", sorted(load_library()))
def test_entry_is_complete_and_uses_only_known_placeholders(key: str) -> None:
    entry = load_library()[key]
    assert entry.title and entry.why and entry.steps
    assert entry.placeholders() <= KNOWN_FACTS | {"asset", "zone"}
    assert all(r.startswith("https://") for r in entry.references)


def test_prerequisites_are_acyclic() -> None:
    library = load_library()
    state: dict[str, int] = {}  # 1 = visiting, 2 = done

    def visit(key: str) -> None:
        assert state.get(key) != 1, f"prerequisite cycle through {key}"
        if state.get(key) == 2:
            return
        state[key] = 1
        for dep in library[key].requires:
            visit(dep)
        state[key] = 2

    for key in library:
        visit(key)


def test_render_substitutes_values() -> None:
    r = render(
        "tls.renew_certificate",
        asset="www.example.org",
        zone="example.org",
        facts={"days_to_expiry": 5, "not_after": "2026-11-02"},
    )
    assert r.title == "Renew the HTTPS certificate for www.example.org"
    assert "2026-11-02" in r.why and "(5 days" in r.why
    assert r.effort_minutes == EFFORT_MINUTES[r.effort]
    assert "{{" not in r.model_dump_json()


def test_missing_fact_renders_visible_placeholder() -> None:
    assert render_text("dig TXT {{include}}", {}) == "dig TXT <include>"
    assert render_text("x {{policy}}", {"policy": ""}) == "x <policy>"


def test_render_has_no_expression_language() -> None:
    # Only bare names are placeholders: no attribute access, indexing or calls.
    for tpl in ("{{asset.__class__}}", "{{asset[0]}}", "{{asset()}}", "{asset}"):
        assert render_text(tpl, {"asset": "x"}) == tpl


def test_facts_cannot_shadow_asset_or_zone() -> None:
    r = render(
        "headers.add_hsts", asset="a.example", zone="example", facts={"asset": "evil.example"}
    )
    assert "a.example" in r.title and "evil" not in r.model_dump_json()


def test_list_facts_are_joined() -> None:
    assert render_text("{{x}}", {"x": ["a", "b"]}) == "a, b"


def test_unknown_key_falls_back_to_generic_entry() -> None:
    entry = get_entry("headers.something_new")
    assert entry.effort == 3 and entry.steps
