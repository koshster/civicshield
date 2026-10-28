"""Content-Security-Policy parsing and weakness detection (CSP Level 3).

A CSP is ``directive source source; directive source ...``. What matters most is the
*effective* policy for scripts: ``script-src`` if present, otherwise ``default-src``
(the fallback rule). A policy can look strict and still allow inline scripts through
the fallback, and this module resolves that.
"""

from __future__ import annotations

from dataclasses import dataclass

# Sources that let an attacker who can inject markup run script anyway.
_WILDCARD_SOURCES = {"*", "http:", "https:", "data:", "blob:"}


@dataclass(frozen=True)
class CSPPolicy:
    directives: dict[str, tuple[str, ...]]

    def sources(self, directive: str) -> tuple[str, ...] | None:
        return self.directives.get(directive)

    def effective(self, directive: str) -> tuple[str, ...] | None:
        """Sources for ``directive``, falling back to default-src."""
        own = self.directives.get(directive)
        return own if own is not None else self.directives.get("default-src")


def parse_csp(header: str) -> CSPPolicy:
    directives: dict[str, tuple[str, ...]] = {}
    for part in header.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        # Per spec, a duplicate directive is ignored; the first one wins.
        if name not in directives:
            directives[name] = tuple(t.lower() if t.startswith("'") else t for t in tokens[1:])
    return CSPPolicy(directives)


@dataclass(frozen=True)
class CSPWeakness:
    kind: str  # "unsafe_inline" | "unsafe_eval" | "wildcard" | "no_script_restriction"
    detail: str


def analyze_csp(policy: CSPPolicy) -> list[CSPWeakness]:
    script = policy.effective("script-src")
    if script is None:
        return [
            CSPWeakness(
                "no_script_restriction",
                "neither script-src nor default-src is set, so scripts are unrestricted",
            )
        ]
    out: list[CSPWeakness] = []
    has_nonce_or_hash = any(
        s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in script
    )
    # With a nonce or hash present, CSP2+ browsers ignore 'unsafe-inline', which is kept
    # only as a fallback for very old browsers. So it's only a weakness without one.
    if "'unsafe-inline'" in script and not has_nonce_or_hash:
        out.append(CSPWeakness("unsafe_inline", "script sources include 'unsafe-inline'"))
    if "'unsafe-eval'" in script:
        out.append(CSPWeakness("unsafe_eval", "script sources include 'unsafe-eval'"))
    # 'strict-dynamic' makes browsers ignore host/scheme allow-lists, so wildcards are moot.
    wild = sorted(set(script) & _WILDCARD_SOURCES)
    if wild and "'strict-dynamic'" not in script:
        out.append(CSPWeakness("wildcard", f"script sources allow {', '.join(wild)}"))
    return out
