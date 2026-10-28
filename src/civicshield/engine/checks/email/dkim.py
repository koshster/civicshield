"""DKIM selector discovery and key strength.

There is no way to list a domain's DKIM selectors: each one lives at
``<selector>._domainkey.<domain>`` and you have to know the name. So we try:
1. selectors used by the email providers we can *detect* (from MX and SPF includes), and
2. a short list of very common selectors.
If nothing is found, we say "not found" at LOW confidence, never "missing". The org may
use a selector we didn't guess.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

# provider → (patterns matched against MX hosts / SPF includes, selectors they use)
PROVIDERS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "Google Workspace": (("google.com", "googlemail.com", "_spf.google.com"), ("google",)),
    "Microsoft 365": (
        ("protection.outlook.com", "spf.protection.outlook.com"),
        ("selector1", "selector2"),
    ),
    "Mailchimp": (("servers.mcsv.net", "mcsv.net", "mandrillapp.com"), ("k1", "k2", "k3")),
    "SendGrid": (("sendgrid.net",), ("s1", "s2", "smtpapi")),
    "Mailgun": (("mailgun.org",), ("mx", "smtp", "pic", "k1")),
    "Amazon SES": (("amazonses.com",), ()),  # SES uses random selectors; can't guess
    "Zoho": (("zoho.com", "zohomail.com"), ("zmail", "zoho")),
    "Proton": (("protonmail.ch",), ("protonmail", "protonmail2", "protonmail3")),
    "Fastmail": (("messagingengine.com",), ("fm1", "fm2", "fm3")),
    "GoDaddy": (("secureserver.net",), ("default",)),
}
COMMON_SELECTORS = ("default", "dkim", "mail", "selector1", "selector2", "google", "k1", "s1")


def detect_providers(mx_hosts: list[str], spf_includes: list[str]) -> list[str]:
    names = [h.lower() for h in mx_hosts + spf_includes]
    return [
        p
        for p, (patterns, _) in PROVIDERS.items()
        if any(n == pat or n.endswith("." + pat) for n in names for pat in patterns)
    ]


def candidate_selectors(providers: list[str]) -> list[str]:
    ordered = [s for p in providers for s in PROVIDERS[p][1]] + list(COMMON_SELECTORS)
    return list(dict.fromkeys(ordered))


@dataclass(frozen=True)
class DKIMKey:
    selector: str
    key_type: str  # "rsa" | "ed25519"
    bits: int | None  # None if unparseable
    revoked: bool  # empty p= means the key was deliberately revoked


def parse_dkim(selector: str, txt: str) -> DKIMKey | None:
    tags = {}
    for part in txt.split(";"):
        k, sep, v = part.strip().partition("=")
        if sep:
            tags[k.strip().lower()] = "".join(v.split())
    if "p" not in tags:
        return None
    key_type = tags.get("k", "rsa").lower()
    if not tags["p"]:
        return DKIMKey(selector, key_type, None, revoked=True)
    bits: int | None = None
    if key_type == "rsa":
        try:
            key = load_der_public_key(base64.b64decode(tags["p"]))
            if isinstance(key, rsa.RSAPublicKey):
                bits = key.key_size
        except (ValueError, binascii.Error):
            bits = None
    else:
        bits = 256
    return DKIMKey(selector, key_type, bits, revoked=False)
