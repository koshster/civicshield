"""Extract the certificate facts we reason about from a DER-encoded certificate."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class CertSummary:
    subject_cn: str | None
    issuer_cn: str | None
    sans: tuple[str, ...]
    not_before: datetime
    not_after: datetime
    key_type: str  # "RSA" | "EC" | "Ed25519" | ...
    key_bits: int
    signature_hash: str | None  # "sha256", "sha1", ... (None for Ed25519)
    self_issued: bool


def _cn(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def summarize(der: bytes) -> CertSummary:
    cert = x509.load_der_x509_certificate(der)
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = tuple(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        sans = ()
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, bits = "EC", key.curve.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        key_type, bits = "DSA", key.key_size
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key_type, bits = "Ed25519", 256
    elif isinstance(key, ed448.Ed448PublicKey):
        key_type, bits = "Ed448", 456
    else:
        key_type, bits = type(key).__name__, 0
    algo = cert.signature_hash_algorithm
    return CertSummary(
        subject_cn=_cn(cert.subject),
        issuer_cn=_cn(cert.issuer),
        sans=sans,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        key_type=key_type,
        key_bits=bits,
        signature_hash=algo.name if algo else None,
        self_issued=cert.subject == cert.issuer,
    )
