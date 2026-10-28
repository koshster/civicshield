"""Generate throwaway X.509 certificates for tests (no network, no fixtures on disk)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


@dataclass
class CertBundle:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey

    @property
    def der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)

    def write(self, directory: Path, name: str = "server") -> tuple[Path, Path]:
        cert_path, key_path = directory / f"{name}.crt", directory / f"{name}.key"
        cert_path.write_bytes(self.cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            self.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return cert_path, key_path


def make_cert(
    names: list[str],
    *,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    issuer: CertBundle | None = None,
    is_ca: bool = False,
    rsa_bits: int | None = None,
    hash_alg: hashes.HashAlgorithm | None = None,
) -> CertBundle:
    now = datetime.now(UTC)
    key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey = (
        rsa.generate_private_key(65537, rsa_bits)
        if rsa_bits
        else ec.generate_private_key(ec.SECP256R1())
    )
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.cert.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(days=1))
        .not_valid_after(not_after or now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    if not is_ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False
        )
    signer = issuer.key if issuer else key
    cert = builder.sign(signer, hash_alg or hashes.SHA256())
    return CertBundle(cert, key)
