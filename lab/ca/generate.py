"""Generate the lab's throwaway CA and target certificates into lab/ca/out/.

Run with: uv run python lab/ca/generate.py

Everything here is for an isolated test network: the CA key is created fresh on every
run, lives only on your machine (out/ is gitignored), and is trusted only by the lab
scanner via CIVICSHIELD_EXTRA_CA_BUNDLE.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lab.cases import OUTSIDE_HOST, ZONES

OUT = Path(__file__).resolve().parent / "out"
NOW = datetime.now(UTC)


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CivicShield Lab (TEST ONLY)"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def _write(stem: str, key: ec.EllipticCurvePrivateKey, cert: x509.Certificate) -> None:
    (OUT / f"{stem}.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (OUT / f"{stem}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def make_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("CivicShield Lab Root CA"))
        .issuer_name(_name("CivicShield Lab Root CA"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(
    hosts: list[str],
    issuer: tuple[ec.EllipticCurvePrivateKey, x509.Certificate] | None,
    *,
    not_before: datetime,
    not_after: datetime,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Leaf certificate for ``hosts``. ``issuer=None`` makes it self-signed."""
    key = ec.generate_private_key(ec.SECP256R1())
    issuer_key, issuer_name = (issuer[0], issuer[1].subject) if issuer else (key, _name(hosts[0]))
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(hosts[0]))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
    )
    if issuer:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer[0].public_key()), False
        )
    return key, builder.sign(issuer_key, hashes.SHA256())


def main() -> None:
    OUT.mkdir(exist_ok=True)
    ca = make_ca()
    _write("ca", *ca)
    valid = {"not_before": NOW - timedelta(days=1), "not_after": NOW + timedelta(days=90)}

    hosts_by_target: dict[str, list[str]] = {}
    for zone in ZONES:
        hosts_by_target.setdefault(zone.target, []).extend(zone.hosts)
    hosts_by_target["outside"] = [OUTSIDE_HOST]

    for target, hosts in hosts_by_target.items():
        if target == "expired-cert":
            leaf = make_leaf(
                hosts, ca, not_before=NOW - timedelta(days=120), not_after=NOW - timedelta(days=30)
            )
        elif target == "self-signed":
            leaf = make_leaf(hosts, None, **valid)
        else:
            leaf = make_leaf(hosts, ca, **valid)
        _write(target, *leaf)
        print(f"  {target}: {', '.join(hosts)}")
    print(f"wrote certificates to {OUT}")


if __name__ == "__main__":
    main()
