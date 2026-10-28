"""Password hashing with argon2id.

argon2id is the OWASP-recommended password hash: it's deliberately slow and memory-hard,
so brute-forcing leaked hashes on GPUs is expensive. The library picks a random salt per
password and encodes the parameters into the hash string.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()  # library defaults follow RFC 9106's recommended profile

MIN_PASSWORD_LENGTH = 12

# Verifying against a real hash when the user doesn't exist makes "unknown email" and
# "wrong password" take the same time, so response timing doesn't reveal which emails
# have accounts (user enumeration).
_DUMMY_HASH = _hasher.hash("civicshield-timing-equalizer")


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True when the hash used weaker parameters than the current defaults."""
    return _hasher.check_needs_rehash(password_hash)
