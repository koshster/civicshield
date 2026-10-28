import pytest
from pydantic import ValidationError

from civicshield.config import Environment, Settings


def test_private_cidrs_rejected_outside_lab() -> None:
    with pytest.raises(ValidationError, match="only permitted"):
        Settings(env=Environment.DEV, allowed_private_cidrs=["10.0.0.0/8"])


def test_private_cidrs_allowed_in_lab_and_parsed_from_csv() -> None:
    s = Settings(env=Environment.LAB, allowed_private_cidrs="172.30.0.0/16, 10.9.0.0/24")  # type: ignore[arg-type]
    assert [str(n) for n in s.private_networks] == ["172.30.0.0/16", "10.9.0.0/24"]


def test_prod_requires_strong_secret() -> None:
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        Settings(env=Environment.PROD, secret_key="short")  # type: ignore[arg-type]


def test_secret_not_in_repr() -> None:
    s = Settings(secret_key="super-secret-value-that-should-not-print")  # type: ignore[arg-type]
    assert "super-secret" not in repr(s)
