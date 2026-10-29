from __future__ import annotations

import pytest
from typer.testing import CliRunner

from civicshield.cli import app


@pytest.mark.parametrize(
    ("email", "password", "complaint"),
    [
        # The login endpoint rejects special-use domains, so the CLI must too.
        ("admin@civicshield.local", "a-long-enough-password", "email"),
        ("not-an-email", "a-long-enough-password", "email"),
        ("op@example.org", "short", "12 characters"),
    ],
)
def test_create_operator_rejects_what_login_would_reject(
    email: str, password: str, complaint: str
) -> None:
    result = CliRunner().invoke(app, ["create-operator", "--email", email, "--password", password])
    assert result.exit_code != 0
    assert complaint in result.output


def test_valid_email_is_normalized() -> None:
    from civicshield.cli import _valid_email

    assert _valid_email("Op@Example.org") == "op@example.org"
