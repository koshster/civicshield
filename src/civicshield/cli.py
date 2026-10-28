"""Operator command-line interface: ``civicshield --help``."""

from __future__ import annotations

import asyncio

import typer
from sqlalchemy import func, select

from civicshield.audit import Actor, record, verify_chain
from civicshield.auth.passwords import hash_password
from civicshield.db.session import dispose_engine, get_sessionmaker
from civicshield.models import User

app = typer.Typer(help="CivicShield operator commands", no_args_is_help=True)


@app.command("create-operator")
def create_operator(
    email: str = typer.Option(..., prompt=True),
    password: str = typer.Option(..., prompt=True, hide_input=True, confirmation_prompt=True),
) -> None:
    """Create the deployment operator account (there is no public sign-up)."""

    async def _run() -> None:
        async with get_sessionmaker()() as db:
            exists = (
                await db.execute(select(User).where(func.lower(User.email) == email.lower()))
            ).scalar_one_or_none()
            if exists:
                raise typer.BadParameter("a user with that email already exists")
            user = User(
                email=email.lower(), password_hash=hash_password(password), is_operator=True
            )
            db.add(user)
            await db.flush()
            await record(
                db,
                actor=Actor.system("cli"),
                action="user.operator_created",
                target_type="user",
                target_id=user.id,
            )
            await db.commit()
        await dispose_engine()

    asyncio.run(_run())
    typer.echo(f"Operator {email} created.")


@app.command("verify-audit")
def verify_audit() -> None:
    """Recompute the audit hash chain and report the first tampered event, if any."""

    async def _run() -> int | None:
        async with get_sessionmaker()() as db:
            bad = await verify_chain(db)
        await dispose_engine()
        return bad

    bad = asyncio.run(_run())
    if bad is None:
        typer.echo("Audit chain intact.")
    else:
        typer.echo(f"Audit chain BROKEN at event id {bad}.", err=True)
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
