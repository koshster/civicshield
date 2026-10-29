"""Application settings, loaded from environment variables (see .env.example).

Every setting is prefixed with ``CIVICSHIELD_``. Secrets are typed as ``SecretStr`` so
they print as ``**********`` in logs, reprs and tracebacks instead of leaking.
"""

from __future__ import annotations

import ipaddress
from enum import StrEnum
from functools import lru_cache
from typing import Annotated

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Environment(StrEnum):
    DEV = "dev"
    TEST = "test"
    LAB = "lab"
    PROD = "prod"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CIVICSHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Environment = Environment.DEV
    # Used to sign session cookies and CSRF tokens. Must be long and random in prod.
    secret_key: SecretStr = SecretStr("dev-insecure-change-me")

    database_url: str = "postgresql+asyncpg://civicshield:civicshield@localhost:5432/civicshield"
    redis_url: str = "redis://localhost:6379/0"

    log_level: str = "INFO"
    log_json: bool = True

    # Sessions
    session_ttl_hours: int = 12
    cookie_secure: bool = True  # set False only for local http:// development

    # Built React app (frontend/dist). When set, the API process also serves the SPA so
    # the browser sees a single origin: no CORS, and the strict cookie/CSRF model holds.
    frontend_dist: str | None = None

    # Volunteer time per week that the "fix these this week" plan fills.
    weekly_budget_minutes: int = Field(default=120, ge=15, le=2400)

    # Scanner politeness and safety
    scanner_user_agent: str = (
        "CivicShield/0.1 (+https://github.com/koshster/civicshield; authorized scan)"
    )
    scanner_requests_per_second: float = 2.0
    scanner_burst: int = 5
    scanner_timeout_seconds: float = 10.0
    scanner_max_redirects: int = 5
    # Optional custom DNS resolver (the lab uses its own CoreDNS server).
    dns_nameservers: Annotated[list[str], NoDecode] = Field(default_factory=list)
    # Private address ranges the scanner is allowed to reach. Only honored when env=lab
    # (see validator below): in any other environment, reaching private IPs is exactly
    # the SSRF/DNS-rebinding attack we defend against.
    allowed_private_cidrs: Annotated[list[str], NoDecode] = Field(default_factory=list)
    # Extra CA bundle to trust (the lab uses its own CA). Empty = system trust store only.
    extra_ca_bundle: str = ""

    # Domain verification
    verification_txt_prefix: str = "civicshield-verification="
    verification_file_path: str = "/.well-known/civicshield-verification.txt"
    verification_max_age_days: int = 30

    # Optional LLM layer (phase 2). Off unless an API key is provided.
    llm_api_key: SecretStr | None = None

    @model_validator(mode="before")
    @classmethod
    def _split_lists(cls, data: dict[str, object]) -> dict[str, object]:
        # Allow comma-separated env vars: CIVICSHIELD_DNS_NAMESERVERS=10.0.0.2,10.0.0.3
        for key in ("dns_nameservers", "allowed_private_cidrs"):
            value = data.get(key)
            if isinstance(value, str):
                data[key] = [v.strip() for v in value.split(",") if v.strip()]
        return data

    @model_validator(mode="after")
    def _safety_checks(self) -> Settings:
        if self.allowed_private_cidrs and self.env is not Environment.LAB:
            raise ValueError(
                "CIVICSHIELD_ALLOWED_PRIVATE_CIDRS is only permitted when CIVICSHIELD_ENV=lab"
            )
        for cidr in self.allowed_private_cidrs:
            ipaddress.ip_network(cidr)  # raises on garbage input
        if self.env is Environment.PROD:
            key = self.secret_key.get_secret_value()
            if len(key) < 32 or key.startswith("dev-"):
                raise ValueError("CIVICSHIELD_SECRET_KEY must be a 32+ char random value in prod")
        return self

    @property
    def private_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(c) for c in self.allowed_private_cidrs]


@lru_cache
def get_settings() -> Settings:
    return Settings()
