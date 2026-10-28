"""Structured logging with central secret redaction.

Every log line is a JSON object (in prod) so it can be searched and aggregated. Instead of
trusting every call site to avoid logging secrets, a structlog processor scrubs values whose
*key* looks sensitive and values that *look* like credentials, before rendering.
"""

from __future__ import annotations

import logging
import re
from collections.abc import MutableMapping
from typing import Any

import structlog

SENSITIVE_KEYS = re.compile(
    r"(pass(word)?|secret|token|api[_-]?key|authorization|cookie|session|csrf)", re.IGNORECASE
)
# Value patterns: bearer tokens, our verification tokens, and long hex/base64 blobs.
SENSITIVE_VALUES = re.compile(
    r"(Bearer\s+\S+|civicshield-verification=\S+|\b[A-Za-z0-9_\-]{40,}\b)"
)
REDACTED = "[REDACTED]"


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        return SENSITIVE_VALUES.sub(REDACTED, value)
    if isinstance(value, dict):
        return {
            k: REDACTED if SENSITIVE_KEYS.search(str(k)) else _redact(v) for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [_redact(v) for v in value]
    return value


def redact_processor(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    for key in list(event_dict):
        if SENSITIVE_KEYS.search(key):
            event_dict[key] = REDACTED
        else:
            event_dict[key] = _redact(event_dict[key])
    return event_dict


def configure_logging(level: str = "INFO", json: bool = True) -> None:
    renderer: Any = structlog.processors.JSONRenderer() if json else structlog.dev.ConsoleRenderer()
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,  # e.g. scan_id bound per job
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            redact_processor,
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping()[level.upper()]
        ),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger
