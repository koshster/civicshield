"""The curated remediation library: what to do about each kind of finding.

Entries live in ``library.yaml`` (data, not code) so non-programmers can review and
translate them. This module validates the file once at import time and renders entries
with a deliberately tiny template language: ``{{name}}`` substitution and nothing else.

Why not Jinja or ``str.format``? Fact values can come from the scanned site (a ``Server``
header, a cookie name). ``str.format`` allows attribute access (``{x.__class__}``) and
Jinja is a whole language. Neither is needed to put a hostname into a sentence, and plain
substitution can't be abused if a template is ever wrong. Rendered text is shown as
plain text by the UI (React escapes it), never as HTML.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from functools import cache
from pathlib import Path
from typing import Annotated, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from civicshield.enums import Category

LIBRARY_PATH = Path(__file__).with_name("library.yaml")
PLACEHOLDER = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")

# Effort levels → minutes of volunteer time, used for the weekly time budget.
EFFORT_MINUTES = {1: 15, 2: 60, 3: 240, 4: 480}


class TechnicalStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    platform: str
    snippet: str


class RemediationEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str
    title: str
    category: Category
    effort: Annotated[int, Field(ge=1, le=4)]
    why: str
    steps: list[str]
    technical: list[TechnicalStep] = Field(default_factory=list)
    verify: str = ""
    requires: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    @property
    def effort_minutes(self) -> int:
        return EFFORT_MINUTES[self.effort]

    def placeholders(self) -> set[str]:
        texts = [self.title, self.why, self.verify, *self.steps]
        texts += [t for step in self.technical for t in (step.platform, step.snippet)]
        return {m.group(1) for text in texts for m in PLACEHOLDER.finditer(text)}


class RenderedRemediation(BaseModel):
    key: str
    title: str
    category: Category
    effort: int
    effort_minutes: int
    why: str
    steps: list[str]
    technical: list[TechnicalStep]
    verify: str
    references: list[str]


def render_text(template: str, values: Mapping[str, Any]) -> str:
    """Substitute ``{{name}}``. A missing value renders as ``<name>``: a visible
    placeholder the tech helper fills in, rather than a silently broken command."""

    def sub(m: re.Match[str]) -> str:
        value = values.get(m.group(1))
        if value is None or value == "":
            return f"<{m.group(1)}>"
        if isinstance(value, list):
            return ", ".join(str(v) for v in value)
        return str(value)

    return PLACEHOLDER.sub(sub, template)


@cache
def load_library(path: Path = LIBRARY_PATH) -> dict[str, RemediationEntry]:
    raw: dict[str, dict[str, Any]] = yaml.safe_load(path.read_text())
    entries = {key: RemediationEntry(key=key, **spec) for key, spec in raw.items()}
    for entry in entries.values():
        unknown = set(entry.requires) - entries.keys()
        if unknown:
            raise ValueError(f"{entry.key} requires unknown keys: {sorted(unknown)}")
        if entry.category.value != entry.key.split(".", 1)[0]:
            raise ValueError(f"{entry.key}: category {entry.category} doesn't match key")
    return entries


def get_entry(key: str) -> RemediationEntry:
    """The entry for ``key``, or a generic fallback so a missing entry never breaks the
    UI. (A unit test makes sure every key the checks emit has a real entry.)"""
    entry = load_library().get(key)
    if entry is not None:
        return entry
    category = key.split(".", 1)[0]
    return RemediationEntry(
        key=key,
        title="Review this finding with your tech helper",
        category=Category(category) if category in Category else Category.HEADERS,
        effort=3,
        why="CivicShield doesn't have written guidance for this finding yet.",
        steps=["Share the evidence below with your tech helper or website provider."],
    )


def render(key: str, *, asset: str, zone: str, facts: Mapping[str, Any]) -> RenderedRemediation:
    entry = get_entry(key)
    # asset/zone are set last so a fact can never shadow them.
    values = {**facts, "asset": asset, "zone": zone}
    return RenderedRemediation(
        key=entry.key,
        title=render_text(entry.title, values),
        category=entry.category,
        effort=entry.effort,
        effort_minutes=entry.effort_minutes,
        why=render_text(entry.why, values),
        steps=[render_text(s, values) for s in entry.steps],
        technical=[
            TechnicalStep(
                platform=render_text(t.platform, values), snippet=render_text(t.snippet, values)
            )
            for t in entry.technical
        ],
        verify=render_text(entry.verify, values),
        references=list(entry.references),
    )
