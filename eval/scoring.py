"""Score scanner output against lab ground truth. Pure functions, no I/O beyond YAML.

Matching key is ``(finding_type, asset)``. For each scored zone:

* expected = every ``hosts`` type on the apex and on www, plus every ``zone`` type on the
  zone itself;
* found    = every issue the scan opened on the apex or www (the zone *is* the apex).

TP = expected ∩ found, FN = expected − found, FP = found − expected. A zone with no
expectations (the hardened control) contributes only FPs, which is the point: it measures
how noisy the scanner is on a site that does everything right.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

Key = tuple[str, str]  # (finding_type, asset)


@dataclass(frozen=True)
class ZoneTruth:
    zone: str
    hosts: tuple[str, ...] = ()
    www_types: tuple[str, ...] = ()
    zone_types: tuple[str, ...] = ()
    score: bool = True

    @property
    def assets(self) -> tuple[str, str]:
        return (self.zone, f"www.{self.zone}")

    def expected(self) -> set[Key]:
        keys = {(t, h) for t in self.hosts for h in self.assets}
        keys |= {(t, f"www.{self.zone}") for t in self.www_types}
        return keys | {(t, self.zone) for t in self.zone_types}


def load_ground_truth(path: Path) -> list[ZoneTruth]:
    raw: Mapping[str, Mapping[str, Any] | None] = yaml.safe_load(path.read_text())
    return [
        ZoneTruth(
            zone=zone,
            hosts=tuple((spec or {}).get("hosts") or ()),
            www_types=tuple((spec or {}).get("www") or ()),
            zone_types=tuple((spec or {}).get("zone") or ()),
            score=bool((spec or {}).get("score", True)),
        )
        for zone, spec in raw.items()
    ]


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0


@dataclass
class Report:
    overall: Counts
    by_category: dict[str, Counts]
    false_positives: list[Key] = field(default_factory=list)
    false_negatives: list[Key] = field(default_factory=list)


def category(finding_type: str) -> str:
    return finding_type.split(".", 1)[0]


def score(truth: Iterable[ZoneTruth], found: Iterable[Key]) -> Report:
    scored = [z for z in truth if z.score]
    in_scope_assets = {a for z in scored for a in z.assets}
    expected: set[Key] = set().union(*(z.expected() for z in scored))
    found_set = {(t, a.lower()) for t, a in found if a.lower() in in_scope_assets}

    by_cat: dict[str, Counts] = defaultdict(Counts)
    overall = Counts()
    for key in expected | found_set:
        c = by_cat[category(key[0])]
        if key in expected and key in found_set:
            c.tp += 1
            overall.tp += 1
        elif key in expected:
            c.fn += 1
            overall.fn += 1
        else:
            c.fp += 1
            overall.fp += 1
    return Report(
        overall=overall,
        by_category=dict(sorted(by_cat.items())),
        false_positives=sorted(found_set - expected),
        false_negatives=sorted(expected - found_set),
    )


def to_markdown(report: Report, *, extra: Mapping[str, str] | None = None) -> str:
    lines = [
        "| Category | TP | FP | FN | Precision | Recall |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    rows = [*report.by_category.items(), ("**overall**", report.overall)]
    for name, c in rows:
        lines.append(f"| {name} | {c.tp} | {c.fp} | {c.fn} | {c.precision:.2f} | {c.recall:.2f} |")
    for title, keys in (
        ("False positives", report.false_positives),
        ("False negatives", report.false_negatives),
    ):
        lines += ["", f"**{title}:** " + (", ".join(f"`{t}` on {a}" for t, a in keys) or "none")]
    for k, v in (extra or {}).items():
        lines += ["", f"**{k}:** {v}"]
    return "\n".join(lines) + "\n"
