"""Auto-tuning suggestions: which field values cause a rule's benign hits?

For each benign hit the tuner looks at the fields an analyst would filter on
(parent process, image, user, host, registry target ...). A candidate
exclusion is proposed only if:

* it removes a meaningful share of the benign hits, and
* replaying the labelled positives *with the exclusion applied* still
  matches every positive event and every real-telemetry sample.

Suggestions are printed as a Sigma ``filter_*`` block for a human to review;
nothing is written to the rule automatically. Exclusions are a trade-off -
an attacker who can make their activity look like the excluded value walks
past the rule - so every suggestion lists what it would hide.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sigmaforge import datasets
from sigmaforge.engine import compile_rule
from sigmaforge.events import Event, load_events
from sigmaforge.replay import BenignCorpus, RuleRun
from sigmaforge.rules import RuleSpec

CANDIDATE_FIELDS = (
    "ParentImage", "Image", "SourceImage", "OriginalFileName", "User", "Computer",
    "TargetObject", "Details", "QueryName", "PipeName", "ImagePath", "ServiceName", "CommandLine",
)
USER_DIR = re.compile(r"^[A-Za-z]:\\Users\\[^\\]+(\\.*)$")


@dataclass
class Suggestion:
    field: str
    modifier: str  # "" (equals) or "endswith"
    value: str
    removed: int
    remaining: int
    positives_kept: bool

    def yaml(self, index: int) -> str:
        key = f"{self.field}|{self.modifier}" if self.modifier else self.field
        value = self.value.replace("'", "''")
        return f"  filter_tuning_{index}:\n    {key}: '{value}'"


def _candidates(hits: list[Event]) -> list[tuple[str, str, str, int]]:
    out = []
    for fieldname in CANDIDATE_FIELDS:
        exact: Counter[str] = Counter()
        tails: Counter[str] = Counter()
        for ev in hits:
            value = ev.get(fieldname)
            if value in (None, ""):
                continue
            text = str(value)
            exact[text] += 1
            m = USER_DIR.match(text.strip('"'))
            if m:
                tails[m.group(1)] += 1
        for value, count in exact.most_common(3):
            out.append((fieldname, "", value, count))
        for tail, count in tails.most_common(2):
            if count > exact.get(tail, 0):
                out.append((fieldname, "endswith", tail, count))
    return out


def _excluded(ev: Event, fieldname: str, modifier: str, value: str) -> bool:
    raw = ev.get(fieldname)
    if raw is None:
        return False
    text = str(raw).strip('"').lower()
    target = value.lower()
    return text.endswith(target) if modifier == "endswith" else text == target


def suggest(spec: RuleSpec, run: RuleRun, benign: BenignCorpus, root: Path, top: int = 5) -> str:
    lines = [f"Rule: {spec.title} ({spec.key})"]
    host_days = benign.host_days or 1
    rate = run.benign_hits / host_days
    budget = spec.noise_budget
    lines.append(
        f"Benign hits: {run.benign_hits} over {host_days} host-days = {rate:.3f} alerts/host/day"
        + (f" (budget {budget:g})" if budget is not None else "")
    )
    if spec.is_correlation:
        lines.append("Correlation rules are tuned through their base rules; run tune on those.")
        return "\n".join(lines)
    if not run.benign_events:
        lines.append("No benign hits - nothing to tune.")
        return "\n".join(lines)

    compiled = compile_rule(spec.rule)
    positives = load_events(spec.tests.positive) if spec.tests.positive else []
    externals: list[tuple[Any, list[Event]]] = []
    for ext in spec.tests.external:
        path = datasets.local_path(root, ext.dataset, ext.path)
        if path.exists():
            externals.append((ext, load_events([path], strict=False)))

    suggestions: list[Suggestion] = []
    total = len(run.benign_events)
    # A suggestion must explain a real share of the noise: values seen once
    # (a single host, a PID-stamped pipe name) are not worth a permanent blind spot.
    min_count = 1 if total == 1 else max(2, -(-total // 4))
    for fieldname, modifier, value, count in _candidates(run.benign_events):
        if count < min_count:
            continue
        remaining = sum(1 for ev in run.benign_events if not _excluded(ev, fieldname, modifier, value))
        kept = all(compiled.matches(ev) and not _excluded(ev, fieldname, modifier, value)
                   for ev in positives if compiled.matches(ev))
        for ext, events in externals:
            hits = sum(1 for ev in events if compiled.matches(ev) and not _excluded(ev, fieldname, modifier, value))
            kept = kept and hits >= ext.min_hits
        suggestions.append(Suggestion(fieldname, modifier, value, run.benign_hits - remaining, remaining, kept))

    safe = [s for s in suggestions if s.positives_kept]
    # prefer what-it-is fields (process, path) over where-it-ran (Computer)
    safe.sort(key=lambda s: (-s.removed, s.field == "Computer", len(s.value)))
    unsafe = [s for s in suggestions if not s.positives_kept]
    lines.append("")
    lines.append("Top values among benign hits:")
    for ev_field, _, value, count in sorted(_candidates(run.benign_events), key=lambda c: -c[3])[: top * 2]:
        lines.append(f"  {count:4d}  {ev_field}: {value[:120]}")
    lines.append("")
    if not safe:
        lines.append("No single-field exclusion removes benign hits without also hiding a labelled positive.")
    else:
        lines.append("Suggested exclusions (positives and real samples still fire with each one applied):")
        for i, s in enumerate(safe[:top], 1):
            projected = s.remaining / host_days
            lines.append(f"  [{i}] removes {s.removed}/{run.benign_hits} hits -> {projected:.3f} alerts/host/day")
            lines.append(s.yaml(i))
        lines.append("")
        lines.append("Add the chosen block(s) under detection and extend the condition with")
        lines.append("  `and not 1 of filter_tuning_*`")
        lines.append("Review each one: anything matching the excluded value becomes invisible to this rule.")
    if unsafe:
        lines.append("")
        lines.append("Rejected (would hide labelled attack telemetry):")
        for s in unsafe[:top]:
            lines.append(f"  {s.field}{'|' + s.modifier if s.modifier else ''}: {s.value[:100]}")
    return "\n".join(lines)
