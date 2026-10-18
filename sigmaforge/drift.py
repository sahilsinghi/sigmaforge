"""Noise drift: replay rules on fresh benign data and compare with main.

Run nightly against the newest benign export. A rule has drifted when its
alerts per host per day exceed its budget, or grow past both
``ratio x baseline`` and ``baseline + min_delta``. The nightly workflow
turns a drift report into a GitHub issue.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from sigmaforge.config import Config
from sigmaforge.replay import Replayer, load_benign
from sigmaforge.rules import load_rules


@dataclass
class DriftItem:
    key: str
    before: float | None
    after: float
    budget: float | None
    reason: str
    examples: list[str] = field(default_factory=list)


@dataclass
class DriftReport:
    host_days: int
    events: int
    items: list[DriftItem]
    checked: int

    @property
    def drifted(self) -> bool:
        return bool(self.items)

    def text(self) -> str:
        lines = [f"Replayed {self.checked} alerting rules on {self.events:,} fresh benign events ({self.host_days} host-days)."]
        if not self.items:
            lines.append("No noise drift.")
        for item in self.items:
            before = "n/a" if item.before is None else f"{item.before:.3f}"
            lines.append(f"DRIFT {item.key}: {before} -> {item.after:.3f} alerts/host/day ({item.reason})")
            lines += [f"    {e}" for e in item.examples[:3]]
        return "\n".join(lines)

    def markdown(self) -> str:
        lines = ["<!-- sigmaforge-drift -->", "## Detection noise drift", "",
                 f"Nightly replay of {self.checked} alerting rules on {self.events:,} fresh benign events "
                 f"({self.host_days} host-days).", "",
                 "| Rule | Baseline | Now | Budget | Why |", "|---|---|---|---|---|"]
        for item in self.items:
            before = "n/a" if item.before is None else f"{item.before:.3f}"
            budget = "-" if item.budget is None else f"{item.budget:g}"
            lines.append(f"| `{item.key}` | {before} | {item.after:.3f} | {budget} | {item.reason} |")
        lines.append("")
        for item in self.items:
            if item.examples:
                lines.append(f"<details><summary>{item.key}: example hits</summary>\n")
                lines += [f"- `{e}`" for e in item.examples[:10]]
                lines.append("\n</details>")
        lines.append("\nRun `sigmaforge tune <rule> --benign <path>` for exclusion suggestions.")
        return "\n".join(lines) + "\n"


def detect_drift(cfg: Config, benign_paths: list[Path], ratio: float = 2.0, min_delta: float = 0.02) -> DriftReport:
    baseline = {}
    if cfg.baseline_metrics.exists():
        baseline = json.loads(cfg.baseline_metrics.read_text(encoding="utf-8")).get("rules", {})
    specs, _ = load_rules(cfg.rules_dir, cfg.root)
    benign = load_benign(benign_paths, cfg.root)
    host_days = benign.host_days or 1
    replayer = Replayer(cfg.root, benign)
    items = []
    checked = 0
    for spec in specs:
        if spec.building_block:
            continue
        checked += 1
        run = replayer.run(spec)
        after = run.benign_hits / host_days
        before = baseline.get(spec.key, {}).get("alerts_per_host_day")
        budget = spec.noise_budget
        reason = None
        if budget is not None and after > budget:
            reason = f"over budget {budget:g}"
        elif before is not None and after > max(before * ratio, before + min_delta):
            reason = f"more than {ratio:g}x baseline"
        if reason:
            examples = [f"{e['host']} {e['summary'][:150]}" for e in run.benign_examples]
            items.append(DriftItem(spec.key, before, after, budget, reason, examples))
    return DriftReport(host_days=benign.host_days, events=len(benign.events), items=items, checked=checked)
