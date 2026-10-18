"""The merge gate: compare this run with the last-known-good baseline.

``baseline/metrics.json`` is regenerated on ``main`` after every merge and
committed. A pull request is blocked when:

* any rule fails (lint, positives, real samples, negatives, noise, required
  conversion, undocumented backend disagreement)
* a rule that passed on main no longer passes, or was deleted while it was
  the only coverage for a technique
* a technique that main covered is no longer covered
* a backend that could convert a rule on main no longer can

Warnings (shown, not blocking): noise rose sharply but is still inside the
budget, quality dropped, a rule was removed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class GateDecision:
    blocked: bool
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    improvements: list[str] = field(default_factory=list)
    baseline_found: bool = True

    def to_json(self) -> dict[str, Any]:
        return {
            "decision": "block" if self.blocked else "pass",
            "reasons": self.reasons,
            "warnings": self.warnings,
            "improvements": self.improvements,
            "baseline_found": self.baseline_found,
        }


def metrics_from_results(results: dict[str, Any]) -> dict[str, Any]:
    """The subset of results that main commits as the regression baseline."""
    rules = {}
    for r in results["rules"]:
        sc = r["score"]
        rules[r["key"]] = {
            "status": sc["status"],
            "tpr": sc["tpr"],
            "alerts_per_host_day": sc["alerts_per_host_day"],
            "externals_passed": sc["externals_passed"],
            "quality": sc["quality"],
            "building_block": r["building_block"],
            "techniques": r["techniques"],
            "conversions": {b: c["ok"] for b, c in r["conversions"].items()},
        }
    covered = sorted(t for t, c in results["coverage"].items() if c["passing"])
    return {
        "attack_version": results["attack_version"],
        "benign": {k: results["benign"].get(k) for k in ("events", "hosts", "host_days")},
        "summary": results["summary"],
        "covered_techniques": covered,
        "rules": rules,
    }


def load_baseline(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def decide(results: dict[str, Any], baseline: dict[str, Any] | None, noise_ratio: float = 1.5) -> GateDecision:
    current = metrics_from_results(results)
    decision = GateDecision(blocked=False, baseline_found=baseline is not None)

    for err in results.get("global_errors", []):
        decision.reasons.append(f"repository: {err}")
    for r in results["rules"]:
        if r["score"]["status"] != "pass":
            failures = r["score"]["failures"] or ["failed"]
            for failure in failures[:4]:
                decision.reasons.append(f"`{r['key']}`: {failure}")
            if len(failures) > 4:
                decision.reasons.append(f"`{r['key']}`: ... and {len(failures) - 4} more (see the report)")

    if baseline is not None:
        base_rules = baseline.get("rules", {})
        cur_rules = current["rules"]
        for key, old in base_rules.items():
            new = cur_rules.get(key)
            if new is None:
                decision.warnings.append(f"`{key}` was removed")
                continue
            if old["status"] == "pass" and new["status"] != "pass":
                decision.reasons.append(f"regression: `{key}` passed on main and fails now")
            for backend, ok in old.get("conversions", {}).items():
                if ok and not new["conversions"].get(backend, False):
                    decision.reasons.append(f"regression: `{key}` no longer converts to {backend}")
            o, n = old.get("alerts_per_host_day"), new.get("alerts_per_host_day")
            if (not new.get("building_block") and o is not None and n is not None
                    and n > max(o * noise_ratio, o + 0.005) and new["status"] == "pass"):
                decision.warnings.append(f"`{key}` noise rose {o:.3f} -> {n:.3f} alerts/host/day (still within budget)")
            if new["status"] == "pass" and old["status"] == "pass" and new["quality"] + 1e-9 < old["quality"]:
                decision.warnings.append(f"`{key}` quality dropped {old['quality']:.2f} -> {new['quality']:.2f}")
            if old["status"] != "pass" and new["status"] == "pass":
                decision.improvements.append(f"`{key}` now passes")
        for key in cur_rules:
            if key not in base_rules:
                status = cur_rules[key]["status"]
                (decision.improvements if status == "pass" else decision.warnings).append(f"new rule `{key}` ({status})")
        lost = sorted(set(baseline.get("covered_techniques", [])) - set(current["covered_techniques"]))
        for tech in lost:
            decision.reasons.append(f"coverage regression: {tech} was covered on main and is not covered now")
        gained = sorted(set(current["covered_techniques"]) - set(baseline.get("covered_techniques", [])))
        for tech in gained:
            decision.improvements.append(f"newly covered technique {tech}")

    decision.blocked = bool(decision.reasons)
    return decision
