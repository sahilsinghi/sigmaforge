"""Turn replay results into pass/fail decisions and a quality score.

Pass / fail is strict and explainable. A rule fails if any of these hold:

* lint errors
* true-positive rate on its labelled positives is below ``min_tpr``
* an external (real-telemetry) sample produced fewer hits than required
* it matched a labelled negative (near-miss) event
* alerts per host per day on the benign baseline exceed its noise budget
* a backend marked ``required_for`` this rule type could not convert it
* the replay engine could not evaluate it

Quality (0-1) is what the coverage map is coloured by. Tagging a technique
is free; quality has to be earned by evidence::

    quality = confidence x evidence x specificity x headroom

* confidence  - author's stated confidence: low 0.5, medium 0.75, high 1.0
* evidence    - 0.4 for one labelled positive, +0.1 per additional positive
                (up to +0.3), +0.3 if real public telemetry also fires it
* specificity - 1.0 with labelled near-miss negatives, 0.85 without
* headroom    - 1.0 if benign noise is at most half the budget, else 0.9

Technique coverage combines rules as 1 - prod(1 - quality_i): a second
decent rule adds coverage, but ten weak ones never reach 100.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sigmaforge.convert import Conversion
from sigmaforge.lint import LintResult
from sigmaforge.replay import BenignCorpus, RuleRun
from sigmaforge.rules import CONFIDENCE_WEIGHT, RuleSpec


@dataclass
class RuleScore:
    key: str
    status: str  # pass | fail
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    tpr: float | None = None
    positives_matched: int = 0
    positives_total: int = 0
    externals_passed: int = 0
    externals_total: int = 0
    externals_skipped: int = 0
    negative_fp: int = 0
    negatives_total: int = 0
    alerts_per_host_day: float | None = None
    quality: float = 0.0
    quality_parts: dict[str, float] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "status": self.status, "failures": self.failures, "warnings": self.warnings,
            "tpr": self.tpr, "positives_matched": self.positives_matched, "positives_total": self.positives_total,
            "externals_passed": self.externals_passed, "externals_total": self.externals_total,
            "externals_skipped": self.externals_skipped, "negative_fp": self.negative_fp,
            "negatives_total": self.negatives_total, "alerts_per_host_day": self.alerts_per_host_day,
            "quality": round(self.quality, 4), "quality_parts": self.quality_parts,
        }


def score_rule(
    spec: RuleSpec,
    run: RuleRun,
    lint: LintResult,
    conversions: dict[str, Conversion],
    benign: BenignCorpus,
    required_backends: dict[str, list[str]],
    min_tpr: float,
) -> RuleScore:
    s = RuleScore(key=spec.key, status="pass")
    s.failures.extend(f"lint: {e}" for e in lint.errors)
    s.warnings.extend(f"lint: {w}" for w in lint.warnings)
    if run.error:
        s.failures.append(run.error)

    # -- positives -------------------------------------------------------
    if spec.is_correlation:
        s.positives_total = len(run.positives)
        s.positives_matched = sum(1 for p in run.positives if p.passed)
    else:
        s.positives_total = sum(p.expected for p in run.positives)
        s.positives_matched = sum(min(p.hits, p.expected) for p in run.positives)
    if s.positives_total:
        s.tpr = s.positives_matched / s.positives_total
        threshold = spec.min_tpr if spec.meta.get("min_tpr") is not None else min_tpr
        if s.tpr < threshold:
            missed = [m for p in run.positives for m in p.missed][:5]
            unit = "scenarios" if spec.is_correlation else "positive events"
            detail = f" (missed: {', '.join(missed)})" if missed else ""
            s.failures.append(
                f"true-positive rate {s.tpr:.0%} < {threshold:.0%}: matched {s.positives_matched}/{s.positives_total} {unit}{detail}"
            )

    # -- external real telemetry ----------------------------------------
    for ext in run.externals:
        if ext.passed is None:
            s.externals_skipped += 1
            s.warnings.append(f"external sample skipped: {ext.source} ({ext.note})")
            continue
        s.externals_total += 1
        if ext.passed:
            s.externals_passed += 1
        else:
            reason = ext.note or f"{ext.hits} hits, needs >= {ext.expected}"
            s.failures.append(f"real-telemetry sample {ext.source}: {reason}")

    # -- negatives -------------------------------------------------------
    for neg in run.negatives:
        s.negatives_total += neg.events if not spec.is_correlation else 1
        if not neg.passed:
            s.negative_fp += neg.hits
            s.failures.append(f"fired on labelled negative {neg.source}: {'; '.join(neg.missed[:3])}")

    # -- noise -------------------------------------------------------------
    host_days = benign.host_days
    if host_days:
        s.alerts_per_host_day = run.benign_hits / host_days
    budget = spec.noise_budget
    if not spec.building_block and budget is not None and s.alerts_per_host_day is not None:
        if s.alerts_per_host_day > budget:
            s.failures.append(
                f"noise {s.alerts_per_host_day:.3f} alerts/host/day exceeds budget {budget:g} "
                f"({run.benign_hits} alerts over {host_days} host-days)"
            )

    # -- conversions -------------------------------------------------------
    kind = "correlation" if spec.is_correlation else "detection"
    for backend, conv in conversions.items():
        if conv.ok:
            continue
        if kind in required_backends.get(backend, []):
            s.failures.append(f"{backend} conversion failed: {conv.error}")
        else:
            s.warnings.append(f"{backend} cannot express this rule: {conv.error}")

    if s.failures:
        s.status = "fail"
    s.quality, s.quality_parts = quality(spec, run, s)
    return s


def quality(spec: RuleSpec, run: RuleRun, s: RuleScore) -> tuple[float, dict[str, float]]:
    if s.status != "pass":
        return 0.0, {}
    confidence = CONFIDENCE_WEIGHT.get(spec.confidence, 0.75)
    n_pos = s.positives_total if spec.is_correlation else sum(p.events for p in run.positives)
    evidence = 0.4 + 0.1 * min(max(n_pos - 1, 0), 3)
    if s.externals_passed:
        evidence += 0.3
    evidence = min(evidence, 1.0)
    specificity = 1.0 if run.negatives else 0.85
    headroom = 1.0
    budget = spec.noise_budget
    if budget and s.alerts_per_host_day is not None and not spec.building_block:
        headroom = 1.0 if s.alerts_per_host_day <= 0.5 * budget else 0.9
    parts = {"confidence": confidence, "evidence": round(evidence, 3), "specificity": specificity, "headroom": headroom}
    return confidence * evidence * specificity * headroom, parts
