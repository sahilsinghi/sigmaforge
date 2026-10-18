"""ATT&CK coverage that only counts tested, passing detections.

A technique lights up only if at least one *alerting* rule tagged with it
passes every test. Its score combines the quality of those rules
(``1 - prod(1 - q)``). Techniques that are tagged but whose rules fail or
are untested are exported in grey with the reason, so the map shows the gap
instead of hiding it. Building-block rules never count as coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sigmaforge import attack
from sigmaforge.rules import RuleSpec
from sigmaforge.scoring import RuleScore

NAVIGATOR_VERSION = "5.1.0"
LAYER_VERSION = "4.5"
GREY = "#d9d9d9"


@dataclass
class TechniqueCoverage:
    technique: str
    name: str
    tactics: list[str]
    score: float  # 0..1, 0 when no passing rule
    passing: list[str] = field(default_factory=list)
    failing: list[str] = field(default_factory=list)

    @property
    def covered(self) -> bool:
        return bool(self.passing)

    def band(self) -> str:
        if not self.covered:
            return "gap"
        if self.score >= 0.75:
            return "strong"
        if self.score >= 0.5:
            return "moderate"
        return "weak"

    def to_json(self) -> dict[str, Any]:
        return {
            "technique": self.technique, "name": self.name, "tactics": self.tactics,
            "score": round(self.score, 4), "band": self.band(), "passing": self.passing, "failing": self.failing,
        }


def compute(specs: list[RuleSpec], scores: dict[str, RuleScore]) -> dict[str, TechniqueCoverage]:
    att = attack.load()
    out: dict[str, TechniqueCoverage] = {}
    for spec in specs:
        if spec.building_block:
            continue
        sc = scores[spec.key]
        for tech in spec.techniques:
            cov = out.get(tech)
            if cov is None:
                cov = TechniqueCoverage(tech, att.name(tech), att.tactics_of(tech), score=0.0)
                out[tech] = cov
            if sc.status == "pass":
                cov.passing.append(spec.key)
            else:
                cov.failing.append(spec.key)
    for tech, cov in out.items():
        miss = 1.0
        for key in cov.passing:
            miss *= 1.0 - scores[key].quality
        cov.score = 1.0 - miss if cov.passing else 0.0
    return dict(sorted(out.items()))


def tactic_summary(coverage: dict[str, TechniqueCoverage]) -> list[dict[str, Any]]:
    att = attack.load()
    rows = []
    for tid, short in att.tactics:
        techs = [c for c in coverage.values() if short in c.tactics]
        rows.append({
            "tactic": short,
            "id": tid,
            "covered": sum(1 for c in techs if c.covered),
            "tagged": len(techs),
            "best": max((c.score for c in techs), default=0.0),
            "techniques": [c.to_json() for c in techs],
        })
    return rows


def navigator_layer(coverage: dict[str, TechniqueCoverage], title: str = "SigmaForge tested coverage",
                    description: str = "") -> dict[str, Any]:
    att = attack.load()
    techniques = []
    for cov in coverage.values():
        entry: dict[str, Any] = {
            "techniqueID": cov.technique,
            "enabled": True,
            "showSubtechniques": "." not in cov.technique,
            "metadata": [{"name": "passing rule", "value": k} for k in cov.passing]
            + [{"name": "failing rule", "value": k} for k in cov.failing],
        }
        if cov.covered:
            entry["score"] = round(cov.score * 100)
            entry["comment"] = f"{len(cov.passing)} passing, tested rule(s); quality {cov.score:.2f}"
        else:
            entry["color"] = GREY
            entry["comment"] = "Tagged, but no rule for it passes its tests. Not counted as coverage."
        techniques.append(entry)
    return {
        "name": title,
        "versions": {"attack": att.version.split(".")[0], "navigator": NAVIGATOR_VERSION, "layer": LAYER_VERSION},
        "domain": "enterprise-attack",
        "description": description or (
            "Scores are earned by tests: a technique is coloured only when an alerting Sigma rule "
            "tagged with it fires on labelled attack telemetry, stays silent on near-miss negatives "
            "and stays inside its noise budget on the benign baseline. Grey = tagged but not passing."
        ),
        "filters": {"platforms": ["Windows"]},
        "sorting": 3,
        "layout": {
            "layout": "side", "aggregateFunction": "max", "showID": True, "showName": True,
            "showAggregateScores": True, "countUnscored": False, "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#fde68a", "#86efac", "#15803d"], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "Tested and passing (score = quality)", "color": "#86efac"},
            {"label": "Tagged, not passing", "color": GREY},
        ],
        "metadata": [{"name": "generator", "value": "sigmaforge"}, {"name": "attack", "value": att.version}],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1f2937",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }
