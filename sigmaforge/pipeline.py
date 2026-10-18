"""Run the whole pipeline once and collect every result in one document.

lint -> convert -> replay (positives, negatives, real samples, benign)
-> score -> coverage -> cross-backend equivalence (optional)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sigmaforge import __version__, attack, coverage, datasets
from sigmaforge.config import Config
from sigmaforge.convert import Conversion, convert_all, write_queries
from sigmaforge.lint import LintReport, lint_all
from sigmaforge.replay import BenignCorpus, Replayer, RuleRun, load_benign
from sigmaforge.rules import RuleSpec, load_rules
from sigmaforge.scoring import RuleScore, score_rule


@dataclass
class PipelineRun:
    config: Config
    specs: list[RuleSpec]
    lint: LintReport
    conversions: dict[str, dict[str, Conversion]]
    runs: dict[str, RuleRun]
    scores: dict[str, RuleScore]
    benign: BenignCorpus
    coverage: dict[str, coverage.TechniqueCoverage]
    equivalence: dict[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return not self.lint.global_errors and all(s.status == "pass" for s in self.scores.values())

    def results(self) -> dict[str, Any]:
        att = attack.load()
        alerting = [s for s in self.specs if not s.building_block]
        rules = []
        for spec in self.specs:
            score = self.scores[spec.key]
            run = self.runs[spec.key]
            rules.append({
                "key": spec.key,
                "id": spec.id,
                "title": spec.title,
                "path": str(spec.path.relative_to(self.config.root)),
                "level": spec.level,
                "kind": "correlation" if spec.is_correlation else "detection",
                "building_block": spec.building_block,
                "owner": spec.owner,
                "confidence": spec.confidence,
                "noise_budget": spec.noise_budget,
                "techniques": spec.techniques,
                "technique_names": {t: att.name(t) for t in spec.techniques},
                "tactics": spec.tactics,
                "description": (getattr(spec.rule, "description", "") or "").strip(),
                "lint": {"errors": self.lint.per_rule[spec.key].errors, "warnings": self.lint.per_rule[spec.key].warnings},
                "score": score.to_json(),
                "samples": {
                    "positive": [p.to_json() for p in run.positives],
                    "negative": [n.to_json() for n in run.negatives],
                    "external": [e.to_json() for e in run.externals],
                },
                "benign": {"hits": run.benign_hits, "examples": run.benign_examples},
                "runtime_ms": round(run.runtime_ms, 2),
                "conversions": {b: c.to_json() for b, c in self.conversions.get(spec.id, {}).items()},
                "equivalence": (self.equivalence or {}).get("rules", {}).get(spec.key),
            })
        covered = [c for c in self.coverage.values() if c.covered]
        tactics = coverage.tactic_summary(self.coverage)
        passing = sum(1 for s in self.scores.values() if s.status == "pass")
        return {
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sigmaforge_version": __version__,
            "attack_version": att.version,
            "status": "pass" if self.ok else "fail",
            "summary": {
                "rules": len(self.specs),
                "alerting_rules": len(alerting),
                "building_blocks": len(self.specs) - len(alerting),
                "passing": passing,
                "failing": len(self.specs) - passing,
                "techniques_tagged": len(self.coverage),
                "techniques_covered": len(covered),
                "tactics_covered": sum(1 for t in tactics if t["covered"]),
                "lint_errors": self.lint.error_count(),
                "lint_warnings": self.lint.warning_count(),
            },
            "global_errors": self.lint.global_errors,
            "benign": self.benign.describe(),
            "datasets": {name: {"repo": d.repo, "commit": d.commit, "license": d.license} for name, d in datasets.DATASETS.items()},
            "backends": {name: {"label": b.label, "target": b.target, "pipelines": b.pipelines, "required_for": b.required_for}
                         for name, b in self.config.backends.items()},
            "rules": rules,
            "coverage": {t: c.to_json() for t, c in self.coverage.items()},
            "tactics": tactics,
            "equivalence": (self.equivalence or {}).get("summary"),
        }


def run_pipeline(config: Config, require_external: bool = False, with_equivalence: bool = True,
                 opensearch_url: str | None = None) -> PipelineRun:
    specs, load_errors = load_rules(config.rules_dir, config.root)
    lint = lint_all(specs, load_errors, config.root, config.sigma_check_exclude)
    conversions = convert_all(config.rules_dir, config.backends)
    benign = load_benign(config.benign, config.root)
    replayer = Replayer(config.root, benign, require_external=require_external)
    runs = {spec.key: replayer.run(spec) for spec in specs}
    required = {name: b.required_for for name, b in config.backends.items()}
    min_tpr = float(config.gate.get("min_tpr", 1.0))
    scores = {
        spec.key: score_rule(spec, runs[spec.key], lint.per_rule[spec.key], conversions.get(spec.id, {}),
                             benign, required, min_tpr)
        for spec in specs
    }
    cov = coverage.compute(specs, scores)
    result = PipelineRun(config, specs, lint, conversions, runs, scores, benign, cov)
    if with_equivalence:
        from sigmaforge.equivalence import run_equivalence

        result.equivalence = run_equivalence(result, opensearch_url=opensearch_url)
        for key, verdict in result.equivalence.get("rules", {}).items():
            for problem in verdict.get("blocking", []):
                scores[key].failures.append(f"equivalence: {problem}")
                scores[key].status = "fail"
                scores[key].quality = 0.0
            for note in verdict.get("notes", []):
                scores[key].warnings.append(f"equivalence: {note}")
        result.coverage = coverage.compute(specs, scores)
    return result


def write_outputs(run: PipelineRun) -> dict[str, Path]:
    out = run.config.out_dir
    out.mkdir(parents=True, exist_ok=True)
    results = run.results()
    paths = {}
    paths["results"] = out / "results.json"
    paths["results"].write_text(json.dumps(results, indent=2, default=str) + "\n", encoding="utf-8")
    layer = coverage.navigator_layer(run.coverage)
    paths["navigator"] = out / "attack-navigator-layer.json"
    paths["navigator"].write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    keys_by_id = {s.id: s.key for s in run.specs}
    write_queries(out, keys_by_id, run.conversions, run.config.backends)
    return paths
