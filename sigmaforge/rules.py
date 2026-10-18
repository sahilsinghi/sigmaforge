"""Load the rule repository: Sigma rules plus SigmaForge test metadata.

Every rule carries a ``x_sigmaforge`` block (a Sigma custom attribute, so
other Sigma tooling ignores it) that turns a detection into something
testable::

    x_sigmaforge:
      owner: sahil.singhi
      confidence: high          # author's confidence in the logic
      noise_budget: 0.05        # max alerts per host per day on benign data
      tests:
        positive:               # labelled attack telemetry - must fire
          - tests/positive/proc_creation_win_powershell_encoded_cmd
        negative:               # near-misses - must NOT fire
          - tests/negative/proc_creation_win_powershell_encoded_cmd
        external:               # real telemetry from a pinned public dataset
          - dataset: evtx-attack-samples
            path: Execution/some_sample.evtx
            min_hits: 1
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from sigmaforge import attack

TECHNIQUE_RE = re.compile(r"^t\d{4}(\.\d{3})?$")
CONFIDENCE_WEIGHT = {"low": 0.5, "medium": 0.75, "high": 1.0}


@dataclass
class ExternalSample:
    dataset: str
    path: str
    min_hits: int = 1


@dataclass
class TestSpec:
    positive: list[Path] = field(default_factory=list)
    negative: list[Path] = field(default_factory=list)
    external: list[ExternalSample] = field(default_factory=list)


@dataclass
class RuleSpec:
    path: Path
    rule: SigmaRule | SigmaCorrelationRule
    meta: dict[str, Any]
    tests: TestSpec
    building_block: bool = False
    key: str = ""  # file stem, or rule name when a file holds several rules

    # -- identity -----------------------------------------------------
    @property
    def id(self) -> str:
        return str(self.rule.id) if self.rule.id else self.path.stem

    @property
    def title(self) -> str:
        return self.rule.title

    @property
    def is_correlation(self) -> bool:
        return isinstance(self.rule, SigmaCorrelationRule)

    @property
    def level(self) -> str:
        level = getattr(self.rule, "level", None)
        return getattr(level, "name", str(level or "")).lower() if level else ""

    # -- metadata -----------------------------------------------------
    @property
    def owner(self) -> str | None:
        return self.meta.get("owner")

    @property
    def noise_budget(self) -> float | None:
        value = self.meta.get("noise_budget")
        return float(value) if isinstance(value, (int, float)) else None

    @property
    def confidence(self) -> str:
        return str(self.meta.get("confidence", "medium")).lower()

    @property
    def min_tpr(self) -> float:
        return float(self.meta.get("min_tpr", 1.0))

    # -- ATT&CK -------------------------------------------------------
    def _tag_names(self) -> list[str]:
        tags = getattr(self.rule, "tags", None)
        if tags:
            return [f"{t.namespace}.{t.name}".lower() for t in tags]
        raw = self.rule.custom_attributes.get("tags", []) if hasattr(self.rule, "custom_attributes") else []
        return [str(t).lower() for t in raw]

    @property
    def techniques(self) -> list[str]:
        out = []
        for tag in self._tag_names():
            ns, _, name = tag.partition(".")
            if ns == "attack" and TECHNIQUE_RE.match(name):
                out.append(name.upper())
        return out

    @property
    def tactics(self) -> list[str]:
        """ATT&CK tactic shortnames (``credential-access``) from the rule's tags."""
        known = set(attack.load().tactic_shortnames())
        out = []
        for tag in self._tag_names():
            ns, _, name = tag.partition(".")
            name = name.replace("_", "-")
            if ns == "attack" and name in known:
                out.append(name)
        return out


class RuleLoadError(Exception):
    pass


def _paths(raw: Any, base: Path) -> list[Path]:
    if raw is None:
        return []
    items = raw if isinstance(raw, list) else [raw]
    return [(base / str(p)).resolve() for p in items]


def _test_spec(meta: dict[str, Any], base: Path) -> TestSpec:
    tests = meta.get("tests") or {}
    external = []
    for item in tests.get("external") or []:
        if isinstance(item, dict) and "dataset" in item and "path" in item:
            external.append(
                ExternalSample(
                    dataset=str(item["dataset"]),
                    path=str(item["path"]),
                    min_hits=int(item.get("min_hits", 1)),
                )
            )
    return TestSpec(
        positive=_paths(tests.get("positive"), base),
        negative=_paths(tests.get("negative"), base),
        external=external,
    )


def load_rules(rules_dir: Path, repo_root: Path) -> tuple[list[RuleSpec], list[str]]:
    """Load every rule under ``rules_dir``.

    Returns the rule specs and a list of parse errors (file: message). Rules
    are parsed with pySigma, so anything pySigma rejects is reported here
    rather than silently skipped.
    """
    files = sorted(p for p in rules_dir.rglob("*.yml") if p.is_file())
    errors: list[str] = []
    specs: list[RuleSpec] = []
    all_rules: list[Any] = []
    origin: dict[int, Path] = {}
    per_file: dict[Path, int] = {}
    for path in files:
        try:
            sub = SigmaCollection.from_yaml(
                path.read_text(encoding="utf-8"), collect_errors=True, resolve_references=False
            )
        except Exception as exc:  # noqa: BLE001 - surface any parser failure
            errors.append(f"{path}: {exc}")
            continue
        errors.extend(f"{path}: {err}" for err in sub.errors)
        for rule in sub.rules:
            if getattr(rule, "errors", None):
                errors.extend(f"{path}: {err}" for err in rule.errors)
            origin[id(rule)] = path
            per_file[path] = per_file.get(path, 0) + 1
        all_rules.extend(sub.rules)
    # Correlations may reference rules in other files, so resolve across the repo.
    collection = SigmaCollection(all_rules, resolve_references=False)
    try:
        collection.resolve_rule_references()
    except Exception as exc:  # noqa: BLE001
        errors.append(f"correlation reference error: {exc}")

    building_blocks: set[int] = set()
    for rule in collection.rules:
        if isinstance(rule, SigmaCorrelationRule) and not rule.generate:
            for ref in rule.rules:
                target = getattr(ref, "rule", None)
                if target is not None:
                    building_blocks.add(id(target))

    for rule in collection.rules:
        path = origin.get(id(rule), rules_dir)
        custom = getattr(rule, "custom_attributes", {}) or {}
        meta = custom.get("x_sigmaforge") or {}
        if not isinstance(meta, dict):
            meta = {}
        if per_file.get(path, 1) == 1:
            key = path.stem
        else:
            key = getattr(rule, "name", None) or f"{path.stem}:{str(rule.id)[:8]}"
        specs.append(
            RuleSpec(
                path=path,
                rule=rule,
                meta=meta,
                tests=_test_spec(meta, repo_root),
                building_block=id(rule) in building_blocks or bool(meta.get("building_block")),
                key=key,
            )
        )
    return specs, errors
