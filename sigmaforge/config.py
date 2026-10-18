"""Project configuration (``sigmaforge.yml`` at the repository root)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_BACKENDS: dict[str, dict[str, Any]] = {
    "splunk": {
        "target": "splunk",
        "pipelines": ["sysmon", "splunk_windows"],
        "label": "Splunk SPL",
        "required_for": ["detection"],
    },
    "lucene": {
        "target": "lucene",
        "pipelines": ["sysmon", "ecs_windows", "sigmaforge_ecs_caseless"],
        "label": "Elastic / OpenSearch Lucene (case-insensitive)",
        "required_for": ["detection"],
    },
    "lucene_stock": {
        "target": "lucene",
        "pipelines": ["sysmon", "ecs_windows"],
        "label": "Elastic / OpenSearch Lucene (stock pipeline)",
        "required_for": [],
    },
    "esql": {
        "target": "esql",
        "pipelines": ["sysmon", "ecs_windows"],
        "label": "Elastic ES|QL",
        "required_for": [],
    },
    "kql": {
        "target": "kusto",
        "pipelines": ["microsoft_xdr"],
        "label": "Microsoft Defender XDR KQL",
        "required_for": [],
    },
}


@dataclass
class BackendConfig:
    name: str
    target: str
    pipelines: list[str]
    label: str
    required_for: list[str]


@dataclass
class Config:
    root: Path
    rules_dir: Path
    benign: list[Path]
    out_dir: Path
    baseline: dict[str, Any]
    backends: dict[str, BackendConfig]
    gate: dict[str, Any]
    sigma_check_exclude: list[str]
    known_differences: Path
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def baseline_metrics(self) -> Path:
        return self.root / self.gate.get("baseline", "baseline/metrics.json")


def load_config(root: Path) -> Config:
    root = root.resolve()
    path = root / "sigmaforge.yml"
    raw: dict[str, Any] = {}
    if path.exists():
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    backends_raw = raw.get("backends") or DEFAULT_BACKENDS
    backends = {
        name: BackendConfig(
            name=name,
            target=spec["target"],
            pipelines=list(spec.get("pipelines", [])),
            label=spec.get("label", name),
            required_for=list(spec.get("required_for", [])),
        )
        for name, spec in backends_raw.items()
    }
    gate = {"min_tpr": 1.0, "noise_regression_ratio": 1.5, "baseline": "baseline/metrics.json"}
    gate.update(raw.get("gate") or {})
    return Config(
        root=root,
        rules_dir=root / raw.get("rules", "rules"),
        benign=[root / p for p in raw.get("benign", ["tests/benign"])],
        out_dir=root / raw.get("out", "out"),
        baseline=raw.get("baseline_generator") or {"out": "tests/benign/synthetic", "hosts": 12, "days": 14, "seed": 1337},
        backends=backends,
        gate=gate,
        sigma_check_exclude=list((raw.get("sigma_check") or {}).get("exclude", [])),
        known_differences=root / (raw.get("equivalence") or {}).get("known_differences", "equivalence-exceptions.yml"),
        raw=raw,
    )
