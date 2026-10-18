"""Convert every rule to each configured SIEM query language with pySigma.

Each backend gets its own processing pipeline, which is where field
mapping happens: ``Image`` becomes ``process.executable`` for Elastic
(``ecs_windows``), ``FolderPath`` in a ``DeviceProcessEvents`` table for
Defender XDR (``microsoft_xdr``) and stays ``Image`` for Splunk's Sysmon
add-on (``splunk_windows``).

pySigma processing pipelines modify rule objects in place, so every backend
converts a freshly parsed copy of the rule files. Conversion failures are
results, not crashes: a backend that cannot express a rule (Lucene has no
correlation support; the XDR schema has no table for Security events) is
reported per rule and backend.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

from sigmaforge.config import BackendConfig

EXTENSIONS = {"splunk": "spl", "lucene": "lucene", "esql": "esql", "kusto": "kql"}


@dataclass
class Conversion:
    backend: str
    ok: bool
    queries: list[str] = field(default_factory=list)
    error: str | None = None
    note: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {"ok": self.ok, "queries": self.queries, "error": self.error, "note": self.note}


def resolve_pipelines(plugins: Any, names: list[str]) -> Any:
    """Resolve installed pipeline names plus SigmaForge's own (``sigmaforge_*``)."""
    from sigmaforge.pipelines import CUSTOM_PIPELINES

    stock = [n for n in names if n not in CUSTOM_PIPELINES]
    pipeline = plugins.get_pipeline_resolver().resolve(stock)
    for name in names:
        if name in CUSTOM_PIPELINES:
            pipeline = pipeline + CUSTOM_PIPELINES[name]()
    return pipeline


def _fresh_rules(rules_dir: Path) -> list[Any]:
    rules: list[Any] = []
    for path in sorted(rules_dir.rglob("*.yml")):
        coll = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"), collect_errors=True, resolve_references=False)
        rules.extend(coll.rules)
    collection = SigmaCollection(rules, resolve_references=False)
    collection.resolve_rule_references()
    return collection.rules


def _first_line(exc: Exception) -> str:
    text = str(exc).strip().splitlines()
    return f"{type(exc).__name__}: {text[0] if text else ''}"


def convert_backend(rules_dir: Path, backend: BackendConfig, output_format: str = "default") -> dict[str, Conversion]:
    """Convert all rules for one backend. Returns rule-id -> Conversion."""
    from sigma.plugins import InstalledSigmaPlugins

    plugins = InstalledSigmaPlugins.autodiscover()
    backend_cls = plugins.backends.get(backend.target)
    if backend_cls is None:
        raise RuntimeError(f"pySigma backend {backend.target!r} is not installed")
    pipeline = resolve_pipelines(plugins, backend.pipelines)
    converter = backend_cls(processing_pipeline=pipeline)

    rules = _fresh_rules(rules_dir)
    ordered = [r for r in rules if not isinstance(r, SigmaCorrelationRule)]
    ordered += [r for r in rules if isinstance(r, SigmaCorrelationRule)]
    results: dict[str, Conversion] = {}
    for rule in ordered:
        rid = str(rule.id)
        try:
            if isinstance(rule, SigmaCorrelationRule):
                queries = converter.convert_correlation_rule(rule, output_format=output_format)
            else:
                queries = converter.convert_rule(rule, output_format=output_format)
        except Exception as exc:  # noqa: BLE001 - every failure is a reportable result
            results[rid] = Conversion(backend.name, ok=False, error=_first_line(exc))
            continue
        texts = [q if isinstance(q, str) else _render(q) for q in queries]
        texts = [t for t in texts if t and t.strip()]
        if not texts:
            results[rid] = Conversion(
                backend.name, ok=True, queries=[], note="building block: only emitted inside its correlation"
            )
        else:
            results[rid] = Conversion(backend.name, ok=True, queries=texts)
    return results


def _render(query: Any) -> str:
    import json

    if isinstance(query, (dict, list)):
        return json.dumps(query, indent=2)
    return str(query)


def convert_all(rules_dir: Path, backends: dict[str, BackendConfig]) -> dict[str, dict[str, Conversion]]:
    """Returns rule-id -> backend name -> Conversion."""
    out: dict[str, dict[str, Conversion]] = {}
    for name, backend in backends.items():
        try:
            per_rule = convert_backend(rules_dir, backend)
        except Exception as exc:  # noqa: BLE001 - e.g. plugin missing
            per_rule = {}
            for rule in _fresh_rules(rules_dir):
                per_rule[str(rule.id)] = Conversion(name, ok=False, error=_first_line(exc))
        for rid, conv in per_rule.items():
            out.setdefault(rid, {})[name] = conv
    return out


def write_queries(out_dir: Path, keys_by_id: dict[str, str], conversions: dict[str, dict[str, Conversion]],
                  backends: dict[str, BackendConfig]) -> None:
    for rid, per_backend in conversions.items():
        key = keys_by_id.get(rid, rid)
        for name, conv in per_backend.items():
            if not conv.ok or not conv.queries:
                continue
            ext = EXTENSIONS.get(backends[name].target, "txt")
            path = out_dir / "queries" / name / f"{key}.{ext}"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("\n\n".join(conv.queries) + "\n", encoding="utf-8")
