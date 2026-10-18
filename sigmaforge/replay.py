"""Replay every rule against its labelled tests and the benign baseline.

For a detection rule:

* every event in a positive file must match (event-level true-positive rate)
* every external sample must produce at least ``min_hits`` matches
* no event in a negative file may match
* matches on the benign corpus become alerts per host per day

For a correlation rule each positive or negative *file* is one scenario: a
positive scenario must raise at least one alert and a negative one none.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sigmaforge import datasets
from sigmaforge.correlation import CorrelationEngine
from sigmaforge.engine import CompiledRule, UnsupportedSigma, compile_rule
from sigmaforge.events import Event, iter_files, load_events
from sigmaforge.rules import RuleSpec

SUMMARY_FIELDS = (
    "CommandLine", "Details", "PipeName", "QueryName", "ImagePath", "TargetObject",
)


def summarize(ev: Event) -> str:
    f = ev.fields
    for name in SUMMARY_FIELDS:
        if f.get(name):
            return str(f[name])
    if f.get("SourceImage"):
        return f"{f.get('SourceImage')} -> {f.get('TargetImage')} ({f.get('GrantedAccess')})"
    if f.get("TargetUserName") or f.get("IpAddress"):
        return f"{ev.channel} {ev.event_id} user={f.get('TargetUserName')} ip={f.get('IpAddress')}"
    return f"{ev.channel} {ev.event_id}"


@dataclass
class SampleResult:
    kind: str  # positive | negative | external
    source: str
    events: int
    hits: int
    expected: int  # positives: events that must match; external: min hits; negative: 0
    passed: bool | None  # None = skipped (sample not available)
    missed: list[str] = field(default_factory=list)
    note: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind, "source": self.source, "events": self.events, "hits": self.hits,
            "expected": self.expected, "passed": self.passed, "missed": self.missed[:10], "note": self.note,
        }


@dataclass
class RuleRun:
    key: str
    positives: list[SampleResult] = field(default_factory=list)
    negatives: list[SampleResult] = field(default_factory=list)
    externals: list[SampleResult] = field(default_factory=list)
    benign_hits: int = 0
    benign_examples: list[dict[str, Any]] = field(default_factory=list)
    benign_events: list[Event] = field(default_factory=list, repr=False)
    runtime_ms: float = 0.0
    error: str | None = None


@dataclass
class BenignCorpus:
    events: list[Event]
    sources: list[str]

    @property
    def host_days(self) -> int:
        return len({(ev.computer.lower(), ev.timestamp.date()) for ev in self.events})

    @property
    def hosts(self) -> int:
        return len({ev.computer.lower() for ev in self.events})

    def describe(self) -> dict[str, Any]:
        if not self.events:
            return {"events": 0, "hosts": 0, "host_days": 0, "sources": self.sources}
        return {
            "events": len(self.events),
            "hosts": self.hosts,
            "host_days": self.host_days,
            "start": self.events[0].timestamp.isoformat(),
            "end": self.events[-1].timestamp.isoformat(),
            "sources": self.sources,
        }


def load_benign(paths: list[Path], root: Path) -> BenignCorpus:
    files = [p for p in iter_files(paths) if p.name != "corpus.json"]
    events = load_events(files)
    sources = [str(p.relative_to(root)) if p.is_relative_to(root) else str(p) for p in files]
    return BenignCorpus(events=events, sources=sources)


def _rel(path: Path, root: Path) -> str:
    return str(path.relative_to(root)) if path.is_relative_to(root) else str(path)


class Replayer:
    def __init__(self, root: Path, benign: BenignCorpus, require_external: bool = False):
        self.root = root
        self.benign = benign
        self.require_external = require_external
        self._compiled: dict[int, CompiledRule] = {}
        self.correlations = CorrelationEngine(self._compiled)

    def _compile(self, spec: RuleSpec) -> CompiledRule:
        compiled = self._compiled.get(id(spec.rule))
        if compiled is None:
            compiled = compile_rule(spec.rule)
            self._compiled[id(spec.rule)] = compiled
        return compiled

    # -- detection rules -------------------------------------------------
    def _detection(self, spec: RuleSpec, run: RuleRun) -> None:
        compiled = self._compile(spec)
        for kind, paths in (("positive", spec.tests.positive), ("negative", spec.tests.negative)):
            for path in paths:
                for file in iter_files([path]):
                    events = load_events([file])
                    matched = [ev for ev in events if compiled.matches(ev)]
                    if kind == "positive":
                        missed = [ev.origin.rsplit("/", 1)[-1] for ev in events if ev not in matched]
                        res = SampleResult(kind, _rel(file, self.root), len(events), len(matched), len(events),
                                           passed=len(matched) == len(events), missed=missed)
                        run.positives.append(res)
                    else:
                        res = SampleResult(kind, _rel(file, self.root), len(events), len(matched), 0,
                                           passed=not matched,
                                           missed=[f"{ev.origin.rsplit('/', 1)[-1]}: {summarize(ev)}" for ev in matched])
                        run.negatives.append(res)
        for ext in spec.tests.external:
            source = f"{ext.dataset}:{ext.path}"
            local = datasets.local_path(self.root, ext.dataset, ext.path)
            if not local.exists():
                run.externals.append(SampleResult(
                    "external", source, 0, 0, ext.min_hits,
                    passed=False if self.require_external else None,
                    note="sample not fetched (run `sigmaforge datasets fetch`)",
                ))
                continue
            events = load_events([local], strict=False)
            hits = sum(1 for ev in events if compiled.matches(ev))
            run.externals.append(SampleResult("external", source, len(events), hits, ext.min_hits,
                                              passed=hits >= ext.min_hits))
        start = time.perf_counter()
        benign_hits = [ev for ev in self.benign.events if compiled.matches(ev)]
        run.runtime_ms = (time.perf_counter() - start) * 1000
        self._record_benign(run, benign_hits)

    # -- correlation rules -----------------------------------------------
    def _correlation(self, spec: RuleSpec, run: RuleRun) -> None:
        for kind, paths in (("positive", spec.tests.positive), ("negative", spec.tests.negative)):
            for path in paths:
                for file in iter_files([path]):
                    events = load_events([file])
                    alerts = self.correlations.evaluate(spec.rule, events)
                    if kind == "positive":
                        res = SampleResult(kind, _rel(file, self.root), len(events), len(alerts), 1,
                                           passed=len(alerts) >= 1,
                                           note="; ".join(f"{a.detail} {a.group}" for a in alerts[:3]))
                        run.positives.append(res)
                    else:
                        res = SampleResult(kind, _rel(file, self.root), len(events), len(alerts), 0,
                                           passed=not alerts,
                                           missed=[f"{a.detail} {a.group}" for a in alerts[:5]])
                        run.negatives.append(res)
        start = time.perf_counter()
        alerts = self.correlations.evaluate(spec.rule, self.benign.events)
        run.runtime_ms = (time.perf_counter() - start) * 1000
        run.benign_hits = len(alerts)
        run.benign_examples = [
            {"host": a.computer, "time": a.timestamp.isoformat(), "summary": f"{a.detail} {a.group}"}
            for a in alerts[:10]
        ]
        run.benign_events = [a.events[-1] for a in alerts if a.events]

    def _record_benign(self, run: RuleRun, hits: list[Event]) -> None:
        run.benign_hits = len(hits)
        run.benign_events = hits
        run.benign_examples = [
            {"host": ev.computer, "time": ev.timestamp.isoformat(), "summary": summarize(ev)[:300]}
            for ev in hits[:10]
        ]

    def run(self, spec: RuleSpec) -> RuleRun:
        run = RuleRun(key=spec.key)
        try:
            if spec.is_correlation:
                self._correlation(spec, run)
            else:
                self._detection(spec, run)
        except UnsupportedSigma as exc:
            run.error = f"replay engine cannot evaluate this rule: {exc}"
        except Exception as exc:  # noqa: BLE001 - a broken rule must not kill the run
            run.error = f"{type(exc).__name__}: {exc}"
        return run
