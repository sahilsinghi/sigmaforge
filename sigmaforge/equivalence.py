"""Cross-backend equivalence: do the converted queries hit the same events?

For every rule and backend, the converted query is replayed on the same
events the Sigma engine saw - labelled positives, near-miss negatives, real
attack samples and the benign corpus - reshaped into that backend's schema.
The result per rule x backend is one of:

* ``identical``     - exactly the same events
* ``documented``    - different, and ``equivalence-exceptions.yml`` explains
                      why (with the exact expected difference, so it cannot
                      silently grow)
* ``mismatch``      - different with no documented reason: blocks the merge
* ``unsupported``   - the backend cannot express the rule (conversion failed)
* ``not-evaluable`` - converted, but no evaluator models that query syntax

Correlation rules are compared by alert count per scenario, because SIEM
correlation output is aggregated rows rather than events.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from sigmaforge import datasets
from sigmaforge.engine import compile_rule
from sigmaforge.events import Event, iter_files, load_events
from sigmaforge.minisiem import Unsupported, kql, lucene, spl
from sigmaforge.replay import summarize
from sigmaforge.shapes import to_ecs, to_splunk, to_xdr

if TYPE_CHECKING:
    from sigmaforge.pipeline import PipelineRun

EVALUATED = {"splunk": "splunk", "lucene": "lucene", "kusto": "kql"}


@dataclass
class Corpus:
    events: list[Event]
    labels: list[str]  # where each event came from (positive/negative/external/benign)


def _build_corpus(run: "PipelineRun") -> Corpus:
    events: list[Event] = []
    labels: list[str] = []
    seen_files: set[Path] = set()
    root = run.config.root
    for spec in run.specs:
        for kind, paths in (("positive", spec.tests.positive), ("negative", spec.tests.negative)):
            for f in iter_files(paths):
                if f in seen_files:
                    continue
                seen_files.add(f)
                for ev in load_events([f]):
                    events.append(ev)
                    labels.append(f"{kind}:{f.relative_to(root)}")
        for ext in spec.tests.external:
            local = datasets.local_path(root, ext.dataset, ext.path)
            if local.exists() and local not in seen_files:
                seen_files.add(local)
                for ev in load_events([local], strict=False):
                    events.append(ev)
                    labels.append(f"external:{ext.path}")
    for ev in run.benign.events:
        events.append(ev)
        labels.append("benign")
    return Corpus(events, labels)


def load_exceptions(path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    out = {}
    for item in data:
        out[(item["rule"], item["backend"])] = item
    return out


def _describe(corpus: Corpus, idx: int) -> str:
    ev = corpus.events[idx]
    return f"[{corpus.labels[idx]}] {summarize(ev)[:140]}"


def _compare(rule_key: str, backend: str, engine: set[int], other: set[int], corpus: Corpus,
             exceptions: dict[tuple[str, str], dict[str, Any]]) -> dict[str, Any]:
    engine_only = sorted(engine - other)
    backend_only = sorted(other - engine)

    def committed(ids: list[int]) -> list[int]:
        # Pinned expectations count committed test data only, so a run without the
        # downloaded real-telemetry samples documents the same numbers as CI.
        return [i for i in ids if not corpus.labels[i].startswith("external:")]

    result: dict[str, Any] = {
        "hits": len(other),
        "engine_hits": len(engine),
        "engine_only": len(engine_only),
        "backend_only": len(backend_only),
        "examples": [f"missed {_describe(corpus, i)}" for i in engine_only[:3]]
        + [f"extra {_describe(corpus, i)}" for i in backend_only[:3]],
    }
    if not engine_only and not backend_only:
        result["status"] = "identical"
        result["summary"] = f"{len(other)} hits, identical to the Sigma engine"
        return result
    c_engine, c_backend = len(committed(engine_only)), len(committed(backend_only))
    ext = (len(engine_only) - c_engine) + (len(backend_only) - c_backend)
    diff = f"{len(engine_only)} missed / {len(backend_only)} extra vs the Sigma engine"
    if ext:
        diff += f" ({ext} of them in real-telemetry samples)"
    exc = exceptions.get((rule_key, backend))
    if exc is None:
        result["status"] = "mismatch"
        result["summary"] = f"{diff}; no documented reason"
        return result
    expected = exc.get("expected") or {}
    if expected and (expected.get("engine_only") != c_engine or expected.get("backend_only", 0) != c_backend):
        result["status"] = "mismatch"
        result["summary"] = (f"{diff}; on committed test data the documented difference expects "
                             f"{expected.get('engine_only')} missed / {expected.get('backend_only', 0)} extra, "
                             f"got {c_engine} / {c_backend}")
        return result
    result["status"] = "documented"
    result["reason"] = " ".join(str(exc.get("reason", "")).split())
    result["summary"] = f"{diff} — documented: {result['reason']}"
    return result


def run_equivalence(run: "PipelineRun", opensearch_url: str | None = None) -> dict[str, Any]:
    corpus = _build_corpus(run)
    exceptions = load_exceptions(run.config.known_differences)
    splunk_docs = [to_splunk(ev) | {"__idx": i} for i, ev in enumerate(corpus.events)]
    ecs_docs = [to_ecs(ev) for ev in corpus.events]
    xdr_rows: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for i, ev in enumerate(corpus.events):
        shaped = to_xdr(ev)
        if shaped is not None:
            xdr_rows.setdefault(shaped[0], []).append((i, shaped[1]))

    backends = [name for name, b in run.config.backends.items()]
    target_of = {name: b.target for name, b in run.config.backends.items()}

    opensearch = None
    os_summary: dict[str, Any] | None = None
    if opensearch_url:
        from sigmaforge.opensearch import OpenSearchError, OpenSearchReplay

        candidate = OpenSearchReplay(opensearch_url)
        if candidate.available():
            try:
                candidate.load(ecs_docs)
                opensearch = candidate
                os_summary = {"version": candidate.version, "rules": 0, "agree": 0, "docs": len(ecs_docs), "disagreements": []}
            except OpenSearchError as exc:
                os_summary = {"error": str(exc)}

    rules_out: dict[str, Any] = {}
    counts = {"identical": 0, "documented": 0, "mismatch": 0, "unsupported": 0, "not-evaluable": 0}
    mismatch_details: list[str] = []
    documented_reasons: list[dict[str, str]] = []

    for spec in run.specs:
        if spec.building_block:
            continue
        conversions = run.conversions.get(spec.id, {})
        verdict: dict[str, Any] = {"backends": {}, "blocking": [], "notes": []}
        if spec.is_correlation:
            engine_counts = _correlation_engine_counts(run, spec)
        else:
            rule_pred = compile_rule(spec.rule)
            engine_hits = {i for i, ev in enumerate(corpus.events) if rule_pred.matches(ev)}
        for backend in backends:
            conv = conversions.get(backend)
            target = target_of[backend]
            if conv is None:
                continue
            if not conv.ok:
                verdict["backends"][backend] = {"status": "unsupported", "summary": conv.error or "conversion failed"}
                counts["unsupported"] += 1
                continue
            if target not in EVALUATED:
                verdict["backends"][backend] = {"status": "not-evaluable",
                                                "summary": "converted; no in-process evaluator for this language"}
                counts["not-evaluable"] += 1
                continue
            query = "\n".join(conv.queries)
            try:
                if spec.is_correlation:
                    res = _correlation_backend(run, spec, target, query, engine_counts, exceptions, backend)
                else:
                    other = _backend_hits(target, query, splunk_docs, ecs_docs, xdr_rows)
                    res = _compare(spec.key, backend, engine_hits, other, corpus, exceptions)
                    if target == "lucene" and opensearch is not None:
                        os_hits = opensearch.hits(query)
                        os_summary["rules"] += 1
                        if os_hits == other:
                            os_summary["agree"] += 1
                            res["opensearch"] = "agrees with the in-process Lucene evaluator"
                        else:
                            res["opensearch"] = (f"OpenSearch returned {len(os_hits)} hits vs {len(other)} in-process "
                                                 f"({len(os_hits - other)} extra, {len(other - os_hits)} missing)")
                            os_summary["disagreements"].append(f"{spec.key}: {res['opensearch']}")
                            verdict["blocking"].append(f"OpenSearch disagrees with the Lucene model: {res['opensearch']}")
            except Unsupported as exc:
                res = {"status": "not-evaluable", "summary": f"query syntax not modelled: {exc}"}
            verdict["backends"][backend] = res
            counts[res["status"]] = counts.get(res["status"], 0) + 1
            if res["status"] == "mismatch":
                msg = f"{backend}: {res['summary']}"
                verdict["blocking"].append(msg)
                mismatch_details.append(f"{spec.key} {msg}")
                for ex in res.get("examples", [])[:3]:
                    verdict["blocking"].append(f"{backend}: {ex}")
            elif res["status"] == "documented":
                verdict["notes"].append(f"{backend}: {res['summary']}")
                documented_reasons.append({"rule": spec.key, "backend": backend, "reason": res.get("reason", "")})
        rules_out[spec.key] = verdict

    if opensearch is not None:
        opensearch.cleanup()
    compared = counts["identical"] + counts["documented"] + counts["mismatch"]
    summary = {
        "compared": compared,
        "identical": counts["identical"],
        "documented": counts["documented"],
        "mismatch": counts["mismatch"],
        "unsupported": counts["unsupported"],
        "not_evaluable": counts["not-evaluable"],
        "corpus_events": len(corpus.events),
        "mismatch_details": mismatch_details,
        "documented_reasons": documented_reasons,
        "opensearch": os_summary if os_summary and "error" not in os_summary else None,
        "opensearch_error": (os_summary or {}).get("error"),
    }
    return {"rules": rules_out, "summary": summary, "backends": backends}


def _backend_hits(target: str, query: str, splunk_docs, ecs_docs, xdr_rows) -> set[int]:
    if target == "splunk":
        run = spl.compile_query(query)
        return {d["__idx"] for d in run(splunk_docs)}
    if target == "lucene":
        pred = lucene.compile_query(query)
        return {i for i, d in enumerate(ecs_docs) if pred(d)}
    if target == "kusto":
        table, pred = kql.compile_query(query)
        return {i for i, row in xdr_rows.get(table, []) if pred(row)}
    raise Unsupported(f"no evaluator for {target}")


# --------------------------------------------------------------------------
# correlations: compare alert counts per scenario
# --------------------------------------------------------------------------

def _scenarios(run: "PipelineRun", spec) -> list[tuple[str, list[Event]]]:
    out = []
    for kind, paths in (("positive", spec.tests.positive), ("negative", spec.tests.negative)):
        for f in iter_files(paths):
            out.append((f"{kind}:{f.name}", load_events([f])))
    out.append(("benign", run.benign.events))
    return out


def _correlation_engine_counts(run: "PipelineRun", spec) -> dict[str, int]:
    from sigmaforge.correlation import CorrelationEngine

    engine = CorrelationEngine()
    return {name: len(engine.evaluate(spec.rule, events)) for name, events in _scenarios(run, spec)}


def _correlation_backend(run, spec, target, query, engine_counts, exceptions, backend) -> dict[str, Any]:
    if target != "splunk":
        raise Unsupported(f"correlation replay is only modelled for SPL, not {target}")
    pipeline = spl.compile_query(query)
    counts = {}
    for name, events in _scenarios(run, spec):
        docs = [to_splunk(ev) | {"__idx": i} for i, ev in enumerate(events)]
        counts[name] = len(pipeline(docs))
    differing = {k: (engine_counts[k], counts[k]) for k in counts if engine_counts.get(k) != counts[k]}
    total = sum(counts.values())
    res: dict[str, Any] = {"hits": total, "engine_hits": sum(engine_counts.values()),
                           "per_scenario": {k: {"engine": engine_counts[k], "backend": counts[k]} for k in counts}}
    if not differing:
        res["status"] = "identical"
        res["summary"] = f"alert counts identical in all {len(counts)} scenarios"
        return res
    exc = exceptions.get((spec.key, backend))
    detail = "; ".join(f"{k}: engine {a} vs {backend} {b}" for k, (a, b) in differing.items())
    if exc is None:
        res["status"] = "mismatch"
        res["summary"] = f"alert counts differ ({detail}); no documented reason"
        return res
    expected = exc.get("expected_scenarios")
    if expected and {k: list(v) for k, v in differing.items()} != {k: list(v) for k, v in expected.items()}:
        res["status"] = "mismatch"
        res["summary"] = f"alert counts differ ({detail}), not as documented"
        return res
    res["status"] = "documented"
    res["reason"] = " ".join(str(exc.get("reason", "")).split())
    res["summary"] = f"{detail} — documented: {res['reason']}"
    return res
