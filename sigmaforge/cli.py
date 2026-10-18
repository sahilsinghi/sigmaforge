"""Command-line interface: ``sigmaforge <command>``.

    lint          sigma check + repository rules
    convert       write SPL / Lucene / ES|QL / KQL for every rule
    test          replay rules: TPR on positives, near-miss FPs, alerts/host/day
    equivalence   compare hits across backends (and OpenSearch, if reachable)
    ci            everything above + merge gate + HTML report + PR comment
    coverage      print ATT&CK coverage and write the Navigator layer
    tune RULE     show which field values cause a rule's benign hits
    drift         compare noise on a fresh benign corpus against the baseline
    baseline      generate the synthetic benign corpus / update metrics.json
    datasets      pin and fetch public attack telemetry
    attack        refresh the ATT&CK snapshot
    export        Elastic detection-rule NDJSON (+ index template) / Splunk savedsearches.conf
    badges        README badges and ATT&CK coverage strip
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from sigmaforge import __version__
from sigmaforge.config import Config, load_config


# --------------------------------------------------------------------------
# small output helpers
# --------------------------------------------------------------------------

def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _supports_color() else text


def ok(text: str) -> str:
    return _c(text, "32")


def bad(text: str) -> str:
    return _c(text, "31")


def warn(text: str) -> str:
    return _c(text, "33")


def dim(text: str) -> str:
    return _c(text, "2")


def table(rows: list[list[str]], headers: list[str]) -> str:
    import re

    strip = re.compile(r"\033\[[0-9;]*m")
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(strip.sub("", cell)))
    def fmt(row: list[str]) -> str:
        return "  ".join(cell + " " * (widths[i] - len(strip.sub("", cell))) for i, cell in enumerate(row))
    lines = [fmt(headers), "  ".join("-" * w for w in widths)]
    lines += [fmt(r) for r in rows]
    return "\n".join(lines)


def _config(args: argparse.Namespace) -> Config:
    return load_config(Path(args.root))


def _ensure_baseline_corpus(cfg: Config) -> None:
    """Generate the synthetic benign corpus if it is missing (it is not committed)."""
    from sigmaforge import baseline

    out = cfg.root / cfg.baseline.get("out", "tests/benign/synthetic")
    if (out / "synthetic-baseline.jsonl.gz").exists():
        return
    print(dim(f"generating synthetic benign baseline in {out.relative_to(cfg.root)} ..."))
    baseline.generate(out, hosts=int(cfg.baseline.get("hosts", 12)), days=int(cfg.baseline.get("days", 14)),
                      seed=int(cfg.baseline.get("seed", 1337)))


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_lint(args: argparse.Namespace) -> int:
    from sigmaforge.lint import lint_all
    from sigmaforge.rules import load_rules

    cfg = _config(args)
    specs, errors = load_rules(cfg.rules_dir, cfg.root)
    report = lint_all(specs, errors, cfg.root, cfg.sigma_check_exclude)
    for err in report.global_errors:
        print(bad(f"ERROR {err}"))
    for key, res in report.per_rule.items():
        for e in res.errors:
            print(f"{bad('ERROR')} {key}: {e}")
        for w in res.warnings:
            print(f"{warn('WARN ')} {key}: {w}")
    n_err, n_warn = report.error_count(), report.warning_count()
    print(f"\n{len(specs)} rules, {bad(str(n_err)) if n_err else ok('0')} errors, {n_warn} warnings")
    return 1 if n_err else 0


def cmd_convert(args: argparse.Namespace) -> int:
    from sigmaforge.convert import convert_all, write_queries
    from sigmaforge.rules import load_rules

    cfg = _config(args)
    backends = {k: v for k, v in cfg.backends.items() if not args.backend or k in args.backend}
    specs, _ = load_rules(cfg.rules_dir, cfg.root)
    conversions = convert_all(cfg.rules_dir, backends)
    write_queries(cfg.out_dir, {s.id: s.key for s in specs}, conversions, backends)
    rows = []
    for spec in specs:
        cells = [spec.key]
        for name in backends:
            conv = conversions.get(spec.id, {}).get(name)
            if conv is None:
                cells.append("?")
            elif not conv.ok:
                cells.append(bad("no"))
            elif not conv.queries:
                cells.append(dim("bb"))
            else:
                cells.append(ok("yes"))
        rows.append(cells)
    print(table(rows, ["rule"] + list(backends)))
    print(dim(f"\nqueries written to {cfg.out_dir.relative_to(cfg.root)}/queries/<backend>/ (bb = building block)"))
    if args.show:
        for spec in specs:
            if args.show not in (spec.key, spec.id):
                continue
            for name, conv in conversions.get(spec.id, {}).items():
                print(f"\n--- {name}")
                print("\n".join(conv.queries) if conv.ok else bad(conv.error or ""))
    return 0


def _print_test_table(results: dict[str, Any]) -> None:
    rows = []
    for r in results["rules"]:
        sc = r["score"]
        status = ok("PASS") if sc["status"] == "pass" else bad("FAIL")
        tpr = f"{sc['tpr']:.0%} ({sc['positives_matched']}/{sc['positives_total']})" if sc["tpr"] is not None else "-"
        ext = f"{sc['externals_passed']}/{sc['externals_total']}" if sc["externals_total"] else ("skip" if sc["externals_skipped"] else "-")
        if r["building_block"]:
            noise = dim("building block")
        elif sc["alerts_per_host_day"] is None:
            noise = "-"
        else:
            text = f"{sc['alerts_per_host_day']:.3f} / {r['noise_budget']:g}"
            noise = bad(text) if r["noise_budget"] is not None and sc["alerts_per_host_day"] > r["noise_budget"] else text
        rows.append([status, r["key"], tpr, ext, str(sc["negative_fp"]), noise, f"{r['runtime_ms']:.0f}ms"])
    print(table(rows, ["", "rule", "TPR", "real", "nearmiss FP", "alerts/host/day / budget", "runtime"]))
    b = results["benign"]
    print(dim(f"\nbenign baseline: {b['events']:,} events, {b['hosts']} hosts, {b['host_days']} host-days"))
    for r in results["rules"]:
        if r["score"]["status"] != "pass":
            print(bad(f"\n{r['key']}"))
            for f in r["score"]["failures"]:
                print(f"  - {f}")


def cmd_test(args: argparse.Namespace) -> int:
    from sigmaforge.pipeline import run_pipeline, write_outputs

    cfg = _config(args)
    _ensure_baseline_corpus(cfg)
    run = run_pipeline(cfg, require_external=args.require_external, with_equivalence=False)
    write_outputs(run)
    results = run.results()
    _print_test_table(results)
    s = results["summary"]
    print(f"\n{s['passing']}/{s['rules']} rules pass")
    return 0 if run.ok else 1


def cmd_equivalence(args: argparse.Namespace) -> int:
    from sigmaforge.pipeline import run_pipeline, write_outputs

    cfg = _config(args)
    _ensure_baseline_corpus(cfg)
    run = run_pipeline(cfg, with_equivalence=True, opensearch_url=args.opensearch)
    write_outputs(run)
    eq = run.equivalence or {}
    rows = []
    for key, verdict in eq.get("rules", {}).items():
        cells = [key]
        for backend in eq.get("backends", []):
            v = verdict["backends"].get(backend)
            if v is None:
                cells.append("-")
                continue
            label = {"identical": ok("="), "documented": warn("≈ doc"), "mismatch": bad("≠"),
                     "unsupported": dim("n/a"), "not-evaluable": dim("skip")}.get(v["status"], v["status"])
            cells.append(f"{label} {v.get('hits', '')}")
        rows.append(cells)
    print(table(rows, ["rule"] + [f"{b} hits" for b in eq.get("backends", [])]))
    summary = eq.get("summary", {})
    print(f"\nidentical {summary.get('identical', 0)}, documented {summary.get('documented', 0)}, "
          f"mismatch {summary.get('mismatch', 0)}, not expressible {summary.get('unsupported', 0)}")
    if summary.get("opensearch"):
        o = summary["opensearch"]
        print(f"OpenSearch {o['version']}: {o['agree']}/{o['rules']} Lucene queries returned the in-process hit set")
    elif args.opensearch:
        print(warn(f"OpenSearch at {args.opensearch} was not reachable; Lucene was checked in-process only"))
    for item in summary.get("mismatch_details", []):
        print(bad(f"  {item}"))
    return 1 if summary.get("mismatch") else 0


def cmd_ci(args: argparse.Namespace) -> int:
    from sigmaforge import gate as gate_mod
    from sigmaforge.pipeline import run_pipeline, write_outputs
    from sigmaforge.report import render_html, render_markdown

    cfg = _config(args)
    _ensure_baseline_corpus(cfg)
    run = run_pipeline(cfg, require_external=args.require_external, with_equivalence=not args.no_equivalence,
                       opensearch_url=args.opensearch)
    paths = write_outputs(run)
    results = run.results()
    baseline_path = Path(args.baseline) if args.baseline else cfg.baseline_metrics
    baseline = gate_mod.load_baseline(baseline_path)
    decision = gate_mod.decide(results, baseline, float(cfg.gate.get("noise_regression_ratio", 1.5)))
    gate_json = decision.to_json()
    out = cfg.out_dir
    (out / "gate.json").write_text(json.dumps(gate_json, indent=2) + "\n", encoding="utf-8")
    (out / "report.html").write_text(render_html(results, gate_json), encoding="utf-8")
    (out / "pr-comment.md").write_text(render_markdown(results, gate_json, args.report_url), encoding="utf-8")
    (out / "metrics.json").write_text(json.dumps(gate_mod.metrics_from_results(results), indent=2) + "\n", encoding="utf-8")
    from sigmaforge.badges import write_all

    write_all(results, out / "badges")
    _print_test_table(results)
    print()
    if decision.blocked:
        print(bad("MERGE BLOCKED"))
        for reason in decision.reasons:
            print(f"  - {reason}")
    else:
        print(ok("READY TO MERGE"))
    for w in decision.warnings:
        print(warn(f"  ! {w}"))
    for i in decision.improvements:
        print(ok(f"  + {i}"))
    print(dim(f"\nreport: {(out / 'report.html').relative_to(cfg.root)} · layer: {paths['navigator'].relative_to(cfg.root)}"
              f" · comment: {(out / 'pr-comment.md').relative_to(cfg.root)}"))
    return 1 if decision.blocked else 0


def cmd_coverage(args: argparse.Namespace) -> int:
    from sigmaforge.pipeline import run_pipeline, write_outputs

    cfg = _config(args)
    _ensure_baseline_corpus(cfg)
    run = run_pipeline(cfg, with_equivalence=False)
    paths = write_outputs(run)
    rows = []
    for tech, cov in run.coverage.items():
        state = {"strong": ok("strong"), "moderate": ok("moderate"), "weak": warn("weak"), "gap": bad("gap")}[cov.band()]
        rows.append([tech, cov.name[:40], ", ".join(cov.tactics), state, f"{cov.score*100:.0f}",
                     ", ".join(cov.passing) or dim("-")])
    print(table(rows, ["technique", "name", "tactics", "band", "score", "passing rules"]))
    print(dim(f"\nNavigator layer: {paths['navigator'].relative_to(cfg.root)} "
              "(load it at https://mitre-attack.github.io/attack-navigator/ via Open Existing Layer)"))
    return 0


def cmd_tune(args: argparse.Namespace) -> int:
    from sigmaforge.replay import Replayer, load_benign
    from sigmaforge.rules import load_rules
    from sigmaforge.tune import suggest

    cfg = _config(args)
    _ensure_baseline_corpus(cfg)
    specs, _ = load_rules(cfg.rules_dir, cfg.root)
    matches = [s for s in specs if args.rule in (s.key, s.id, s.path.name)]
    if not matches:
        print(bad(f"no rule named {args.rule!r}"))
        return 2
    spec = matches[0]
    benign = load_benign([Path(p) for p in args.benign] if args.benign else cfg.benign, cfg.root)
    run = Replayer(cfg.root, benign).run(spec)
    print(suggest(spec, run, benign, cfg.root, top=args.top))
    return 0


def cmd_drift(args: argparse.Namespace) -> int:
    from sigmaforge.drift import detect_drift

    cfg = _config(args)
    report = detect_drift(cfg, [Path(p) for p in args.benign], ratio=args.ratio, min_delta=args.min_delta)
    print(report.text())
    if args.markdown:
        Path(args.markdown).write_text(report.markdown(), encoding="utf-8")
    return 1 if report.drifted else 0


def cmd_baseline(args: argparse.Namespace) -> int:
    cfg = _config(args)
    if args.action == "generate":
        from sigmaforge import baseline

        out = Path(args.out) if args.out else cfg.root / cfg.baseline.get("out", "tests/benign/synthetic")
        info = baseline.generate(out, hosts=args.hosts or int(cfg.baseline.get("hosts", 12)),
                                 days=args.days or int(cfg.baseline.get("days", 14)),
                                 seed=args.seed if args.seed is not None else int(cfg.baseline.get("seed", 1337)))
        print(json.dumps(info.to_json(), indent=2))
        return 0
    if args.action == "update":
        from sigmaforge import gate as gate_mod
        from sigmaforge.pipeline import run_pipeline

        _ensure_baseline_corpus(cfg)
        run = run_pipeline(cfg, require_external=args.require_external, with_equivalence=False)
        metrics = gate_mod.metrics_from_results(run.results())
        cfg.baseline_metrics.parent.mkdir(parents=True, exist_ok=True)
        cfg.baseline_metrics.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {cfg.baseline_metrics.relative_to(cfg.root)}")
        return 0
    if args.action == "verify":
        from sigmaforge import baseline

        out = cfg.root / cfg.baseline.get("out", "tests/benign/synthetic")
        manifest = json.loads((cfg.root / "baseline" / "corpus.lock.json").read_text())
        info = baseline.generate(out, hosts=int(cfg.baseline.get("hosts", 12)), days=int(cfg.baseline.get("days", 14)),
                                 seed=int(cfg.baseline.get("seed", 1337)))
        if info.sha256 != manifest["sha256"]:
            print(bad(f"benign corpus hash {info.sha256} != locked {manifest['sha256']}"))
            print("The generator changed. If intended, run `sigmaforge baseline lock` and commit it.")
            return 1
        print(ok(f"benign corpus matches lock ({info.events:,} events, sha256 {info.sha256[:16]}...)"))
        return 0
    if args.action == "lock":
        from sigmaforge import baseline

        out = cfg.root / cfg.baseline.get("out", "tests/benign/synthetic")
        info = baseline.generate(out, hosts=int(cfg.baseline.get("hosts", 12)), days=int(cfg.baseline.get("days", 14)),
                                 seed=int(cfg.baseline.get("seed", 1337)))
        path = cfg.root / "baseline" / "corpus.lock.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(info.to_json(), indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path.relative_to(cfg.root)}")
        return 0
    return 2


def cmd_datasets(args: argparse.Namespace) -> int:
    from sigmaforge import datasets
    from sigmaforge.rules import load_rules

    cfg = _config(args)
    if args.action == "lock":
        lock = datasets.build_lock(cfg.root, datasets.DATASETS[args.name])
        print(f"pinned {len(lock['files'])} files at {lock['commit']}")
        return 0
    if args.action == "fetch":
        if args.all:
            files = datasets.fetch(cfg.root, args.name)
        else:
            specs, _ = load_rules(cfg.rules_dir, cfg.root)
            wanted = sorted({e.path for s in specs for e in s.tests.external if e.dataset == args.name})
            files = datasets.fetch(cfg.root, args.name, wanted)
        print(f"{len(files)} files verified in {datasets.cache_dir(cfg.root, datasets.DATASETS[args.name]).relative_to(cfg.root)}")
        return 0
    return 2


def cmd_badges(args: argparse.Namespace) -> int:
    from sigmaforge.badges import write_all

    cfg = _config(args)
    results_path = cfg.out_dir / "results.json"
    if not results_path.exists():
        print(bad("run `sigmaforge ci` first (out/results.json is missing)"))
        return 2
    results = json.loads(results_path.read_text(encoding="utf-8"))
    for path in write_all(results, Path(args.output)):
        print(f"wrote {path}")
    return 0


def cmd_attack(args: argparse.Namespace) -> int:
    from sigmaforge import attack

    att = attack.refresh()
    print(f"ATT&CK snapshot updated to v{att.version}: {len(att.tactics)} tactics, {len(att.techniques)} techniques")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from sigmaforge.convert import convert_backend

    cfg = _config(args)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.target == "elastic-template":
        from sigmaforge.opensearch import component_template_for_queries

        conv = convert_backend(cfg.rules_dir, cfg.backends["lucene"])
        queries = [q for c in conv.values() if c.ok for q in c.queries]
        template = component_template_for_queries(queries)
        out.write_text(json.dumps(template, indent=2) + "\n", encoding="utf-8")
        fields = len(template["template"]["mappings"]["_meta"]["caseless_fields"])
        print(f"wrote component template adding .caseless multi-fields to {fields} fields: {out}")
        return 0
    if args.target == "elastic":
        conv = convert_backend(cfg.rules_dir, cfg.backends["lucene"], output_format="siem_rule_ndjson")
    else:
        conv = convert_backend(cfg.rules_dir, cfg.backends["splunk"], output_format="savedsearches")
    chunks = [q for c in conv.values() if c.ok for q in c.queries]
    if args.target == "elastic":
        chunks = [json.dumps(json.loads(q), separators=(",", ":")) for q in chunks]  # one rule per line
    out.write_text("\n".join(chunks) + "\n", encoding="utf-8")
    print(f"wrote {len(chunks)} items to {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sigmaforge", description="Detection-as-code pipeline for Sigma rules.")
    p.add_argument("--version", action="version", version=f"sigmaforge {__version__}")
    p.add_argument("--root", default=".", help="repository root (default: current directory)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("lint", help="sigma check plus repository rules").set_defaults(func=cmd_lint)

    c = sub.add_parser("convert", help="convert rules to every backend")
    c.add_argument("--backend", action="append", help="only this backend (repeatable)")
    c.add_argument("--show", help="print the queries for one rule")
    c.set_defaults(func=cmd_convert)

    t = sub.add_parser("test", help="replay rules against positives, negatives and the benign baseline")
    t.add_argument("--require-external", action="store_true", help="fail when real-telemetry samples are missing")
    t.set_defaults(func=cmd_test)

    e = sub.add_parser("equivalence", help="compare hit sets across backends")
    e.add_argument("--opensearch", help="OpenSearch URL, e.g. http://localhost:9200")
    e.set_defaults(func=cmd_equivalence)

    ci = sub.add_parser("ci", help="full pipeline + merge gate + reports")
    ci.add_argument("--require-external", action="store_true")
    ci.add_argument("--opensearch", help="OpenSearch URL for real Lucene replay")
    ci.add_argument("--baseline", help="metrics.json from the base branch")
    ci.add_argument("--report-url", help="link to the published report for the PR comment")
    ci.add_argument("--no-equivalence", action="store_true")
    ci.set_defaults(func=cmd_ci)

    sub.add_parser("coverage", help="ATT&CK coverage + Navigator layer").set_defaults(func=cmd_coverage)

    tu = sub.add_parser("tune", help="explain a rule's benign hits and propose exclusions")
    tu.add_argument("rule")
    tu.add_argument("--benign", action="append", help="benign corpus path (default: from config)")
    tu.add_argument("--top", type=int, default=5)
    tu.set_defaults(func=cmd_tune)

    d = sub.add_parser("drift", help="compare noise on fresh benign data with the committed baseline")
    d.add_argument("--benign", action="append", required=True)
    d.add_argument("--ratio", type=float, default=2.0)
    d.add_argument("--min-delta", type=float, default=0.02)
    d.add_argument("--markdown", help="write an issue body here")
    d.set_defaults(func=cmd_drift)

    b = sub.add_parser("baseline", help="benign corpus and regression baseline")
    b.add_argument("action", choices=["generate", "update", "lock", "verify"])
    b.add_argument("--out")
    b.add_argument("--hosts", type=int)
    b.add_argument("--days", type=int)
    b.add_argument("--seed", type=int)
    b.add_argument("--require-external", action="store_true")
    b.set_defaults(func=cmd_baseline)

    ds = sub.add_parser("datasets", help="pinned public attack telemetry")
    ds.add_argument("action", choices=["lock", "fetch"])
    ds.add_argument("name", nargs="?", default="evtx-attack-samples")
    ds.add_argument("--all", action="store_true", help="fetch every file, not only those rules reference")
    ds.set_defaults(func=cmd_datasets)

    sub.add_parser("attack", help="refresh the ATT&CK snapshot (network)").set_defaults(func=cmd_attack)

    bd = sub.add_parser("badges", help="README badges and coverage strip from out/results.json")
    bd.add_argument("-o", "--output", default="docs/img")
    bd.set_defaults(func=cmd_badges)

    ex = sub.add_parser("export", help="deployable rule bundles")
    ex.add_argument("target", choices=["elastic", "elastic-template", "splunk"])
    ex.add_argument("-o", "--output", required=True)
    ex.set_defaults(func=cmd_export)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
