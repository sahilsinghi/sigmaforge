"""Render results as a self-contained HTML report and a Markdown PR comment."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup, escape

TEMPLATES = Path(__file__).parent / "templates"
COMMENT_MARKER = "<!-- sigmaforge-report -->"


def _md_inline(text: str) -> Markup:
    """Render `code` spans in gate messages; escape everything else."""
    parts = re.split(r"(`[^`]+`)", text)
    out = []
    for part in parts:
        if part.startswith("`") and part.endswith("`") and len(part) > 1:
            out.append(Markup("<code>") + escape(part[1:-1]) + Markup("</code>"))
        else:
            out.append(escape(part))
    return Markup("").join(out)


def render_html(results: dict[str, Any], gate: dict[str, Any] | None = None) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html", "j2"]))
    template = env.get_template("report.html.j2")
    ext_pass = sum(r["score"]["externals_passed"] for r in results["rules"])
    ext_total = sum(r["score"]["externals_total"] for r in results["rules"])
    return template.render(
        r=results,
        gate=gate,
        md=_md_inline,
        ext_pass=ext_pass,
        ext_total=ext_total,
        backends=results["backends"],
        commit=os.environ.get("GITHUB_SHA", ""),
    )


def _status_icon(ok: bool) -> str:
    return "✅" if ok else "❌"


def render_markdown(results: dict[str, Any], gate: dict[str, Any] | None, report_url: str | None = None) -> str:
    s = results["summary"]
    lines = [COMMENT_MARKER]
    if gate:
        verdict = "🚫 **Merge blocked**" if gate["decision"] == "block" else "✅ **Ready to merge**"
    else:
        verdict = "✅ **All rules pass**" if results["status"] == "pass" else "❌ **Failures**"
    lines.append(f"## SigmaForge · {verdict}")
    lines.append("")
    lines.append(
        f"**{s['passing']}/{s['rules']}** rules pass · **{s['techniques_covered']}/{s['techniques_tagged']}** "
        f"tagged techniques covered by a tested rule · benign baseline **{results['benign']['events']:,}** events / "
        f"**{results['benign']['host_days']}** host-days · ATT&CK v{results['attack_version']}"
    )
    eq = results.get("equivalence")
    if eq:
        os_part = ""
        if eq.get("opensearch"):
            o = eq["opensearch"]
            os_part = f" · OpenSearch agreed on {o['agree']}/{o['rules']} Lucene queries"
        lines.append(
            f"Cross-backend replay: {eq['identical']} identical, {eq['documented']} documented differences, "
            f"{eq['mismatch']} undocumented{os_part}"
        )
    lines.append("")
    if gate:
        if gate["reasons"]:
            lines.append("### Blocking")
            lines += [f"- {r}" for r in gate["reasons"]]
            lines.append("")
        if gate["warnings"]:
            lines.append("### Warnings")
            lines += [f"- {w}" for w in gate["warnings"]]
            lines.append("")
        if gate["improvements"]:
            lines.append("### Improvements")
            lines += [f"- {w}" for w in gate["improvements"]]
            lines.append("")
        if not gate.get("baseline_found", True):
            lines.append("> No `baseline/metrics.json` on the base branch, so regression checks were skipped.")
            lines.append("")
    lines.append("<details><summary>Per-rule results</summary>")
    lines.append("")
    lines.append("| Rule | Status | TPR | Real samples | Near-miss FP | Alerts/host/day (budget) | Quality |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in results["rules"]:
        sc = r["score"]
        tpr = f"{sc['positives_matched']}/{sc['positives_total']}" if sc["positives_total"] else "—"
        ext = f"{sc['externals_passed']}/{sc['externals_total']}" if sc["externals_total"] else ("skipped" if sc["externals_skipped"] else "—")
        if r["building_block"]:
            noise = "building block"
        elif sc["alerts_per_host_day"] is None:
            noise = "—"
        else:
            noise = f"{sc['alerts_per_host_day']:.3f} ({r['noise_budget']:g})"
        quality = f"{sc['quality']:.2f}" if sc["status"] == "pass" and not r["building_block"] else "—"
        lines.append(
            f"| `{r['key']}` | {_status_icon(sc['status'] == 'pass')} | {tpr} | {ext} | {sc['negative_fp']} | {noise} | {quality} |"
        )
    lines.append("")
    lines.append("</details>")
    failing = [r for r in results["rules"] if r["score"]["status"] != "pass"]
    if failing:
        lines.append("")
        lines.append("### Why rules failed")
        for r in failing:
            lines.append(f"**`{r['key']}`**")
            lines += [f"- {f}" for f in r["score"]["failures"][:6]]
            if r["benign"]["examples"] and any("noise" in f for f in r["score"]["failures"]):
                lines.append("- top benign hits (tuning candidates):")
                lines += [f"  - `{e['host']}` `{e['summary'][:160]}`" for e in r["benign"]["examples"][:5]]
    if report_url:
        lines.append("")
        lines.append(f"Full report, ATT&CK Navigator layer and converted queries: {report_url}")
    return "\n".join(lines) + "\n"
