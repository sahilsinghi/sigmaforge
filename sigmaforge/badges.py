"""Static SVGs for the README: status badges and an ATT&CK coverage strip.

CI regenerates these on ``main`` and publishes them with the report, so the
front page always shows the last tested state rather than a hand-written
claim.
"""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any

BAND_COLORS = {"strong": "#15803d", "moderate": "#86efac", "weak": "#fde68a", "gap": "#d4d4d4"}


def _text_width(text: str) -> int:
    return int(sum(7 if c.isupper() or c.isdigit() else 6 for c in text)) + 10


def badge(label: str, value: str, color: str) -> str:
    lw, vw = _text_width(label), _text_width(value)
    w = lw + vw
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="{escape(label)}: {escape(value)}">
<title>{escape(label)}: {escape(value)}</title>
<clipPath id="r"><rect width="{w}" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#555"/><rect x="{lw}" width="{vw}" height="20" fill="{color}"/></g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
<text x="{lw / 2}" y="14">{escape(label)}</text><text x="{lw + vw / 2}" y="14">{escape(value)}</text></g>
</svg>
"""


def coverage_strip(results: dict[str, Any]) -> str:
    """One column per ATT&CK tactic, one cell per tagged technique."""
    tactics = results["tactics"]
    col_w, cell_h, gap, head = 118, 30, 6, 46
    rows = max([len(t["techniques"]) for t in tactics] + [1])
    width = len(tactics) * (col_w + gap) + gap
    height = head + rows * (cell_h + 4) + 34
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        'font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif" role="img" aria-label="ATT&amp;CK coverage">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
    ]
    for i, tactic in enumerate(tactics):
        x = gap + i * (col_w + gap)
        name = tactic["tactic"].replace("-", " ")
        words = name.split()
        line1, line2 = (" ".join(words[:2]), " ".join(words[2:])) if len(name) > 18 else (name, "")
        parts.append(f'<text x="{x + 4}" y="16" font-size="11" font-weight="600" fill="#111">{escape(line1)}</text>')
        if line2:
            parts.append(f'<text x="{x + 4}" y="29" font-size="11" font-weight="600" fill="#111">{escape(line2)}</text>')
        parts.append(f'<text x="{x + 4}" y="41" font-size="10" fill="#666">{tactic["covered"]}/{tactic["tagged"]} covered</text>')
        for j, tech in enumerate(tactic["techniques"]):
            y = head + j * (cell_h + 4)
            color = BAND_COLORS[tech["band"]]
            fg = "#ffffff" if tech["band"] == "strong" else "#111111"
            label = f'{tech["technique"]}'
            score = f'{round(tech["score"] * 100)}' if tech["passing"] else "—"
            title = escape(f'{tech["technique"]} {tech["name"]}: {score}')
            parts.append(f'<g><title>{title}</title><rect x="{x}" y="{y}" width="{col_w}" height="{cell_h}" rx="4" fill="{color}"/>')
            parts.append(f'<text x="{x + 6}" y="{y + 13}" font-size="10" font-weight="600" fill="{fg}">{escape(label)}  {score}</text>')
            short = tech["name"] if len(tech["name"]) <= 20 else tech["name"][:19] + "…"
            parts.append(f'<text x="{x + 6}" y="{y + 25}" font-size="9.5" fill="{fg}">{escape(short)}</text></g>')
    ly = height - 14
    lx = gap
    for band, label in (("strong", "strong ≥75"), ("moderate", "moderate 50–74"), ("weak", "weak <50"), ("gap", "tagged, not passing")):
        parts.append(f'<rect x="{lx}" y="{ly - 9}" width="10" height="10" rx="2" fill="{BAND_COLORS[band]}"/>')
        parts.append(f'<text x="{lx + 14}" y="{ly}" font-size="10" fill="#444">{escape(label)}</text>')
        lx += 120
    parts.append(f'<text x="{width - 6}" y="{ly}" font-size="10" fill="#666" text-anchor="end">ATT&amp;CK v{escape(results["attack_version"])} · '
                 'score = tested quality of passing rules</text>')
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def write_all(results: dict[str, Any], out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    s = results["summary"]
    ok = results["status"] == "pass"
    files = {
        "rules.svg": badge("rules passing", f"{s['passing']}/{s['rules']}", "#2ea043" if ok else "#cf222e"),
        "coverage.svg": badge("ATT&CK techniques", f"{s['techniques_covered']} tested", "#1f6feb"),
        "attack-coverage.svg": coverage_strip(results),
    }
    eq = results.get("equivalence")
    if eq:
        files["backends.svg"] = badge("backend parity", f"{eq['identical']} identical · {eq['documented']} documented",
                                      "#2ea043" if not eq["mismatch"] else "#cf222e")
    paths = []
    for name, svg in files.items():
        path = out_dir / name
        path.write_text(svg, encoding="utf-8")
        paths.append(path)
    return paths
