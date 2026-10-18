#!/usr/bin/env python3
"""Record the README GIF from real runs: a PR that breaks a rule is blocked, the fix passes.

    python scripts/record_demo.py docs/demo.gif      (needs Pillow)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(sys.executable).parent
RULE = "rules/windows/process_creation/proc_creation_win_powershell_encoded_cmd.yml"


def main() -> int:
    out_gif = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "demo.gif"
    work = Path(tempfile.mkdtemp(prefix="sigmaforge-demo-"))
    for name in ("rules", "tests", "datasets", "baseline", "sigmaforge.yml", "equivalence-exceptions.yml"):
        src = ROOT / name
        (shutil.copytree if src.is_dir() else shutil.copy)(src, work / name)
    if (ROOT / ".cache").exists():
        (work / ".cache").symlink_to(ROOT / ".cache")
    env = {**os.environ, "NO_COLOR": "1", "PATH": f"{BIN}:{os.environ['PATH']}"}

    def run(cmd: str) -> str:
        p = subprocess.run(cmd, shell=True, cwd=work, env=env, capture_output=True, text=True)
        return (p.stdout + p.stderr).rstrip()

    steps: list[dict] = [{"say": "# SigmaForge: every PR replays the rules before it can merge", "hold": 1.5}]

    def step(cmd: str, hold: float = 1.8, grep: tuple[str, ...] = (), tail: int | None = None, show: str | None = None):
        lines = run(cmd).splitlines()
        if grep:
            lines = [ln for ln in lines if any(g in ln for g in grep)]
        if tail:
            lines = lines[-tail:]
        steps.append({"cmd": show or cmd, "out": "\n".join(lines), "hold": hold})

    run("sigmaforge baseline update")
    step("sigmaforge ci --no-equivalence", hold=2.5,
         grep=("powershell_encoded", "lsass_memory", "run_key", "bruteforce", "rules pass", "benign baseline", "READY", "BLOCKED"))
    steps.append({"say": "# PR: 'simplify' the encoded-PowerShell rule: ' -e' instead of ' -e ', drop the SCCM filter", "hold": 2.0})
    path = work / RULE
    text = path.read_text()
    text = text.replace("      - ' -e '\n      - ' -en '\n      - ' -enc '\n      - ' -ec '\n      - ' -encodedcommand '\n", "      - ' -e'\n")
    text = text.replace("  filter_sccm:\n    ParentImage: 'C:\\Windows\\CCM\\CcmExec.exe'\n", "")
    text = text.replace("  condition: all of selection_* and not filter_sccm", "  condition: all of selection_*")
    path.write_text(text)
    step(f"grep -A3 'selection_cli' {RULE}", hold=1.5)
    step("sigmaforge ci --no-equivalence", hold=6.0,
         grep=("FAIL  proc_creation_win_powershell", "MERGE BLOCKED", "  - `proc", "  - regression", "  - coverage"))
    steps.append({"say": "# fix: restore the spaced patterns and the SCCM filter", "hold": 1.5})
    shutil.copy(ROOT / RULE, path)
    step("sigmaforge ci --no-equivalence", hold=3.0, grep=("PASS  proc_creation_win_powershell", "rules pass", "READY", "BLOCKED"))

    session = work / "session.json"
    session.write_text(json.dumps(steps, indent=1))
    subprocess.run([sys.executable, str(ROOT / "scripts" / "termgif.py"), str(session), str(out_gif), "sigmaforge demo"],
                   check=True)
    shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
