"""The test cases from the project spec, run end to end on a copy of the repo.

* change a rule's field name to a wrong one  -> positive test fails, PR blocked
* loosen a rule to a broad wildcard          -> benign alerts/day over budget, blocked
* add a new rule with no test file           -> linter rejects it
* same rule, three backends                  -> identical hits (or documented reason)
* coverage map only lights tested, passing techniques
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from sigmaforge import coverage, gate
from sigmaforge.config import load_config
from sigmaforge.pipeline import run_pipeline

ENCODED = "rules/windows/process_creation/proc_creation_win_powershell_encoded_cmd.yml"


def _run(root: Path, equivalence: bool = False):
    run = run_pipeline(load_config(root), with_equivalence=equivalence)
    return run, run.results()


@pytest.fixture()
def main_branch(repo_copy: Path):
    """Results of the unmodified rules = the baseline main would commit."""
    _, results = _run(repo_copy)
    assert results["status"] == "pass", [r["score"]["failures"] for r in results["rules"] if r["score"]["failures"]]
    return repo_copy, gate.metrics_from_results(results)


def _edit(root: Path, rel: str, old: str, new: str) -> None:
    path = root / rel
    text = path.read_text()
    assert old in text, f"{old!r} not in {rel}"
    path.write_text(text.replace(old, new))


def test_wrong_field_name_breaks_positives_and_blocks(main_branch):
    root, baseline = main_branch
    _edit(root, ENCODED, "  selection_cli:\n    CommandLine|windash|contains:", "  selection_cli:\n    CommandLin|windash|contains:")
    _, results = _run(root)
    rule = next(r for r in results["rules"] if r["key"] == "proc_creation_win_powershell_encoded_cmd")
    assert rule["score"]["status"] == "fail"
    assert any("true-positive rate 0%" in f for f in rule["score"]["failures"])
    decision = gate.decide(results, baseline)
    assert decision.blocked
    assert any("regression" in r and "powershell_encoded_cmd" in r for r in decision.reasons)
    assert any("coverage regression: T1059.001" in r for r in decision.reasons)


def test_broad_wildcard_blows_noise_budget_and_blocks(main_branch):
    root, baseline = main_branch
    # "tidy up" the rule: drop the SCCM filter and match any dash-argument
    _edit(root, ENCODED, "  condition: all of selection_* and not filter_sccm", "  condition: all of selection_*")
    _edit(root, ENCODED, "      - ' -e '\n", "      - ' -'\n")
    _, results = _run(root)
    rule = next(r for r in results["rules"] if r["key"] == "proc_creation_win_powershell_encoded_cmd")
    assert rule["score"]["status"] == "fail"
    noise = [f for f in rule["score"]["failures"] if f.startswith("noise")]
    assert noise, rule["score"]["failures"]
    assert rule["score"]["alerts_per_host_day"] > rule["noise_budget"]
    assert gate.decide(results, baseline).blocked


def test_new_rule_without_tests_is_rejected_by_lint(main_branch):
    root, baseline = main_branch
    new = root / "rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml"
    new.write_text("""title: Bitsadmin Download
id: 7f3c2b1a-0d4e-4f5a-9b6c-1d2e3f4a5b6c
status: test
description: Bitsadmin transfer from a URL.
author: Sahil Singhi
date: 2026-10-18
tags:
  - attack.command-and-control
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\bitsadmin.exe'
    CommandLine|contains: '/transfer'
  condition: selection
level: medium
x_sigmaforge:
  owner: sahil.singhi
  confidence: medium
  noise_budget: 0.05
""")
    _, results = _run(root)
    rule = next(r for r in results["rules"] if r["key"] == "proc_creation_win_bitsadmin_download")
    assert any("no positive test data" in e for e in rule["lint"]["errors"])
    assert rule["score"]["status"] == "fail"
    decision = gate.decide(results, baseline)
    assert decision.blocked
    assert any("bitsadmin" in r for r in decision.reasons)


def test_backends_agree_or_differ_for_a_documented_reason(main_branch):
    root, _ = main_branch
    run, results = _run(root, equivalence=True)
    summary = results["equivalence"]
    assert summary["mismatch"] == 0, summary["mismatch_details"]
    assert summary["identical"] > 40
    by_key = {r["key"]: r for r in results["rules"]}
    encoded = by_key["proc_creation_win_powershell_encoded_cmd"]["equivalence"]["backends"]
    for backend in ("splunk", "lucene", "kql"):
        assert encoded[backend]["status"] == "identical", (backend, encoded[backend])
    assert encoded["lucene_stock"]["status"] == "documented"


def test_undocumented_backend_difference_blocks(main_branch):
    root, _ = main_branch
    exceptions = root / "equivalence-exceptions.yml"
    text = exceptions.read_text()
    # drop the documented reason for the stock-pipeline case-sensitivity gap
    text = re.sub(r"- rule: proc_creation_win_powershell_encoded_cmd\n  backend: lucene_stock\n(  .*\n|    .*\n)+", "", text)
    exceptions.write_text(text)
    _, results = _run(root, equivalence=True)
    rule = next(r for r in results["rules"] if r["key"] == "proc_creation_win_powershell_encoded_cmd")
    assert rule["score"]["status"] == "fail"
    assert any("equivalence: lucene_stock" in f for f in rule["score"]["failures"])


def test_coverage_only_lights_tested_passing_techniques(main_branch):
    root, _ = main_branch
    _edit(root, ENCODED, "  selection_cli:\n    CommandLine|windash|contains:", "  selection_cli:\n    CommandLin|windash|contains:")
    run, results = _run(root)
    cov = results["coverage"]
    assert cov["T1059.001"]["passing"] == []
    assert cov["T1059.001"]["band"] == "gap"
    layer = coverage.navigator_layer(run.coverage)
    entry = next(t for t in layer["techniques"] if t["techniqueID"] == "T1059.001")
    assert "score" not in entry and entry["color"] == coverage.GREY
    # building blocks never count as coverage
    assert "T1110" not in cov
    # every scored technique has at least one passing rule
    for t in layer["techniques"]:
        if "score" in t:
            assert cov[t["techniqueID"]]["passing"]


def test_results_are_json_serialisable(main_branch):
    root, _ = main_branch
    _, results = _run(root)
    json.dumps(results)
