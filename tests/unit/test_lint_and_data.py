"""Linter rules, dataset pinning and the deterministic benign baseline."""

import hashlib
import json
from pathlib import Path

from sigmaforge import baseline, datasets
from sigmaforge.lint import _check_regex, lint_rule
from sigmaforge.rules import load_rules


def _write_rule(root: Path, body: str, name: str = "proc_creation_win_test_rule.yml") -> Path:
    path = root / "rules" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path


BASE = """title: Test
id: 5d6c1c2e-1111-4222-8333-944455556666
status: test
description: d
author: a
date: 2026-10-18
level: low
tags: [attack.execution, attack.t1059.001]
logsource: {category: process_creation, product: windows}
detection:
%s
x_sigmaforge:
  owner: me
  noise_budget: 0.1
  tests:
    positive: [tests/positive/p]
"""


def _lint(tmp_path, detection):
    _write_rule(tmp_path, BASE % detection)
    pos = tmp_path / "tests/positive/p"
    pos.mkdir(parents=True, exist_ok=True)
    (pos / "e.jsonl").write_text(json.dumps({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                                             "Computer": "h", "@timestamp": "2026-10-01T00:00:00Z", "Image": "x"}) + "\n")
    specs, errors = load_rules(tmp_path / "rules", tmp_path)
    assert not errors
    return lint_rule(specs[0], tmp_path)


def test_wildcard_only_value_is_an_error(tmp_path):
    res = _lint(tmp_path, "  sel:\n    CommandLine|contains: '*'\n  condition: sel")
    assert any("matches anything" in e for e in res.errors)


def test_negation_only_condition_is_an_error(tmp_path):
    res = _lint(tmp_path, "  filter:\n    Image|endswith: '\\\\explorer.exe'\n  condition: not filter")
    assert any("only excludes events" in e for e in res.errors)


def test_clean_rule_passes(tmp_path):
    res = _lint(tmp_path, "  sel:\n    Image|endswith: '\\\\powershell.exe'\n  condition: sel")
    assert res.errors == []


def test_missing_metadata_and_test_paths(tmp_path):
    body = (BASE % "  sel:\n    Image: x\n  condition: sel").replace("  owner: me\n", "").replace("tests/positive/p", "tests/positive/missing")
    _write_rule(tmp_path, body)
    specs, _ = load_rules(tmp_path / "rules", tmp_path)
    res = lint_rule(specs[0], tmp_path)
    assert any("owner" in e for e in res.errors)
    assert any("does not exist" in e for e in res.errors)


def test_lucene_regex_portability_checks():
    assert any("inline flags" in p for p in _check_regex(r"(?i)foo"))
    assert any("literal letter" in p for p in _check_regex(r"\bfoo"))
    assert _check_regex(r"\d+-\w+") == []
    assert any("anchored" in p for p in _check_regex(r"^abc$"))
    assert _check_regex(r"\\[^\\]+-[0-9]+-(stdin|stdout)") == []


def test_outdated_attack_tags_are_rejected(tmp_path):
    body = (BASE % "  sel:\n    Image: x\n  condition: sel").replace(
        "tags: [attack.execution, attack.t1059.001]", "tags: [attack.defense-evasion, attack.t1070.001]")
    _write_rule(tmp_path, body)
    specs, _ = load_rules(tmp_path / "rules", tmp_path)
    res = lint_rule(specs[0], tmp_path)
    assert any("T1070.001 is not a technique" in e for e in res.errors)


def test_git_blob_sha_matches_git():
    # `printf 'hello\n' | git hash-object --stdin`
    assert datasets.git_blob_sha1(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_dataset_lock_pins_commit(repo):
    lock = json.loads((repo / "datasets/evtx-attack-samples.lock.json").read_text())
    assert lock["commit"] == datasets.DATASETS["evtx-attack-samples"].commit
    assert len(lock["files"]) > 200


def test_benign_baseline_is_deterministic(tmp_path, repo):
    a = baseline.generate(tmp_path / "a", days=2)
    b = baseline.generate(tmp_path / "b", days=2)
    assert a.sha256 == b.sha256 == hashlib.sha256((tmp_path / "a" / a.path.name).read_bytes()).hexdigest()
    lock = json.loads((repo / "baseline/corpus.lock.json").read_text())
    full = baseline.generate(tmp_path / "c", hosts=lock["hosts"], days=lock["days"], seed=lock["seed"])
    assert full.sha256 == lock["sha256"], "generator changed: run `sigmaforge baseline lock`"
