"""Lint: pySigma's own validators plus SigmaForge's repository rules.

``sigma check`` catches malformed Sigma. The custom checks catch rules that
are valid Sigma but cannot be trusted in this repository:

* required metadata is missing (owner, noise budget, ATT&CK technique ...)
* a test file is missing, empty or unparseable - a rule with no positive
  sample is rejected outright
* a value is nothing but wildcards, or the condition only says what *not*
  to match - both alert on almost everything
* a regular expression uses syntax Lucene/OpenSearch does not support
  (inline flags, word boundaries, ``^``/``$`` anchors, lookarounds); it
  converts fine and then silently never matches in Elastic (verified
  against OpenSearch 2.19)
* an external sample is not in the pinned dataset lock
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from sigma.conditions import ConditionAND, ConditionNOT, ConditionOR
from sigma.correlations import SigmaCorrelationRule
from sigma.types import SigmaRegularExpression, SigmaString, SpecialChars

from sigmaforge import attack, datasets
from sigmaforge.events import EventFormatError, iter_files, load_events
from sigmaforge.rules import RuleSpec

REQUIRED_RULE_FIELDS = ("title", "id", "status", "description", "author", "date", "level")
FILENAME_PREFIXES = {
    "process_creation": "proc_creation_win_",
    "process_access": "proc_access_win_",
    "registry_set": "registry_set_win_",
    "registry_event": "registry_event_win_",
    "pipe_created": "pipe_created_win_",
    "dns_query": "dns_query_win_",
    "network_connection": "net_connection_win_",
    "file_event": "file_event_win_",
    "image_load": "image_load_win_",
}
SERVICE_PREFIXES = {"security": "win_security_", "system": "win_system_", "powershell": "win_powershell_"}

LUCENE_REGEX_PROBLEMS = [
    (re.compile(r"\(\?[imsx-]+\)|\(\?[imsx-]+:"), "inline flags like (?i) are not supported by Lucene regex"),
    (re.compile(r"(?<!\\)\\[bBAZz]"), r"\b, \A and \Z are not Lucene regex syntax (they match the literal letter)"),
    (re.compile(r"\(\?[=!<]"), "lookarounds are not supported by Lucene regex"),
    (re.compile(r"^\^|(?<!\\)\$$"), "^ and $ are literal characters in Lucene regex (patterns are implicitly anchored)"),
    (re.compile(r"(?<!\\)[@&~#<>]"), "@ & ~ # < > are operators in Lucene regex and must be escaped"),
]


@dataclass
class LintResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass
class LintReport:
    per_rule: dict[str, LintResult]
    global_errors: list[str]

    @property
    def ok(self) -> bool:
        return not self.global_errors and all(r.ok for r in self.per_rule.values())

    def error_count(self) -> int:
        return len(self.global_errors) + sum(len(r.errors) for r in self.per_rule.values())

    def warning_count(self) -> int:
        return sum(len(r.warnings) for r in self.per_rule.values())


# --------------------------------------------------------------------------

def _detection_values(rule):
    for name, detection in rule.detection.detections.items():
        for item in _walk_items(detection):
            for value in item.value:
                yield name, item, value


def _walk_items(detection):
    for item in detection.detection_items:
        if hasattr(item, "detection_items"):
            yield from _walk_items(item)
        else:
            yield item


def _only_wildcards(value: SigmaString) -> bool:
    parts = list(value.s)
    if not parts:
        return True
    return all(p in (SpecialChars.WILDCARD_MULTI, SpecialChars.WILDCARD_SINGLE) or p == "" for p in parts)


def _positive_leaf_exists(node, negated: bool = False) -> bool:
    """True if some leaf of the condition is reached without negation."""
    if isinstance(node, ConditionNOT):
        return _positive_leaf_exists(node.args[0], not negated)
    if isinstance(node, (ConditionAND, ConditionOR)):
        return any(_positive_leaf_exists(a, negated) for a in node.args)
    return not negated


def _check_regex(pattern: str) -> list[str]:
    problems = []
    for regex, message in LUCENE_REGEX_PROBLEMS:
        if regex.search(pattern):
            problems.append(message)
    return problems


def _check_tests(spec: RuleSpec, root: Path, res: LintResult) -> None:
    tests = spec.tests
    if not tests.positive and not tests.external:
        res.errors.append("no positive test data declared (x_sigmaforge.tests.positive)")
    for label, paths in (("positive", tests.positive), ("negative", tests.negative)):
        for path in paths:
            rel = path.relative_to(root) if path.is_relative_to(root) else path
            if not path.exists():
                res.errors.append(f"{label} test path {rel} does not exist")
                continue
            files = list(iter_files([path]))
            if not files:
                res.errors.append(f"{label} test path {rel} contains no event files")
                continue
            try:
                events = load_events(files)
            except EventFormatError as exc:
                res.errors.append(f"{label} test data does not parse: {exc}")
                continue
            if not events:
                res.errors.append(f"{label} test path {rel} contains no events")
    for ext in tests.external:
        ds = datasets.DATASETS.get(ext.dataset)
        if ds is None:
            res.errors.append(f"external sample uses unknown dataset {ext.dataset!r}")
            continue
        try:
            lock = datasets.load_lock(root, ds)
        except datasets.DatasetError as exc:
            res.errors.append(str(exc))
            continue
        if ext.path not in lock["files"]:
            res.errors.append(f"external sample {ext.path!r} is not in the pinned {ext.dataset} tree")


def lint_rule(spec: RuleSpec, root: Path) -> LintResult:
    res = LintResult()
    rule = spec.rule
    att = attack.load()

    for name in REQUIRED_RULE_FIELDS:
        value = getattr(rule, name, None)
        if value in (None, "", []):
            res.errors.append(f"missing required field '{name}'")
    if not spec.owner:
        res.errors.append("missing x_sigmaforge.owner")
    if spec.confidence not in ("low", "medium", "high"):
        res.errors.append(f"x_sigmaforge.confidence must be low, medium or high (got {spec.confidence!r})")
    budget = spec.meta.get("noise_budget")
    if not spec.building_block:
        if budget is None:
            res.errors.append("missing x_sigmaforge.noise_budget (max alerts per host per day)")
        elif not isinstance(budget, (int, float)) or not 0 <= float(budget) <= 50:
            res.errors.append(f"noise_budget must be a number between 0 and 50 (got {budget!r})")

    techniques = spec.techniques
    if not techniques:
        res.errors.append("no ATT&CK technique tag (attack.tNNNN)")
    for tech in techniques:
        if not att.exists(tech):
            res.errors.append(f"{tech} is not a technique in ATT&CK v{att.version}")
    if techniques and not spec.tactics:
        res.errors.append(f"no ATT&CK tactic tag valid in v{att.version} (e.g. attack.execution)")
    for tech in techniques:
        if att.exists(tech) and spec.tactics and not set(att.tactics_of(tech)) & set(spec.tactics):
            res.warnings.append(
                f"{tech} belongs to {', '.join(att.tactics_of(tech))} in ATT&CK v{att.version}, none of which is tagged"
            )

    if not isinstance(rule, SigmaCorrelationRule):
        _lint_detection(spec, res)
        category = rule.logsource.category
        service = rule.logsource.service
        expected = FILENAME_PREFIXES.get(category or "") or SERVICE_PREFIXES.get(service or "")
        if expected and not spec.path.name.startswith(expected) and "correlation" not in spec.path.parts:
            res.warnings.append(f"file name should start with '{expected}' for this log source")
    if len(spec.path.name) > 90:
        res.warnings.append("file name longer than 90 characters")

    _check_tests(spec, root, res)
    return res


def _lint_detection(spec: RuleSpec, res: LintResult) -> None:
    rule = spec.rule
    for name, item, value in _detection_values(rule):
        field_label = f"{name}.{item.field or '<keyword>'}"
        if isinstance(value, SigmaString) and _only_wildcards(value):
            res.errors.append(f"{field_label}: value matches anything (wildcard-only or empty contains)")
        if isinstance(value, SigmaRegularExpression):
            pattern = value.regexp.to_plain() if isinstance(value.regexp, SigmaString) else str(value.regexp)
            for problem in _check_regex(pattern):
                res.warnings.append(f"{field_label}: regex /{pattern}/ - {problem}")
        if isinstance(value, SigmaString) and not _only_wildcards(value):
            plain = "".join(p for p in value.s if isinstance(p, str)).strip()
            if len(plain) < 2 and item.field:
                res.warnings.append(f"{field_label}: value {plain!r} is very short and likely broad")
    for cond in rule.detection.parsed_condition:
        try:
            tree = cond.parsed
        except Exception as exc:  # noqa: BLE001 - surfaced as lint error
            res.errors.append(f"condition does not parse: {exc}")
            continue
        if not _positive_leaf_exists(tree):
            res.errors.append(f"condition '{cond.condition}' only excludes events; it matches everything else")


def run_sigma_validators(specs: list[RuleSpec], exclude: list[str]) -> dict[str, list[tuple[str, str]]]:
    """Run every installed pySigma validator. Returns rule-id -> [(severity, text)]."""
    from sigma.plugins import InstalledSigmaPlugins
    from sigma.validation import SigmaValidator

    plugins = InstalledSigmaPlugins.autodiscover()
    excluded = {e.lower() for e in exclude}
    validators = [v for name, v in plugins.validators.items() if name.lower() not in excluded]
    validator = SigmaValidator(validators)
    by_id: dict[str, list[tuple[str, str]]] = {}
    rules = [s.rule for s in specs]
    for issue in validator.validate_rules(rules):
        severity = getattr(issue.severity, "name", str(issue.severity)).lower()
        text = str(issue)
        for rule in issue.rules:
            by_id.setdefault(str(rule.id), []).append((severity, text))
    return by_id


def lint_all(specs: list[RuleSpec], load_errors: list[str], root: Path, exclude: list[str]) -> LintReport:
    per_rule = {spec.key: lint_rule(spec, root) for spec in specs}
    global_errors = list(load_errors)
    seen_ids: dict[str, str] = {}
    seen_titles: dict[str, str] = {}
    for spec in specs:
        if spec.id in seen_ids:
            global_errors.append(f"duplicate rule id {spec.id} in {spec.key} and {seen_ids[spec.id]}")
        seen_ids[spec.id] = spec.key
        if spec.title in seen_titles:
            per_rule[spec.key].errors.append(f"duplicate title (also used by {seen_titles[spec.title]})")
        seen_titles[spec.title] = spec.key
    try:
        issues = run_sigma_validators(specs, exclude)
    except Exception as exc:  # noqa: BLE001 - e.g. ATT&CK feed unreachable
        global_errors.append(f"pySigma validators could not run: {exc}")
        issues = {}
    for spec in specs:
        for severity, text in issues.get(spec.id, []):
            target = per_rule[spec.key].errors if severity in ("high", "critical", "medium") else per_rule[spec.key].warnings
            target.append(f"sigma check: {text}")
    return LintReport(per_rule=per_rule, global_errors=global_errors)
