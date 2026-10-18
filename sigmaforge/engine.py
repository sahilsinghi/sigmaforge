"""Evaluate Sigma rules directly against events - the local replay engine.

The engine does not re-implement Sigma parsing. pySigma parses each rule,
applies the modifiers (``contains``, ``windash``, ``base64offset``, ``all``,
``cidr`` ...) and resolves the condition (``1 of selection_*``) into a tree of
AND / OR / NOT nodes whose leaves are ``field == typed value``. This module
walks that tree. Because it consumes the same tree the SIEM backends convert,
a disagreement between the engine and a converted query is a real backend
or field-mapping difference, not a parsing difference.

Matching semantics follow the Sigma specification:

* strings are case-insensitive unless the ``cased`` modifier is used
* ``*`` and ``?`` are wildcards and the value must match the whole field
* ``re`` is an unanchored search, case-sensitive unless ``re|i``
* a list-valued field matches if any element matches
* keywords (values with no field) search every string field of the event
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Callable

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

from sigmaforge.events import Event
from sigmaforge.logsource import rule_accepts

Predicate = Callable[[Event], bool]


class UnsupportedSigma(Exception):
    """The rule uses a construct the local engine cannot evaluate."""


# --------------------------------------------------------------------------
# Value matchers (value -> predicate over a single field value)
# --------------------------------------------------------------------------

def sigma_string_regex(value: SigmaString, cased: bool = False) -> re.Pattern[str]:
    parts: list[str] = []
    for part in value.s:
        if isinstance(part, str):
            parts.append(re.escape(part))
        elif part is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            raise UnsupportedSigma(f"placeholder {part!r} must be resolved before replay")
    flags = re.DOTALL if cased else re.DOTALL | re.IGNORECASE
    return re.compile("".join(parts), flags)


def _as_values(raw: Any) -> list[Any]:
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        return [v for v in raw if v is not None]
    return [raw]


def _to_number(raw: Any) -> float | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        text = raw.strip()
        try:
            return float(int(text, 0)) if text.lower().startswith("0x") else float(text)
        except ValueError:
            return None
    return None


def _compile_value(value: Any) -> Callable[[Any], bool]:
    """Compile a Sigma value into a predicate over one raw field value."""
    if isinstance(value, SigmaString):
        pattern = sigma_string_regex(value, cased=isinstance(value, SigmaCasedString))
        return lambda raw: raw is not None and pattern.fullmatch(_stringify(raw)) is not None
    if isinstance(value, SigmaNumber):
        target = float(value.number)
        text = str(value.number)

        def match_number(raw: Any) -> bool:
            num = _to_number(raw)
            if num is not None:
                return num == target
            return isinstance(raw, str) and raw.strip() == text

        return match_number
    if isinstance(value, SigmaBool):
        return lambda raw: str(raw).lower() == str(value.boolean).lower()
    if isinstance(value, SigmaRegularExpression):
        flags = 0
        if SigmaRegularExpressionFlag.IGNORECASE in value.flags:
            flags |= re.IGNORECASE
        if SigmaRegularExpressionFlag.MULTILINE in value.flags:
            flags |= re.MULTILINE
        if SigmaRegularExpressionFlag.DOTALL in value.flags:
            flags |= re.DOTALL
        regex = value.regexp.to_plain() if isinstance(value.regexp, SigmaString) else str(value.regexp)
        compiled = re.compile(regex, flags)
        return lambda raw: raw is not None and compiled.search(_stringify(raw)) is not None
    if isinstance(value, SigmaCIDRExpression):
        network = value.network

        def match_cidr(raw: Any) -> bool:
            try:
                return ipaddress.ip_address(str(raw).strip()) in network
            except ValueError:
                return False

        return match_cidr
    if isinstance(value, SigmaCompareExpression):
        bound = float(value.number.number)
        ops = {
            CompareOperators.LT: lambda a: a < bound,
            CompareOperators.LTE: lambda a: a <= bound,
            CompareOperators.GT: lambda a: a > bound,
            CompareOperators.GTE: lambda a: a >= bound,
        }
        op = ops.get(value.op)
        if op is None:  # pragma: no cover - future operators
            raise UnsupportedSigma(f"compare operator {value.op}")

        def match_compare(raw: Any) -> bool:
            num = _to_number(raw)
            return num is not None and op(num)

        return match_compare
    raise UnsupportedSigma(f"value type {type(value).__name__}")


def _stringify(raw: Any) -> str:
    if isinstance(raw, bool):
        return str(raw).lower()
    return str(raw)


def _is_empty(raw: Any) -> bool:
    return raw is None or raw == "" or raw == []


# --------------------------------------------------------------------------
# Condition tree -> predicate
# --------------------------------------------------------------------------

def _field_predicate(fieldname: str, value: Any) -> Predicate:
    if isinstance(value, SigmaExpansion):
        preds = [_field_predicate(fieldname, v) for v in value.values]
        return lambda ev: any(p(ev) for p in preds)
    if isinstance(value, SigmaNull):
        return lambda ev: _is_empty(ev.get(fieldname))
    if isinstance(value, SigmaExists):
        if value.exists:
            return lambda ev: ev.has(fieldname)
        return lambda ev: not ev.has(fieldname)
    if isinstance(value, SigmaFieldReference):
        other = value.field

        def match_ref(ev: Event) -> bool:
            left = ev.get(fieldname)
            right = ev.get(other)
            if left is None or right is None:
                return False
            ls, rs = _stringify(left).lower(), _stringify(right).lower()
            if value.starts_with:
                return ls.startswith(rs)
            if value.ends_with:
                return ls.endswith(rs)
            return ls == rs

        return match_ref
    matcher = _compile_value(value)
    return lambda ev: any(matcher(v) for v in _as_values(ev.get(fieldname)))


def _keyword_predicate(value: Any) -> Predicate:
    if isinstance(value, SigmaExpansion):
        preds = [_keyword_predicate(v) for v in value.values]
        return lambda ev: any(p(ev) for p in preds)
    if isinstance(value, SigmaString):
        # Keyword search is a substring search over every string field.
        pattern = sigma_string_regex(value, cased=isinstance(value, SigmaCasedString))

        def match_keyword(ev: Event) -> bool:
            for raw in ev.fields.values():
                for v in _as_values(raw):
                    if isinstance(v, str) and pattern.search(v):
                        return True
            return False

        return match_keyword
    matcher = _compile_value(value)
    return lambda ev: any(matcher(v) for raw in ev.fields.values() for v in _as_values(raw))


def compile_tree(node: Any) -> Predicate:
    if isinstance(node, ConditionAND):
        preds = [compile_tree(a) for a in node.args]
        return lambda ev: all(p(ev) for p in preds)
    if isinstance(node, ConditionOR):
        preds = [compile_tree(a) for a in node.args]
        return lambda ev: any(p(ev) for p in preds)
    if isinstance(node, ConditionNOT):
        inner = compile_tree(node.args[0])
        return lambda ev: not inner(ev)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _field_predicate(node.field, node.value)
    if isinstance(node, ConditionValueExpression):
        return _keyword_predicate(node.value)
    raise UnsupportedSigma(f"condition node {type(node).__name__}")


@dataclass
class CompiledRule:
    rule: SigmaRule
    predicate: Predicate

    def accepts(self, event: Event) -> bool:
        return rule_accepts(self.rule.logsource, event.source)

    def matches(self, event: Event) -> bool:
        return self.accepts(event) and self.predicate(event)


def compile_rule(rule: SigmaRule) -> CompiledRule:
    if rule.errors:
        raise UnsupportedSigma("; ".join(str(e) for e in rule.errors))
    conditions = [compile_tree(c.parsed) for c in rule.detection.parsed_condition]
    if len(conditions) == 1:
        predicate = conditions[0]
    else:
        predicate = lambda ev: any(p(ev) for p in conditions)  # noqa: E731
    return CompiledRule(rule=rule, predicate=predicate)


def match_events(compiled: CompiledRule, events: list[Event]) -> list[Event]:
    return [ev for ev in events if compiled.matches(ev)]
