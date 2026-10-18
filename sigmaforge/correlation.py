"""Sigma v2 correlation rules on top of the replay engine.

Supported correlation types: ``event_count``, ``value_count``, ``temporal``
and ``temporal_ordered``, with ``group-by``, ``timespan`` and field
``aliases``. Correlations may reference other correlations.

Windows are *sliding*: a burst of failures that straddles a clock boundary
still counts. Many SIEM conversions use fixed buckets instead (Splunk's
``bin _time span=5m``), which can miss a burst split across two buckets;
the equivalence report calls this out rather than hiding it.

After a group fires, its state is cleared so one incident produces one
alert, not one alert per additional event inside the window.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from sigma.correlations import (
    SigmaCorrelationConditionOperator as Op,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)
from sigma.rule import SigmaRule

from sigmaforge.engine import CompiledRule, compile_rule
from sigmaforge.events import Event


@dataclass
class Hit:
    """A base-rule match or a correlation alert, as seen by a correlation."""

    rule_key: str
    timestamp: datetime
    fields: dict[str, Any]
    events: list[Event] = field(default_factory=list)

    @property
    def epoch(self) -> float:
        return self.timestamp.timestamp()


@dataclass
class CorrelationAlert:
    rule: SigmaCorrelationRule
    timestamp: datetime
    group: dict[str, Any]
    events: list[Event]
    detail: str

    @property
    def computer(self) -> str:
        return self.events[-1].computer if self.events else "unknown-host"


_OPS: dict[Op, Callable[[float, float], bool]] = {
    Op.LT: lambda a, b: a < b,
    Op.LTE: lambda a, b: a <= b,
    Op.GT: lambda a, b: a > b,
    Op.GTE: lambda a, b: a >= b,
    Op.EQ: lambda a, b: a == b,
}
if hasattr(Op, "NEQ"):
    _OPS[Op.NEQ] = lambda a, b: a != b


class UnsupportedCorrelation(Exception):
    pass


def _ref_key(rule: Any) -> str:
    return getattr(rule, "name", None) or str(rule.id)


def _group_fields(corr: SigmaCorrelationRule, ref_rule: Any) -> list[str]:
    """Resolve group-by names through aliases for one referenced rule."""
    names = list(corr.group_by or [])
    aliases = getattr(corr, "aliases", None)
    alias_map = {}
    if aliases is not None:
        for alias in getattr(aliases, "aliases", {}).values():
            mapping = {}
            for ref, fieldname in alias.mapping.items():
                target = getattr(ref, "rule", None)
                mapping[_ref_key(target) if target is not None else str(ref.reference)] = fieldname
            alias_map[alias.alias] = mapping
    out = []
    for name in names:
        per_rule = alias_map.get(name)
        out.append(per_rule.get(_ref_key(ref_rule), name) if per_rule else name)
    return out


def _group_key(hit: Hit, fields_: list[str], names: list[str]) -> tuple | None:
    values = []
    for fieldname in fields_:
        value = hit.fields.get(fieldname)
        if value in (None, ""):
            return None  # SIEM stats drop events with an empty group-by field
        values.append(str(value).lower())
    return tuple(values)


class CorrelationEngine:
    """Evaluates correlations over a pre-sorted event list."""

    def __init__(self, compiled_cache: dict[int, CompiledRule] | None = None):
        self._compiled = compiled_cache if compiled_cache is not None else {}

    # -- base rule hits --------------------------------------------------
    def _base_hits(self, rule: SigmaRule, events: list[Event]) -> list[Hit]:
        compiled = self._compiled.get(id(rule))
        if compiled is None:
            compiled = compile_rule(rule)
            self._compiled[id(rule)] = compiled
        key = _ref_key(rule)
        return [Hit(key, ev.timestamp, ev.fields, [ev]) for ev in events if compiled.matches(ev)]

    def _hits_for(self, rule: Any, events: list[Event]) -> list[Hit]:
        if isinstance(rule, SigmaCorrelationRule):
            key = _ref_key(rule)
            hits = []
            for alert in self.evaluate(rule, events):
                merged = {}
                for ev in alert.events:
                    merged.update(ev.fields)
                merged.update(alert.group)
                hits.append(Hit(key, alert.timestamp, merged, alert.events))
            return hits
        return self._base_hits(rule, events)

    # -- evaluation ------------------------------------------------------
    def evaluate(self, corr: SigmaCorrelationRule, events: list[Event]) -> list[CorrelationAlert]:
        refs = [getattr(r, "rule", None) for r in corr.rules]
        if any(r is None for r in refs):
            raise UnsupportedCorrelation(f"{corr.title}: unresolved rule reference")
        span = float(corr.timespan.seconds)
        names = list(corr.group_by or [])

        tagged: list[tuple[Hit, tuple]] = []
        for ref in refs:
            fields_ = _group_fields(corr, ref)
            for hit in self._hits_for(ref, events):
                key = _group_key(hit, fields_, names)
                if key is not None:
                    tagged.append((hit, key))
        tagged.sort(key=lambda t: t[0].epoch)

        ctype = corr.type
        if ctype == SigmaCorrelationType.EVENT_COUNT:
            return self._event_count(corr, tagged, span, names)
        if ctype == SigmaCorrelationType.VALUE_COUNT:
            return self._value_count(corr, tagged, span, names)
        if ctype == SigmaCorrelationType.TEMPORAL:
            return self._temporal(corr, tagged, span, names, [_ref_key(r) for r in refs], ordered=False)
        if ctype == SigmaCorrelationType.TEMPORAL_ORDERED:
            return self._temporal(corr, tagged, span, names, [_ref_key(r) for r in refs], ordered=True)
        raise UnsupportedCorrelation(f"correlation type {ctype} is not supported by the local engine")

    def _condition(self, corr: SigmaCorrelationRule) -> tuple[Callable[[float, float], bool], float]:
        cond = corr.condition
        op = _OPS.get(cond.op)
        if op is None:
            raise UnsupportedCorrelation(f"condition operator {cond.op}")
        return op, float(cond.count)

    def _event_count(self, corr, tagged, span, names) -> list[CorrelationAlert]:
        op, threshold = self._condition(corr)
        windows: dict[tuple, deque[Hit]] = defaultdict(deque)
        alerts = []
        for hit, key in tagged:
            win = windows[key]
            win.append(hit)
            while win and hit.epoch - win[0].epoch > span:
                win.popleft()
            if op(len(win), threshold):
                alerts.append(self._alert(corr, hit, key, names, list(win), f"{len(win)} events in {corr.timespan.spec}"))
                win.clear()
        return alerts

    def _value_count(self, corr, tagged, span, names) -> list[CorrelationAlert]:
        op, threshold = self._condition(corr)
        fieldname = corr.condition.fieldref
        if not fieldname:
            raise UnsupportedCorrelation("value_count needs condition.field")
        windows: dict[tuple, deque[Hit]] = defaultdict(deque)
        alerts = []
        for hit, key in tagged:
            win = windows[key]
            win.append(hit)
            while win and hit.epoch - win[0].epoch > span:
                win.popleft()
            distinct = {str(h.fields.get(fieldname)).lower() for h in win if h.fields.get(fieldname) not in (None, "")}
            if op(len(distinct), threshold):
                alerts.append(
                    self._alert(corr, hit, key, names, list(win), f"{len(distinct)} distinct {fieldname} in {corr.timespan.spec}")
                )
                win.clear()
        return alerts

    def _temporal(self, corr, tagged, span, names, order: list[str], ordered: bool) -> list[CorrelationAlert]:
        state: dict[tuple, dict[str, list[Hit]]] = defaultdict(lambda: defaultdict(list))
        alerts = []
        for hit, key in tagged:
            seen = state[key]
            seen[hit.rule_key].append(hit)
            for rk in list(seen):
                seen[rk] = [h for h in seen[rk] if hit.epoch - h.epoch <= span]
            chain = self._chain(seen, order, ordered)
            if chain:
                alerts.append(
                    self._alert(corr, hit, key, names, chain, ("ordered " if ordered else "") + " -> ".join(order))
                )
                seen.clear()
        return alerts

    @staticmethod
    def _chain(seen: dict[str, list[Hit]], order: list[str], ordered: bool) -> list[Hit] | None:
        if not all(seen.get(rk) for rk in order):
            return None
        if not ordered:
            return [seen[rk][-1] for rk in order]
        # Walk backwards from the last step, picking the latest earlier hit.
        chain: list[Hit] = []
        bound = float("inf")
        for rk in reversed(order):
            candidates = [h for h in seen[rk] if h.epoch <= bound and h not in chain]
            if not candidates:
                return None
            pick = candidates[-1]
            chain.append(pick)
            bound = pick.epoch
        chain.reverse()
        return chain

    @staticmethod
    def _alert(corr, hit: Hit, key: tuple, names: list[str], members: list[Hit], detail: str) -> CorrelationAlert:
        events: list[Event] = []
        for member in members:
            events.extend(member.events)
        return CorrelationAlert(
            rule=corr,
            timestamp=hit.timestamp,
            group=dict(zip(names, key)),
            events=events,
            detail=detail,
        )
