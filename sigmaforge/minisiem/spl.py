"""Splunk SPL evaluator for the subset pySigma's Splunk backend emits.

Splunk semantics that matter here:

* Boolean precedence is NOT > OR > AND, and AND is implied between terms.
  ``a OR b c OR d`` means ``(a OR b) AND (c OR d)`` - pySigma relies on it.
* ``field=value`` compares case-insensitively, ``*`` is a wildcard and the
  whole value must match. A missing field never equals anything, so
  ``NOT field=x`` is true for events without the field.
* ``| regex field="re"`` keeps events whose field matches (PCRE search,
  case-sensitive unless ``(?i)``).
* Inside double quotes ``\\\\`` is a backslash and ``\\"`` a quote.

Supported commands: search, regex, rex, eval (``if(isnotnull(x), a, b)``),
bin, stats (count / dc), table, fields. Correlation queries use
``bin _time span=...`` - fixed time buckets, not sliding windows.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Callable

from sigmaforge.minisiem import Unsupported

Doc = dict[str, Any]
Pred = Callable[[Doc], bool]


def _split_pipes(query: str) -> list[str]:
    parts, buf, in_q, i = [], [], False, 0
    while i < len(query):
        ch = query[i]
        if ch == "\\" and in_q and i + 1 < len(query):
            buf.append(query[i:i + 2])
            i += 2
            continue
        if ch == '"':
            in_q = not in_q
        if ch == "|" and not in_q:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf).strip())
    return [p for p in parts if p]


def unquote(text: str) -> str:
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        inner = text[1:-1]
        return re.sub(r'\\(["\\])', r"\1", inner)
    return text


@dataclass
class _Tok:
    kind: str  # LP RP AND OR NOT CMP IN WORD COMMA
    field: str = ""
    op: str = ""
    value: str = ""


_CMP = re.compile(r'([A-Za-z_][\w.]*)\s*(!=|>=|<=|=|>|<)\s*("(?:[^"\\]|\\.)*"|[^\s()]+)')
_IN = re.compile(r"([A-Za-z_][\w.]*)\s+IN\s*\(", re.IGNORECASE)
_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')


def tokenize(expr: str) -> list[_Tok]:
    toks: list[_Tok] = []
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "(":
            toks.append(_Tok("LP"))
            i += 1
            continue
        if ch == ")":
            toks.append(_Tok("RP"))
            i += 1
            continue
        m = _IN.match(expr, i)
        if m:
            j = m.end()
            values = []
            while True:
                while j < len(expr) and expr[j] in " ,":
                    j += 1
                if j < len(expr) and expr[j] == ")":
                    j += 1
                    break
                q = _QUOTED.match(expr, j)
                if q:
                    values.append(unquote(q.group(0)))
                    j = q.end()
                    continue
                w = re.match(r"[^\s,()]+", expr[j:])
                if not w:
                    raise Unsupported("bad IN list")
                values.append(w.group(0))
                j += len(w.group(0))
            toks.append(_Tok("IN", field=m.group(1), value="\x00".join(values)))
            i = j
            continue
        m = _CMP.match(expr, i)
        if m:
            toks.append(_Tok("CMP", field=m.group(1), op=m.group(2), value=unquote(m.group(3))))
            i = m.end()
            continue
        q = _QUOTED.match(expr, i)
        if q:
            toks.append(_Tok("WORD", value=unquote(q.group(0))))
            i = q.end()
            continue
        w = re.match(r"[^\s()]+", expr[i:])
        word = w.group(0)
        if word in ("AND", "OR", "NOT"):
            toks.append(_Tok(word))
        else:
            toks.append(_Tok("WORD", value=word))
        i += len(word)
    return toks


def _wild(value: str) -> re.Pattern[str]:
    parts = [".*" if p == "*" else re.escape(p) for p in re.split(r"(\*)", value)]
    return re.compile("".join(parts), re.IGNORECASE | re.DOTALL)


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _vals(doc: Doc, field: str) -> list[Any]:
    raw = doc.get(field)
    if raw is None:
        return []
    return raw if isinstance(raw, list) else [raw]


def _cmp_pred(field: str, op: str, value: str) -> Pred:
    if op in ("=", "!="):
        rx = _wild(value)
        num = _num(value)

        def eq_one(v: Any) -> bool:
            if num is not None and _num(v) is not None and "*" not in value:
                return _num(v) == num
            return rx.fullmatch(str(v)) is not None

        if op == "=":
            return lambda doc: any(eq_one(v) for v in _vals(doc, field))
        return lambda doc: bool(_vals(doc, field)) and not any(eq_one(v) for v in _vals(doc, field))
    target = _num(value)
    if target is None:
        raise Unsupported(f"non-numeric comparison {field}{op}{value}")
    ops = {">": lambda a: a > target, "<": lambda a: a < target, ">=": lambda a: a >= target, "<=": lambda a: a <= target}
    fn = ops[op]
    return lambda doc: any(_num(v) is not None and fn(_num(v)) for v in _vals(doc, field))


def _word_pred(word: str) -> Pred:
    rx = _wild(f"*{word}*")
    return lambda doc: any(rx.fullmatch(str(v)) for k, v in doc.items() if not k.startswith("__"))


class _Parser:
    """Splunk precedence: NOT > OR > AND (AND implied by adjacency)."""

    def __init__(self, toks: list[_Tok]):
        self.toks, self.i = toks, 0

    def peek(self) -> _Tok | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> _Tok:
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def parse(self) -> Pred:
        pred = self._and()
        if self.peek() is not None:
            raise Unsupported(f"unexpected {self.peek().kind}")
        return pred

    def _and(self) -> Pred:
        parts = [self._or()]
        while self.peek() is not None and self.peek().kind != "RP":
            if self.peek().kind == "AND":
                self.take()
            parts.append(self._or())
        return parts[0] if len(parts) == 1 else (lambda doc: all(p(doc) for p in parts))

    def _or(self) -> Pred:
        parts = [self._not()]
        while self.peek() is not None and self.peek().kind == "OR":
            self.take()
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else (lambda doc: any(p(doc) for p in parts))

    def _not(self) -> Pred:
        tok = self.peek()
        if tok is not None and tok.kind == "NOT":
            self.take()
            inner = self._not()
            return lambda doc: not inner(doc)
        return self._primary()

    def _primary(self) -> Pred:
        tok = self.take()
        if tok.kind == "LP":
            inner = self._and()
            if self.peek() is None or self.take().kind != "RP":
                raise Unsupported("unbalanced parentheses")
            return inner
        if tok.kind == "CMP":
            return _cmp_pred(tok.field, tok.op, tok.value)
        if tok.kind == "IN":
            preds = [_cmp_pred(tok.field, "=", v) for v in tok.value.split("\x00")]
            return lambda doc: any(p(doc) for p in preds)
        if tok.kind == "WORD":
            return _word_pred(tok.value)
        raise Unsupported(f"unexpected token {tok.kind}")


def compile_search(expr: str) -> Pred:
    expr = expr.strip()
    if expr.lower().startswith("search "):
        expr = expr[7:]
    if not expr:
        return lambda doc: True
    return _Parser(tokenize(expr)).parse()


_SPAN = re.compile(r"span=(\d+)([smhd])")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _command(segment: str) -> Callable[[list[Doc]], list[Doc]]:
    name, _, rest = segment.partition(" ")
    name = name.lower()
    rest = rest.strip()
    if name == "search":
        pred = compile_search(rest)
        return lambda docs: [d for d in docs if pred(d)]
    if name == "regex":
        m = re.match(r'([\w.]+)\s*(!?=)\s*("(?:[^"\\]|\\.)*")$', rest)
        if not m:
            raise Unsupported(f"regex syntax: {rest[:60]}")
        field, op, pattern = m.group(1), m.group(2), unquote(m.group(3))
        rx = re.compile(pattern)
        if op == "=":
            return lambda docs: [d for d in docs if any(rx.search(str(v)) for v in _vals(d, field))]
        return lambda docs: [d for d in docs if not any(rx.search(str(v)) for v in _vals(d, field))]
    if name == "rex":
        m = re.match(r'field=([\w.]+)\s+("(?:[^"\\]|\\.)*")$', rest)
        if not m:
            raise Unsupported(f"rex syntax: {rest[:60]}")
        field = m.group(1)
        pattern = unquote(m.group(2)).replace("(?<", "(?P<")
        rx = re.compile(pattern)

        def rex(docs: list[Doc]) -> list[Doc]:
            out = []
            for d in docs:
                for v in _vals(d, field):
                    hit = rx.search(str(v))
                    if hit:
                        d = {**d, **{k: val for k, val in hit.groupdict().items() if val is not None}}
                        break
                out.append(d)
            return out

        return rex
    if name == "eval":
        m = re.match(r'([\w.]+)=if\(isnotnull\(([\w.]+)\),\s*("[^"]*"),\s*("[^"]*")\)$', rest)
        if not m:
            raise Unsupported(f"eval expression: {rest[:60]}")
        target, src, yes, no = m.group(1), m.group(2), unquote(m.group(3)), unquote(m.group(4))
        return lambda docs: [{**d, target: yes if d.get(src) is not None else no} for d in docs]
    if name == "bin":
        m = re.match(r"_time\s+" + _SPAN.pattern + r"$", rest)
        if not m:
            raise Unsupported(f"bin syntax: {rest}")
        span = int(m.group(1)) * _UNITS[m.group(2)]
        return lambda docs: [{**d, "_time": math.floor(d["_time"] / span) * span} for d in docs]
    if name == "stats":
        m = re.match(r"(count|dc\(([\w.]+)\))(?:\s+as\s+(\w+))?\s+by\s+(.+)$", rest)
        if not m:
            raise Unsupported(f"stats syntax: {rest}")
        func, dc_field, alias, by = m.group(1), m.group(2), m.group(3), m.group(4)
        keys = by.replace(",", " ").split()
        out_name = alias or ("count" if func == "count" else f"dc({dc_field})")

        def stats(docs: list[Doc]) -> list[Doc]:
            groups: dict[tuple, list[Doc]] = {}
            for d in docs:
                if any(d.get(k) in (None, "") for k in keys):
                    continue
                groups.setdefault(tuple(str(d.get(k)) for k in keys), []).append(d)
            rows = []
            for key, members in groups.items():
                if func == "count":
                    value = len(members)
                else:
                    value = len({str(v) for m_ in members for v in _vals(m_, dc_field)})
                rows.append({**dict(zip(keys, key)), out_name: value, "__members": [m_.get("__idx") for m_ in members]})
            return rows

        return stats
    if name in ("table", "fields", "sort", "head"):
        return lambda docs: docs
    raise Unsupported(f"SPL command '{name}' is not modelled")


def compile_query(query: str) -> Callable[[list[Doc]], list[Doc]]:
    segments = _split_pipes(query.strip())
    if not segments:
        raise Unsupported("empty query")
    first = compile_search(segments[0])
    steps = [_command(seg) for seg in segments[1:]]

    def run(docs: list[Doc]) -> list[Doc]:
        current = [d for d in docs if first(d)]
        for step in steps:
            current = step(current)
        return current

    return run
