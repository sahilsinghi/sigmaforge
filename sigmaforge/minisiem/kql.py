"""Kusto (KQL) evaluator for the subset pySigma's Kusto backend emits.

Kusto semantics that matter here:

* ``contains`` / ``startswith`` / ``endswith`` / ``has`` / ``=~`` / ``in~``
  are case-insensitive; ``==``, ``in`` and the ``_cs`` variants are not
* there are **no wildcards** in these operators: ``endswith "\\Run*"``
  looks for a literal asterisk
* ``matches regex`` is an unanchored, case-sensitive RE2 search
* a null or missing column makes string predicates false

A query is ``Table | where <expr> [| where <expr> ...]``; each event is
first routed to its Defender XDR table by ``sigmaforge.shapes.to_xdr``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Callable

from sigmaforge.minisiem import Unsupported

Row = dict[str, Any]
Pred = Callable[[Row], bool]

_STRING_OPS = [
    "!contains_cs", "contains_cs", "!contains", "contains",
    "!startswith_cs", "startswith_cs", "!startswith", "startswith",
    "!endswith_cs", "endswith_cs", "!endswith", "endswith",
    "!has_cs", "has_cs", "!has", "has_any", "has_all", "has",
    "matches regex", "!in~", "in~", "!in", "in",
    "==", "!=", "=~", "!~", ">=", "<=", ">", "<",
]


@dataclass
class _Tok:
    kind: str  # LP RP COMMA AND OR NOT STR NUM IDENT OP
    value: Any = None


def _read_string(text: str, i: int) -> tuple[str, int]:
    verbatim = text[i] == "@"
    if verbatim:
        i += 1
    quote = text[i]
    j = i + 1
    out = []
    while j < len(text):
        ch = text[j]
        if verbatim:
            if ch == quote:
                if j + 1 < len(text) and text[j + 1] == quote:
                    out.append(quote)
                    j += 2
                    continue
                return "".join(out), j + 1
            out.append(ch)
            j += 1
            continue
        if ch == "\\" and j + 1 < len(text):
            nxt = text[j + 1]
            out.append({"n": "\n", "t": "\t", "r": "\r"}.get(nxt, nxt))
            j += 2
            continue
        if ch == quote:
            return "".join(out), j + 1
        out.append(ch)
        j += 1
    raise Unsupported("unterminated string literal")


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
        if ch == ",":
            toks.append(_Tok("COMMA"))
            i += 1
            continue
        if ch in "\"'" or (ch == "@" and i + 1 < len(expr) and expr[i + 1] in "\"'"):
            value, i = _read_string(expr, i)
            toks.append(_Tok("STR", value))
            continue
        matched = False
        for op in _STRING_OPS:
            end = i + len(op)
            if expr[i:end].lower() == op and (not op[-1].isalpha() or end >= len(expr) or not (expr[end].isalnum() or expr[end] == "_")):
                if op[0].isalpha() and i > 0 and (expr[i - 1].isalnum() or expr[i - 1] == "_"):
                    continue
                toks.append(_Tok("OP", op))
                i = end
                matched = True
                break
        if matched:
            continue
        m = re.match(r"-?\d+(\.\d+)?", expr[i:])
        if m and (i == 0 or not expr[i - 1].isalnum()):
            toks.append(_Tok("NUM", float(m.group(0))))
            i += len(m.group(0))
            continue
        m = re.match(r"[A-Za-z_][\w.]*", expr[i:])
        if m:
            word = m.group(0)
            low = word.lower()
            if low in ("and", "or"):
                toks.append(_Tok(low.upper()))
            elif low == "not":
                toks.append(_Tok("NOT"))
            else:
                toks.append(_Tok("IDENT", word))
            i += len(word)
            continue
        raise Unsupported(f"unexpected character {ch!r} in KQL")
    return toks


def _col(row: Row, name: str) -> Any:
    return row.get(name)


def _s(v: Any) -> str:
    return "" if v is None else str(v)


def _has(hay: str, needle: str, cs: bool) -> bool:
    if not cs:
        hay, needle = hay.lower(), needle.lower()
    if not needle:
        return False
    pattern = r"(?<![0-9A-Za-z_])" + re.escape(needle) + r"(?![0-9A-Za-z_])"
    return re.search(pattern, hay) is not None


def _binary(column: str, op: str, rhs: Any) -> Pred:
    neg = op.startswith("!") and op not in ("!=",)
    base = op[1:] if neg else op
    if base in ("in", "in~"):
        items = rhs if isinstance(rhs, list) else [rhs]
        if base == "in~":
            lowered = {_s(x).lower() for x in items}
            fn = lambda v: v is not None and _s(v).lower() in lowered  # noqa: E731
        else:
            exact = {_s(x) for x in items}
            fn = lambda v: v is not None and _s(v) in exact  # noqa: E731
    elif base in ("has_any", "has_all"):
        items = rhs if isinstance(rhs, list) else [rhs]
        agg = any if base == "has_any" else all
        fn = lambda v: v is not None and agg(_has(_s(v), _s(x), False) for x in items)  # noqa: E731
    elif base == "matches regex":
        rx = re.compile(_s(rhs))
        fn = lambda v: v is not None and rx.search(_s(v)) is not None  # noqa: E731
    elif base in (">", "<", ">=", "<="):
        target = float(rhs)
        cmp = {">": float.__gt__, "<": float.__lt__, ">=": float.__ge__, "<=": float.__le__}[base]

        def fn(v: Any) -> bool:
            try:
                return v is not None and cmp(float(v), target)
            except (TypeError, ValueError):
                return False
    else:
        needle = _s(rhs)
        cs = base.endswith("_cs") or base in ("==", "!=")
        kind = base.replace("_cs", "")

        def norm(x: str) -> str:
            return x if cs else x.lower()

        n = norm(needle)
        if kind in ("==", "=~"):
            fn = lambda v: v is not None and norm(_s(v)) == n  # noqa: E731
        elif kind in ("!=", "!~"):
            fn = lambda v: v is not None and norm(_s(v)) != n  # noqa: E731
        elif kind == "contains":
            fn = lambda v: v is not None and n in norm(_s(v))  # noqa: E731
        elif kind == "startswith":
            fn = lambda v: v is not None and norm(_s(v)).startswith(n)  # noqa: E731
        elif kind == "endswith":
            fn = lambda v: v is not None and norm(_s(v)).endswith(n)  # noqa: E731
        elif kind == "has":
            fn = lambda v: v is not None and _has(_s(v), needle, cs)  # noqa: E731
        else:
            raise Unsupported(f"KQL operator {op}")
    if neg:
        return lambda row: not fn(_col(row, column))
    return lambda row: fn(_col(row, column))


class _Parser:
    def __init__(self, toks: list[_Tok]):
        self.toks, self.i = toks, 0

    def peek(self, offset: int = 0) -> _Tok | None:
        j = self.i + offset
        return self.toks[j] if j < len(self.toks) else None

    def take(self, kind: str | None = None) -> _Tok:
        tok = self.toks[self.i]
        if kind and tok.kind != kind:
            raise Unsupported(f"expected {kind}, got {tok.kind}")
        self.i += 1
        return tok

    def parse(self) -> Pred:
        pred = self._or()
        if self.peek() is not None:
            raise Unsupported(f"trailing tokens in KQL: {self.peek().kind}")
        return pred

    def _or(self) -> Pred:
        parts = [self._and()]
        while self.peek() is not None and self.peek().kind == "OR":
            self.take()
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else (lambda r: any(p(r) for p in parts))

    def _and(self) -> Pred:
        parts = [self._unary()]
        while self.peek() is not None and self.peek().kind == "AND":
            self.take()
            parts.append(self._unary())
        return parts[0] if len(parts) == 1 else (lambda r: all(p(r) for p in parts))

    def _unary(self) -> Pred:
        tok = self.peek()
        if tok.kind == "NOT":
            self.take()
            self.take("LP")
            inner = self._or()
            self.take("RP")
            return lambda r: not inner(r)
        if tok.kind == "LP":
            self.take()
            inner = self._or()
            self.take("RP")
            return inner
        if tok.kind == "IDENT" and self.peek(1) is not None and self.peek(1).kind == "LP":
            return self._function()
        if tok.kind == "IDENT":
            column = self.take().value
            op = self.take("OP").value
            return _binary(column, op, self._value(op))
        raise Unsupported(f"unexpected token {tok.kind}")

    def _value(self, op: str) -> Any:
        tok = self.peek()
        if tok.kind == "LP":
            self.take()
            items = []
            while self.peek().kind != "RP":
                if self.peek().kind == "COMMA":
                    self.take()
                    continue
                items.append(self.take().value)
            self.take("RP")
            return items
        if tok.kind in ("STR", "NUM"):
            return self.take().value
        raise Unsupported(f"unsupported value after {op}")

    def _function(self) -> Pred:
        name = self.take("IDENT").value.lower()
        self.take("LP")
        args = []
        while self.peek().kind != "RP":
            if self.peek().kind == "COMMA":
                self.take()
                continue
            args.append(self.take())
        self.take("RP")
        if name in ("isempty", "isnull") and len(args) == 1:
            col = args[0].value
            return lambda r: _s(r.get(col)) == ""
        if name in ("isnotempty", "isnotnull") and len(args) == 1:
            col = args[0].value
            return lambda r: _s(r.get(col)) != ""
        if name == "ipv4_is_in_range" and len(args) == 2:
            col, net = args[0].value, ipaddress.ip_network(args[1].value, strict=False)

            def in_range(r: Row) -> bool:
                try:
                    return ipaddress.ip_address(_s(r.get(col))) in net
                except ValueError:
                    return False

            return in_range
        raise Unsupported(f"KQL function {name}()")


def compile_query(query: str) -> tuple[str, Pred]:
    """Return (table, predicate) for ``Table | where ... | where ...``."""
    segments = [s.strip() for s in _split_pipes(query)]
    if not segments or not re.fullmatch(r"[A-Za-z_]\w*", segments[0]):
        raise Unsupported("query must start with a table name")
    table = segments[0]
    preds = []
    for seg in segments[1:]:
        if not seg.lower().startswith("where "):
            raise Unsupported(f"KQL operator '{seg.split()[0]}' is not modelled")
        preds.append(_Parser(tokenize(seg[6:])).parse())
    return table, (lambda r: all(p(r) for p in preds))


def _split_pipes(query: str) -> list[str]:
    parts, buf, quote, i = [], [], None, 0
    while i < len(query):
        ch = query[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(query):
                buf.append(query[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf.append(ch)
        elif ch == "|":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [p for p in parts if p.strip()]
