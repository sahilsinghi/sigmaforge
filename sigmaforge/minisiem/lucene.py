"""Lucene ``query_string`` evaluator with OpenSearch keyword semantics.

Semantics verified against OpenSearch 2.19 with the index template from
``sigmaforge.opensearch``:

* keyword fields match case-sensitively; wildcards and regexes must match
  the *whole* value (regexes are implicitly anchored)
* ``<field>.caseless`` multi-fields use a lowercase normalizer, which is
  applied to the stored value and to the query term
* a backslash escapes the next character; inside regexes ``\\d \\w \\s``
  (and their negations) are character classes, while other escapes such as
  ``\\b`` are the literal letter - there are no word boundaries
* ``^``, ``$``, inline flags ``(?i)`` and lookarounds are not regex syntax
  in Lucene: such patterns silently match nothing
* ``NOT x`` matches documents where x does not match, including documents
  that lack the field
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from sigmaforge.minisiem import Unsupported

Doc = dict[str, Any]
Pred = Callable[[Doc], bool]

_REGEX_OPERATORS = set("@&~#<>")
_SHORTHAND = {
    "d": "[0-9]", "D": "[^0-9]", "w": "[A-Za-z0-9_]", "W": "[^A-Za-z0-9_]",
    "s": "[ \\t\\n\\r\\f\\v]", "S": "[^ \\t\\n\\r\\f\\v]",
}


@dataclass
class _Tok:
    kind: str  # LP RP AND OR NOT TERM
    text: str = ""


def _scan_until(text: str, i: int, stop: Callable[[str], bool]) -> tuple[str, int]:
    out = []
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            out.append(text[i:i + 2])
            i += 2
            continue
        if stop(ch):
            break
        out.append(ch)
        i += 1
    return "".join(out), i


def _read_delimited(text: str, i: int, delim: str) -> tuple[str, int]:
    """Read "..." or /.../ starting at text[i] == delim; returns raw inner text."""
    j = i + 1
    out = []
    while j < len(text):
        ch = text[j]
        if ch == "\\" and j + 1 < len(text):
            out.append(text[j:j + 2])
            j += 2
            continue
        if ch == delim:
            return "".join(out), j + 1
        out.append(ch)
        j += 1
    raise Unsupported(f"unterminated {delim} in query")


def tokenize(query: str) -> list[_Tok]:
    toks: list[_Tok] = []
    i = 0
    n = len(query)
    while i < n:
        ch = query[i]
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
        if ch in "\"/":
            raw, i = _read_delimited(query, i, ch)
            toks.append(_Tok("TERM", ch + raw + ch))
            continue
        # field:value, or a bare term
        word, j = _scan_until(query, i, lambda c: c.isspace() or c in "():")
        if j == i:
            raise Unsupported(f"cannot parse query at {query[i:i + 20]!r}")
        if j < n and query[j] == ":":
            field = word
            j += 1
            if j < n and query[j] == "(":
                toks.append(_Tok("FIELD", field))
                i = j
                continue
            if j < n and query[j] in "\"/":
                raw, k = _read_delimited(query, j, query[j])
                toks.append(_Tok("TERM", f"{field}:{query[j]}{raw}{query[j]}"))
                i = k
                continue
            value, k = _scan_until(query, j, lambda c: c.isspace() or c in "()")
            toks.append(_Tok("TERM", f"{field}:{value}"))
            i = k
            continue
        if word in ("AND", "OR", "NOT"):
            toks.append(_Tok(word))
        elif word in ("&&", "||"):
            toks.append(_Tok("AND" if word == "&&" else "OR"))
        else:
            toks.append(_Tok("TERM", word))
        i = j
    return toks


def _unescape(raw: str) -> str:
    return re.sub(r"\\(.)", r"\1", raw)


def _wildcard_regex(raw: str) -> re.Pattern[str] | None:
    """Translate an escaped query-string term into a regex if it has wildcards."""
    out = []
    wild = False
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            out.append(re.escape(raw[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
            wild = True
        elif ch == "?":
            out.append(".")
            wild = True
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile("".join(out), re.DOTALL) if wild else None


def lucene_regex_to_python(raw: str) -> re.Pattern[str]:
    out = []
    i = 0
    in_class = False
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt in _SHORTHAND:
                # Lucene 9 supports \d \D \s \S \w \W (ASCII classes)
                out.append(_SHORTHAND[nxt] if not in_class else _SHORTHAND[nxt][1:-1])
            elif in_class:
                out.append("\\" + nxt if not nxt.isalnum() else nxt)
            else:
                # any other escape is the literal character (\b is "b", not a word boundary)
                out.append(re.escape(nxt))
            i += 2
            continue
        if not in_class and ch == "(" and raw[i + 1:i + 2] == "?":
            raise Unsupported("Lucene regex has no inline flags or lookarounds; OpenSearch matches nothing")
        if not in_class and ch in _REGEX_OPERATORS:
            raise Unsupported(f"Lucene regex operator {ch!r} (ALL flags) is not modelled")
        if ch == "[" and not in_class:
            in_class = True
        elif ch == "]" and in_class:
            in_class = False
        elif not in_class and ch in "^$":
            out.append(re.escape(ch))
            i += 1
            continue
        out.append(ch)
        i += 1
    try:
        return re.compile("".join(out), re.DOTALL)
    except re.error as exc:
        raise Unsupported(f"regex not translatable: {exc}") from exc


def _values(doc: Doc, field: str) -> tuple[list[str], bool]:
    """Return (stringified values, caseless?) for a field reference."""
    caseless = field.endswith(".caseless")
    base = field[: -len(".caseless")] if caseless else field
    if base == "*":
        vals = [v for v in doc.values()]
    else:
        raw = doc.get(base)
        vals = raw if isinstance(raw, list) else ([] if raw is None else [raw])
    out = []
    for v in vals:
        if v is None:
            continue
        s = str(v).lower() if isinstance(v, bool) else str(v)
        out.append(s.lower() if caseless else s)
    return out, caseless


def _term_predicate(field: str, raw: str) -> Pred:
    if field == "_exists_":
        target = _unescape(raw)
        return lambda doc: doc.get(target) not in (None, "", [])
    if raw.startswith("/") and raw.endswith("/") and len(raw) >= 2:
        pattern = lucene_regex_to_python(raw[1:-1])

        def regex_match(doc: Doc) -> bool:
            vals, caseless = _values(doc, field)
            return any(pattern.fullmatch(v) for v in vals)

        return regex_match
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        phrase = _unescape(raw[1:-1])

        def phrase_match(doc: Doc) -> bool:
            vals, caseless = _values(doc, field)
            target = phrase.lower() if caseless else phrase
            return any(v == target for v in vals)

        return phrase_match
    regex = _wildcard_regex(raw)
    if regex is not None:
        def wildcard_match(doc: Doc) -> bool:
            vals, caseless = _values(doc, field)
            rx = regex if not caseless else re.compile(regex.pattern.lower(), re.DOTALL)
            return any(rx.fullmatch(v) for v in vals)

        if field.endswith(".caseless"):
            lowered = re.compile(regex.pattern.lower(), re.DOTALL)

            def wildcard_caseless(doc: Doc) -> bool:
                vals, _ = _values(doc, field)
                return any(lowered.fullmatch(v) for v in vals)

            return wildcard_caseless
        return wildcard_match
    literal = _unescape(raw)

    def exact(doc: Doc) -> bool:
        vals, caseless = _values(doc, field)
        target = literal.lower() if caseless else literal
        return any(v == target for v in vals)

    return exact


class _Parser:
    def __init__(self, toks: list[_Tok]):
        self.toks = toks
        self.i = 0

    def peek(self) -> _Tok | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> _Tok:
        tok = self.toks[self.i]
        self.i += 1
        return tok

    def parse(self, field_scope: str | None = None) -> Pred:
        pred = self._or(field_scope)
        if self.peek() is not None and self.peek().kind != "RP":
            raise Unsupported(f"unexpected token {self.peek().kind}")
        return pred

    def _or(self, scope: str | None) -> Pred:
        parts = [self._and(scope)]
        ops = []
        while True:
            tok = self.peek()
            if tok is None or tok.kind == "RP":
                break
            if tok.kind == "OR":
                self.take()
                ops.append("OR")
                parts.append(self._and(scope))
            elif tok.kind in ("TERM", "LP", "NOT", "FIELD"):
                # adjacent clauses: Lucene's default operator is OR
                ops.append("OR")
                parts.append(self._and(scope))
            else:
                raise Unsupported(f"unexpected token {tok.kind}")
        if len(parts) == 1:
            return parts[0]
        return lambda doc: any(p(doc) for p in parts)

    def _and(self, scope: str | None) -> Pred:
        parts = [self._unary(scope)]
        while self.peek() is not None and self.peek().kind == "AND":
            self.take()
            parts.append(self._unary(scope))
        if self.peek() is not None and self.peek().kind == "OR" and len(parts) > 1:
            raise Unsupported("AND and OR mixed without parentheses (Lucene does not use boolean precedence)")
        if len(parts) == 1:
            return parts[0]
        return lambda doc: all(p(doc) for p in parts)

    def _unary(self, scope: str | None) -> Pred:
        tok = self.take()
        if tok.kind == "NOT":
            inner = self._unary(scope)
            return lambda doc: not inner(doc)
        if tok.kind == "LP":
            inner = self._or(scope)
            if self.peek() is None or self.take().kind != "RP":
                raise Unsupported("unbalanced parentheses")
            return inner
        if tok.kind == "FIELD":
            if self.peek() is None or self.take().kind != "LP":
                raise Unsupported("expected ( after field:")
            inner = self._or(tok.text)
            if self.peek() is None or self.take().kind != "RP":
                raise Unsupported("unbalanced parentheses in field group")
            return inner
        if tok.kind == "TERM":
            text = tok.text
            if scope is not None:
                return _term_predicate(scope, text)
            if text[:1] in "\"/":
                return _term_predicate("*", text)
            field, sep, value = _split_field(text)
            if not sep:
                return _term_predicate("*", text)
            return _term_predicate(_unescape(field), value)
        raise Unsupported(f"unexpected token {tok.kind}")


def _split_field(text: str) -> tuple[str, str, str]:
    i = 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == ":":
            return text[:i], ":", text[i + 1:]
        i += 1
    return text, "", ""


def compile_query(query: str) -> Pred:
    toks = tokenize(query.strip())
    if not toks:
        raise Unsupported("empty query")
    parser = _Parser(toks)
    pred = parser.parse()
    if parser.peek() is not None:
        raise Unsupported("unbalanced parentheses")
    return pred
