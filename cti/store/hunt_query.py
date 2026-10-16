"""A key:value hunt language over the selector store, Censys / Hunt.io style.

    tls.jarm:27d40d40d00040d1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c AND NOT net.asn:13335
    tls.default_subject:* AND net.port:8443 during:[2026-03-01,2026-04-30]
    cluster:jadeprox role:candidate band:probable
    indicator:~"\\.top$" AND tls.issuer:~"^CN=localhost"
    changed:tls.cert_sha256 since:7d

## Terms

`key:value`, where key is

* a selector type (`tls.jarm`, `net.historical_ip`, `http.body_sha256`, ...;
  see `selectors.TYPES`). The value is normalized the way the store
  normalizes it, so case and DN order do not matter. `*` matches any value;
  `~regex` matches by regular expression against the stored form.
* `net.port` - a single port inside any `net.port_set` or
  `net.passive_port_set`.
* `indicator` - the indicator value itself (exact, or `~regex`).
* `type` - the indicator's kind: domain, ipv4, ipv6, url, hash, cert...
* `cluster`, `role` (seed / accepted / candidate / rejected), `band`
  (strong / probable / weak / noise - that band or better) - membership.
* `vantage` - observed from that vantage (probe, win116, zeek...).
* `changed` - a selector type (a span of it opened since `since:`, on an
  indicator that already held one before) or a change-detector field
  (`cert_hash`, `resolved_ip`, `ja4s`, ... from attribute_changes and
  service_changes). `since:7d` or `since:2026-10-01`; default 7 days.

Terms combine with AND (also implicit, by juxtaposition), OR, NOT and
parentheses. NOT binds tightest, then AND, then OR.

## Time

`seen:>DATE`, `seen:<DATE` and `during:[A,B]` are not filters of their own:
they set the window every selector term must have been live in. A span
counts when it overlaps the window, so "who carried this JARM in March" is
`tls.jarm:... during:[2026-03-01,2026-03-31]`. On their own, they select
anything observed in the window.

Matching is always against what the store observed, from any source: a hit
says "this indicator carried this value", and `pairs` says how much that is
worth.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import duckdb

from ..util import rows
from .selectors import TYPES, normalize
from .spans import to_ts

BANDS = ("noise", "weak", "probable", "strong")
ROLES = ("seed", "accepted", "candidate", "rejected")
DEFAULT_SINCE = timedelta(days=7)
DEFAULT_LIMIT = 200

_META_KEYS = {"indicator", "type", "cluster", "role", "band", "vantage", "changed"}
_TIME_KEYS = {"seen", "during", "since"}
_VIRTUAL_SELECTORS = {"net.port"}

# Every indicator the store knows, with a kind. `entities` covers anything
# with a membership; the rest are typed from their shape.
_UNIVERSE = """
    SELECT u.v AS indicator_value,
           coalesce(e.type,
                    CASE WHEN regexp_matches(u.v, '^[0-9]{1,3}(\\.[0-9]{1,3}){3}$') THEN 'ipv4'
                         WHEN regexp_matches(u.v, '^[0-9a-f:]+$') AND u.v LIKE '%:%' THEN 'ipv6'
                         WHEN u.v LIKE '%://%' THEN 'url'
                         WHEN u.v LIKE 'cert-sha256:%' THEN 'cert'
                         ELSE 'domain' END) AS kind
    FROM (SELECT indicator_value AS v FROM selector_spans
          UNION SELECT value FROM entities
          UNION SELECT target FROM service_snapshots) u
    LEFT JOIN entities e ON e.value = u.v
"""


class QueryError(ValueError):
    """The query does not parse, or names a key nothing can answer."""


# --------------------------------------------------------------------------- #
# Lexing and parsing
# --------------------------------------------------------------------------- #

_TOKEN = re.compile(r"""
    \s*(?:
      (?P<lparen>\()
    | (?P<rparen>\))
    | (?P<term>[A-Za-z][\w.\-]*:
         (?: ~?"(?:[^"\\]|\\.)*"      # quoted value, optionally a regex
           | \[[^\]]*\]               # [a,b] window
           | [^\s()]+ ))              # bare value
    | (?P<word>[A-Za-z]+)
    )""", re.X)


@dataclass
class Term:
    key: str
    value: str
    regex: bool = False

    def describe(self) -> str:
        return f"{self.key}:{'~' if self.regex else ''}{self.value}"


@dataclass
class Node:
    op: str                      # "and" | "or" | "not" | "term"
    children: list["Node"] = field(default_factory=list)
    term: Term | None = None


def _unquote(raw: str) -> tuple[str, bool]:
    regex = raw.startswith("~")
    if regex:
        raw = raw[1:]
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        raw = re.sub(r'\\(.)', r"\1", raw[1:-1])
    return raw, regex


def tokenize(text: str) -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    pos = 0
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise QueryError(f"cannot read the query at: {text[pos:pos + 30]!r}")
        pos = m.end()
        if m.group("lparen"):
            out.append(("(", None))
        elif m.group("rparen"):
            out.append((")", None))
        elif m.group("term"):
            key, _, raw = m.group("term").partition(":")
            value, regex = _unquote(raw)
            out.append(("term", Term(key.lower(), value, regex)))
        else:
            word = m.group("word").upper()
            if word not in ("AND", "OR", "NOT"):
                raise QueryError(f"{m.group('word')!r} is not a key:value term or AND/OR/NOT")
            out.append((word, None))
    return out


class _Parser:
    def __init__(self, tokens: list[tuple[str, Any]]):
        self.tokens, self.i = tokens, 0

    def peek(self) -> str | None:
        return self.tokens[self.i][0] if self.i < len(self.tokens) else None

    def take(self) -> tuple[str, Any]:
        token = self.tokens[self.i]
        self.i += 1
        return token

    def parse(self) -> Node | None:
        if not self.tokens:
            return None
        node = self.or_expr()
        if self.peek() is not None:
            raise QueryError(f"unexpected {self.peek()!r}")
        return node

    def or_expr(self) -> Node:
        children = [self.and_expr()]
        while self.peek() == "OR":
            self.take()
            children.append(self.and_expr())
        return children[0] if len(children) == 1 else Node("or", children)

    def and_expr(self) -> Node:
        children = [self.not_expr()]
        while self.peek() in ("AND", "NOT", "term", "("):
            if self.peek() == "AND":
                self.take()
            children.append(self.not_expr())
        return children[0] if len(children) == 1 else Node("and", children)

    def not_expr(self) -> Node:
        if self.peek() == "NOT":
            self.take()
            return Node("not", [self.not_expr()])
        return self.atom()

    def atom(self) -> Node:
        kind = self.peek()
        if kind == "(":
            self.take()
            node = self.or_expr()
            if self.peek() != ")":
                raise QueryError("missing ')'")
            self.take()
            return node
        if kind == "term":
            return Node("term", term=self.take()[1])
        raise QueryError(f"expected a term, got {kind!r}")


# --------------------------------------------------------------------------- #
# Time modifiers
# --------------------------------------------------------------------------- #

@dataclass
class Window:
    lo: datetime | None = None
    hi: datetime | None = None
    since: datetime | None = None

    @property
    def active(self) -> bool:
        return self.lo is not None or self.hi is not None


def _when(text: str, now: datetime) -> datetime:
    rel = re.fullmatch(r"(\d+)([dhw])", text.strip())
    if rel:
        n, unit = int(rel.group(1)), rel.group(2)
        return now - {"d": timedelta(days=n), "h": timedelta(hours=n),
                      "w": timedelta(weeks=n)}[unit]
    dt = to_ts(text.strip())
    if dt is None:
        raise QueryError(f"not a date or a relative age like 7d: {text!r}")
    return dt


def _extract_time(node: Node | None, window: Window, now: datetime) -> Node | None:
    """Pull seen/during/since terms out of the tree into `window`. They must
    sit at the top level (or inside top-level ANDs): a window under an OR or
    a NOT would mean something nobody intends."""
    if node is None:
        return None
    if node.op == "term" and node.term.key in _TIME_KEYS:
        t = node.term
        if t.key == "since":
            window.since = _when(t.value, now)
        elif t.key == "during":
            m = re.fullmatch(r"\[\s*([^,\]]+)\s*,\s*([^,\]]+)\s*\]", t.value)
            if not m:
                raise QueryError("during: takes [start,end]")
            window.lo, window.hi = _when(m.group(1), now), _when(m.group(2), now)
        else:
            m = re.fullmatch(r"(>=|<=|>|<)?(.+)", t.value)
            op, when = m.group(1) or ">", _when(m.group(2), now)
            if op.startswith(">"):
                window.lo = when
            else:
                window.hi = when
        return None
    if node.op == "and":
        kept = [c for c in (_extract_time(c, window, now) for c in node.children) if c]
        if not kept:
            return None
        return kept[0] if len(kept) == 1 else Node("and", kept)
    if _contains_time(node):
        raise QueryError("seen:/during:/since: apply to the whole query - "
                         "use them at the top level, not under OR or NOT")
    return node


def _contains_time(node: Node) -> bool:
    if node.op == "term":
        return node.term.key in _TIME_KEYS
    return any(_contains_time(c) for c in node.children)


# --------------------------------------------------------------------------- #
# Compiling
# --------------------------------------------------------------------------- #

def _window_sql(window: Window, params: list[Any]) -> str:
    clauses = []
    if window.lo is not None:
        clauses.append("end_at >= ?")
        params.append(window.lo)
    if window.hi is not None:
        clauses.append("start_at <= ?")
        params.append(window.hi)
    return (" AND " + " AND ".join(clauses)) if clauses else ""


def _value_sql(column: str, term: Term, params: list[Any], *, selector_type: str | None
               ) -> str:
    if term.value == "*" and not term.regex:
        return "TRUE"
    if term.regex:
        try:
            re.compile(term.value)
        except re.error as e:
            raise QueryError(f"bad regex in {term.describe()}: {e}") from e
        params.append(term.value)
        return f"regexp_matches({column}, ?)"
    value = normalize(selector_type, term.value) if selector_type else term.value.strip()
    if value is None:
        raise QueryError(f"{term.describe()} normalizes to nothing - nothing can carry it")
    params.append(value)
    return f"{column} = ?"


def _selector_cond(term: Term, window: Window, params: list[Any]) -> str:
    """The WHERE clause over selector_spans for one selector term, window
    included. Parameters are appended in the order the clause uses them."""
    if term.key == "net.port":
        if not term.value.isdigit():
            raise QueryError("net.port takes a port number")
        params.append(term.value)
        cond = ("selector_type IN ('net.port_set', 'net.passive_port_set') "
                "AND list_contains(string_split(selector_value, ','), ?)")
    else:
        params.append(term.key)
        cond = "selector_type = ? AND " + _value_sql("selector_value", term, params,
                                                     selector_type=term.key)
    return cond + _window_sql(window, params)


def _term_sql(term: Term, window: Window, params: list[Any], now: datetime) -> str:
    key = term.key
    if key in TYPES or key in _VIRTUAL_SELECTORS:
        return ("SELECT DISTINCT indicator_value FROM selector_spans WHERE "
                + _selector_cond(term, window, params))
    if key == "indicator":
        value = _value_sql("indicator_value", term, params, selector_type=None)
        if not term.regex and term.value != "*":
            params[-1] = params[-1].lower().rstrip(".")
        return f"SELECT indicator_value FROM ({_UNIVERSE}) WHERE {value}"
    if key == "type":
        params.append(term.value.lower())
        return f"SELECT indicator_value FROM ({_UNIVERSE}) WHERE kind = ?"
    if key == "cluster":
        params.append(term.value.strip().lower().replace(" ", "-"))
        return "SELECT entity AS indicator_value FROM memberships WHERE cluster = ?"
    if key == "role":
        if term.value not in ROLES:
            raise QueryError(f"role is one of {', '.join(ROLES)}")
        params.append(term.value)
        return "SELECT entity AS indicator_value FROM memberships WHERE role = ?"
    if key == "band":
        if term.value not in BANDS:
            raise QueryError(f"band is one of {', '.join(BANDS)}")
        allowed = BANDS[BANDS.index(term.value):]
        params.extend(allowed)
        return (f"SELECT entity AS indicator_value FROM memberships WHERE band IN "
                f"({', '.join('?' for _ in allowed)})")
    if key == "vantage":
        params.extend([term.value, term.value])
        return ("SELECT indicator_value FROM selector_spans WHERE vantage = ? "
                "UNION SELECT target AS indicator_value FROM service_snapshots WHERE vantage = ?")
    if key == "changed":
        since = window.since or (now - DEFAULT_SINCE)
        if term.value in TYPES:
            params.extend([term.value, since, since])
            return ("SELECT DISTINCT n.indicator_value FROM selector_spans n "
                    "WHERE n.selector_type = ? AND n.start_at >= ? AND EXISTS ("
                    "SELECT 1 FROM selector_spans o WHERE o.indicator_value = n.indicator_value "
                    "AND o.selector_type = n.selector_type AND o.start_at < ? "
                    "AND (o.selector_value <> n.selector_value OR o.end_at < n.start_at))")
        params.extend([term.value, since, term.value, since])
        return ("SELECT indicator_value FROM attribute_changes "
                "WHERE attribute = ? AND detected_at >= ? "
                "UNION SELECT target AS indicator_value FROM service_changes "
                "WHERE field = ? AND detected_at >= ?")
    raise QueryError(f"unknown key {key!r} - a selector type, net.port, or one of "
                     f"{', '.join(sorted(_META_KEYS | _TIME_KEYS))}")


def _node_sql(node: Node, window: Window, params: list[Any], now: datetime) -> str:
    if node.op == "term":
        return _term_sql(node.term, window, params, now)
    if node.op == "not":
        inner = _node_sql(node.children[0], window, params, now)
        return f"SELECT indicator_value FROM ({_UNIVERSE}) EXCEPT ({inner})"
    joiner = " INTERSECT " if node.op == "and" else " UNION "
    return joiner.join(f"({_node_sql(c, window, params, now)})" for c in node.children)


@dataclass
class Compiled:
    sql: str
    params: list[Any]
    window: Window
    terms: list[Term]


def _terms(node: Node | None, negated: bool = False) -> list[Term]:
    """The positive selector terms, for showing what each hit matched on."""
    if node is None:
        return []
    if node.op == "term":
        return [] if negated else [node.term]
    if node.op == "not":
        return _terms(node.children[0], not negated)
    return [t for c in node.children for t in _terms(c, negated)]


def compile_query(text: str, *, now: datetime | None = None) -> Compiled:
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    window = Window()
    tree = _extract_time(_Parser(tokenize(text)).parse(), window, now)
    params: list[Any] = []
    if tree is None:
        if not window.active:
            raise QueryError("an empty query - give at least one key:value term")
        body = "SELECT DISTINCT indicator_value FROM selector_spans WHERE TRUE" + \
            _window_sql(window, params)
    else:
        body = _node_sql(tree, window, params, now)
    return Compiled(f"SELECT DISTINCT indicator_value FROM ({body}) q "
                    f"WHERE indicator_value IS NOT NULL", params, window, _terms(tree))


# --------------------------------------------------------------------------- #
# Running
# --------------------------------------------------------------------------- #

def run(con: duckdb.DuckDBPyConnection, text: str, *, limit: int = DEFAULT_LIMIT,
        now: datetime | None = None) -> dict[str, Any]:
    """Run a query. Each hit carries its memberships and, for every selector
    term in the query, the spans on which it matched."""
    compiled = compile_query(text, now=now)
    hits = [r[0] for r in con.execute(compiled.sql + " ORDER BY 1", compiled.params).fetchall()]
    total = len(hits)
    hits = hits[:limit]

    selector_terms = [t for t in compiled.terms if t.key in TYPES or t.key == "net.port"]
    results = []
    for indicator in hits:
        matched = []
        for term in selector_terms:
            params: list[Any] = [indicator]
            cond = _selector_cond(term, compiled.window, params)
            for row in rows(con, "SELECT selector_type, selector_value, source, vantage, "
                                 "start_at, end_at, observations FROM selector_spans "
                                 f"WHERE indicator_value = ? AND {cond} ORDER BY start_at",
                            params):
                matched.append({"type": row["selector_type"], "value": row["selector_value"],
                                "from": str(row["start_at"]), "to": str(row["end_at"]),
                                "source": row["source"], "vantage": row["vantage"],
                                "observations": row["observations"]})
        member_rows = rows(con, "SELECT cluster, role, band, score FROM memberships "
                                "WHERE entity = ? ORDER BY cluster", [indicator])
        results.append({"indicator": indicator, "memberships": member_rows,
                        "matched": matched})
    return {"query": text, "total": total, "returned": len(results),
            "window": {"from": str(compiled.window.lo) if compiled.window.lo else None,
                       "to": str(compiled.window.hi) if compiled.window.hi else None},
            "results": results}


def explain(text: str) -> dict[str, Any]:
    compiled = compile_query(text)
    return {"sql": compiled.sql, "params": [str(p) for p in compiled.params]}


# --------------------------------------------------------------------------- #
# Pairs: what an indicator shares, with whom, when, and what it is worth
# --------------------------------------------------------------------------- #

def pairs(con: duckdb.DuckDBPyConnection, a: str, b: str | None = None, *,
          limit: int = 50) -> dict[str, Any]:
    """With `b`: every key:value a and b share, the gap between the spans in
    which each held it, and the relatedness that adds up to. Without: every
    indicator a shares anything with, scored pairwise and ranked - "what is
    this most like", across every cluster and every candidate."""
    from . import entities
    from . import relatedness as R

    a = entities.canonical(a)
    if b is not None:
        result = R.pairs_between(con, a, entities.canonical(b)).to_dict()
        return {"indicator": a, "other": entities.canonical(b), **result}

    shared = R.shared_with_anything(con, a, limit=500)
    others: list[str] = []
    for row in shared:
        for holder in (row["holders"] or "").split(", "):
            if holder and holder not in others:
                others.append(holder)
    scored = []
    for other in others[: max(limit * 4, limit)]:
        result = R.score_against(con, a, [other])
        if not result.pairs:
            continue
        entry = result.to_dict()
        entry["other"] = other
        entry["memberships"] = rows(con, "SELECT cluster, role, band FROM memberships "
                                         "WHERE entity = ? ORDER BY cluster", [other])
        entry["evidence"] = entry["evidence"][:6]
        scored.append(entry)
    scored.sort(key=lambda e: (-e["score"], e["other"]))
    return {"indicator": a, "shared_values": len(shared), "related": scored[:limit]}
