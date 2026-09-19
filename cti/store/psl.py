"""Registered-domain extraction, from the Public Suffix List.

## Why a real list and not a heuristic

`dns.apex` is the selector that expresses a *registration* link - the thing
that tied three malware families together in the SilkParasite reporting,
where the connection was "shared registration of hoster-kg.com, not a shared
server". It only means that if the apex is genuinely the registered domain.

The first version of this took the last two labels. Running it over this
repo's own data immediately produced `workers.dev` (Cloudflare Workers, which
hands out subdomains to anyone) and `edu.hk` as four-indicator and
two-indicator "registration links". Both are public suffixes: two names under
them share a registrar's product, not an owner. A hand-written list of
exceptions was never going to be right - there are 10,000 such rules.

So the list is vendored as data, the same way the ATT&CK corpus is, and
refreshed by a script rather than guessed at.
"""
from __future__ import annotations

import functools
from pathlib import Path

_LIST_PATH = Path(__file__).with_name("data") / "public_suffix_list.dat"


@functools.lru_cache(maxsize=1)
def _rules() -> tuple[frozenset[str], frozenset[str]]:
    """(normal rules, exception rules). Wildcards are stored as written."""
    normal: set[str] = set()
    exceptions: set[str] = set()
    try:
        text = _LIST_PATH.read_text(encoding="utf-8")
    except OSError:
        return frozenset(), frozenset()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("!"):
            exceptions.add(line[1:].lower())
        else:
            normal.add(line.lower())
    return frozenset(normal), frozenset(exceptions)


def available() -> bool:
    return bool(_rules()[0])


def public_suffix(host: str) -> str | None:
    """The public suffix of a hostname, per PSL matching rules."""
    normal, exceptions = _rules()
    if not normal:
        return None
    labels = [p for p in host.lower().rstrip(".").split(".") if p]
    if not labels:
        return None

    # An exception rule wins outright and shortens the suffix by one label.
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exceptions:
            return ".".join(labels[i + 1:])

    # Otherwise the longest matching rule wins; a wildcard matches one label.
    best = None
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        wildcard = ".".join(["*"] + labels[i + 1:]) if i + 1 <= len(labels) else None
        if candidate in normal or (wildcard and wildcard in normal):
            best = candidate
            break
    if best is None:
        best = labels[-1]        # unknown TLD: treat the last label as the suffix
    return best


def registered_domain(host: str) -> str | None:
    """The registered domain (public suffix plus one label), or None.

    None when the host IS a public suffix, or is only one label longer than
    nothing useful - in both cases there is no registration to link on.
    Returning None is deliberate: a wrong apex would invent a link, which is
    worse than missing one.
    """
    suffix = public_suffix(host)
    if suffix is None:
        return None
    labels = [p for p in host.lower().rstrip(".").split(".") if p]
    suffix_labels = suffix.split(".")
    if len(labels) <= len(suffix_labels):
        return None              # the host is itself a public suffix
    return ".".join(labels[-(len(suffix_labels) + 1):])


def is_public_suffix(host: str) -> bool:
    return public_suffix(host) == host.lower().rstrip(".")


def apex_for_selector(host: str) -> str | None:
    """The apex to record as a `dns.apex` selector, or None to record nothing.

    Nothing is recorded when the host is already the registered domain: an
    apex linking only to itself is not a link, and recording it would make
    every tracked domain share a selector with nobody.
    """
    apex = registered_domain(host)
    if apex is None:
        return None
    if apex == host.lower().rstrip("."):
        return None
    return apex
