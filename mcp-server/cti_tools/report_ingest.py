"""Fetch a threat report (URL or local file) and extract observables/TTPs
from it with plain regexes — no network SDKs, no NLP model, no external
API calls, consistent with the rest of this tool.

This is a heuristic best-effort extractor, not a CTI parsing engine.
Treat its output — especially `suggest_cluster_names` — as a starting
point for an agent (or analyst) to confirm, not as ground truth. It will
both miss things (PDFs are out of scope; obfuscated/imaged IOCs won't be
seen) and occasionally over-match (e.g. a version string that happens to
look like an IP). `core.ingest_report` refuses to guess a cluster name
when extraction is ambiguous rather than silently filing a report under
the wrong actor — see its docstring.
"""
from __future__ import annotations

import html
import ipaddress
import re
import urllib.request
from collections import Counter

USER_AGENT = "cti-agent-report-ingest/1.0 (+local analysis tool, no telemetry)"
FETCH_TIMEOUT = 20

# Deliberately curated, not exhaustive: generic TLDs plus ccTLDs/newer
# gTLDs that show up disproportionately often in malicious infrastructure
# reporting. A hostname whose TLD isn't in this set is dropped rather
# than risking false positives on arbitrary "word.word" text. Extend
# this list if your reports keep missing legitimate domains.
_TLDS = {
    "com", "net", "org", "info", "biz", "io", "co", "me", "us", "uk",
    "de", "fr", "nl", "ru", "su", "cn", "hk", "tw", "jp", "kr", "in",
    "br", "pl", "es", "it", "se", "no", "fi", "dk", "ch", "at", "be",
    "cc", "tv", "ws", "to", "cf", "ga", "gq", "ml", "tk", "top", "xyz",
    "site", "online", "club", "icu", "live", "shop", "store", "fun",
    "vip", "buzz", "space", "click", "link", "download", "stream",
    "work", "rest", "cyou", "monster", "bond", "cam", "pw", "sh",
    "app", "dev", "cloud", "host", "pro", "biz", "name", "email",
}

_HASH_PATTERNS = {
    "sha256": re.compile(r"\b[A-Fa-f0-9]{64}\b"),
    "sha1": re.compile(r"\b[A-Fa-f0-9]{40}\b"),
    "md5": re.compile(r"\b[A-Fa-f0-9]{32}\b"),
}
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>\)\]]+", re.IGNORECASE)
_DOMAIN_CANDIDATE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"([a-zA-Z]{2,24})\b"
)
_TTP_PATTERN = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")

# Naming conventions from the major vendor taxonomies. Best-effort:
# these catch the common cases, not every alias scheme in use.
_NAME_PATTERNS = [
    # Microsoft weather-themed actor names, e.g. "Volt Typhoon"
    re.compile(r"\b[A-Z][a-z]+\s+(?:Tempest|Typhoon|Blizzard|Sandstorm|Sleet|Storm|Flood|Hail|Dust)\b"),
    # CrowdStrike animal-themed adversary names, e.g. "Fancy Bear"
    re.compile(r"\b[A-Z][a-z]+\s+(?:Spider|Panda|Bear|Kitten|Jackal|Chollima|Buffalo|Tiger|Ocelot|Crane|Wolf|Fox)\b"),
    # Mandiant / Proofpoint / Secureworks numbered clusters
    re.compile(r"\b(?:APT|FIN|UNC|TA|GOLD|BRONZE|COPPER|TIN)[\s-]?\d{2,5}\b", re.IGNORECASE),
    # "<Name> ransomware/malware/loader/..." — malware family names
    re.compile(r"\b([A-Z][A-Za-z0-9]{2,20})(?=\s+(?:ransomware|malware|loader|backdoor|trojan|stealer|botnet|worm))\b"),
]

_DEFANG_SUBS = [
    (re.compile(r"hxxps", re.IGNORECASE), "https"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\[:\]|\(:\)"), ":"),
    (re.compile(r"\[at\]|\(at\)", re.IGNORECASE), "@"),
]


class UnsupportedSource(Exception):
    pass


def defang_normalize(text: str) -> str:
    """Undo common IOC defanging (hxxp, [.], etc.) so regexes can match
    normally. Reports defang IOCs specifically so they don't get treated
    as live links/clicked by accident — this tool re-fangs them purely
    in memory for extraction, nothing here fetches or resolves them."""
    for pattern, repl in _DEFANG_SUBS:
        text = pattern.sub(repl, text)
    return text


def _strip_html(raw: str) -> str:
    raw = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", raw)
    raw = re.sub(r"(?s)<[^>]+>", " ", raw)
    return html.unescape(raw)


def fetch_text(source: str) -> str:
    """Return plain text for a URL or local file path. HTML is stripped
    to text; PDFs and other binary formats are explicitly unsupported —
    extract text yourself first and pass a .txt file if you hit one."""
    if source.lower().endswith(".pdf"):
        raise UnsupportedSource(
            "PDF sources aren't supported yet; extract the text first "
            "(e.g. `pdftotext report.pdf report.txt`) and pass that file")

    if source.startswith(("http://", "https://")):
        req = urllib.request.Request(source, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            content_type = resp.headers.get_content_type()
            raw = resp.read().decode(resp.headers.get_content_charset() or "utf-8",
                                      errors="replace")
        if content_type == "text/html":
            return _strip_html(raw)
        return raw

    from pathlib import Path
    p = Path(source)
    if not p.exists():
        raise FileNotFoundError(f"no such file: {source}")
    raw = p.read_text(errors="replace")
    if p.suffix.lower() in (".htm", ".html"):
        return _strip_html(raw)
    return raw


def extract_observables(text: str) -> dict[str, list[str]]:
    """Pull hashes/IPs/domains/URLs/ATT&CK technique IDs out of report
    text. Input should already be defang-normalized."""
    urls = sorted(set(_URL_PATTERN.findall(text)))

    ips = []
    for m in _IP_PATTERN.findall(text):
        try:
            addr = ipaddress.ip_address(m)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local \
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified:
            continue  # not useful as adversary infrastructure
        ips.append(m)
    ips = sorted(set(ips))

    domains = set()
    for m in _DOMAIN_CANDIDATE.finditer(text):
        tld = m.group(1).lower()
        if tld in _TLDS:
            domains.add(m.group(0).rstrip("."))
    domains = sorted(domains)

    # Longest-match-first so a sha256 substring can't also register as
    # an md5/sha1 hit — word boundaries already prevent this in practice
    # since hex runs are contiguous word characters, but keep it explicit.
    hashes: dict[str, str] = {}
    for algo in ("sha256", "sha1", "md5"):
        for m in _HASH_PATTERNS[algo].findall(text):
            hashes.setdefault(m.lower(), algo)
    hash_list = sorted(f"{algo}:{value}" for value, algo in hashes.items())

    ttps = sorted(set(_TTP_PATTERN.findall(text)))

    return {"hashes": hash_list, "domains": domains, "ips": ips,
            "urls": urls, "ttps": ttps}


def suggest_cluster_names(text: str, max_candidates: int = 5) -> list[str]:
    """Rank candidate threat-actor/malware names by mention frequency.
    Best-effort only — always let an explicit cluster_name from the
    caller/agent override this."""
    counts: Counter[str] = Counter()
    for pattern in _NAME_PATTERNS:
        for m in pattern.finditer(text):
            name = m.group(0).strip()
            name = re.sub(r"\s+", " ", name)
            counts[name] += 1
    ranked = [name for name, _ in counts.most_common(max_candidates)]
    return ranked
