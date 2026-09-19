"""Turning one observation of a host into selectors.

`vm_proxy.observe` returns what a host looks like. This decides which of
those facts could be *shared* with another host, and at what strength.

The split matters: the probe VM's job is to collect, and this module's job
is to interpret. A field that nothing can pivot on - a status code, a
content length - is deliberately not a selector, however useful it is
elsewhere.
"""
from __future__ import annotations

from typing import Any, Iterator

from ..store import psl
from ..store.selectors import TYPES

# Certificate subjects that identify a default build rather than an operator.
# A self-signed cert left at its install-time defaults is shared by every
# deployment of that software, so it links tools, not owners. Recording it
# would tie together every unconfigured host on the internet.
_DEFAULT_CERT_MARKERS = (
    "o = internet widgits", "ou = internet widgits",   # OpenSSL's default
    "cn = localhost", "cn = example.com",
)

# Titles that mean "nothing is configured here".
_DEFAULT_TITLES = {
    "welcome to nginx!", "apache2 ubuntu default page: it works",
    "apache2 debian default page: it works", "it works!",
    "test page for the apache http server", "iis windows server",
    "404 not found", "403 forbidden", "400 bad request",
}


def _is_default_cert(subject: str | None) -> bool:
    if not subject:
        return False
    lowered = subject.lower()
    return any(marker in lowered for marker in _DEFAULT_CERT_MARKERS)


def selectors_from(result: dict[str, Any], *, target: str,
                   kind: str) -> Iterator[tuple[str, Any]]:
    """Yield (selector_type, value) pairs from one observe result.

    Nothing here contacts anything; it reads what the pass already returned.
    """
    http = result.get("http") or {}
    tls = result.get("tls") or {}
    dns = result.get("dns") or {}
    whois = result.get("whois") or {}
    cdn = result.get("cdn") or {}
    on_shared_infra = bool(cdn.get("is_cdn"))

    # --- identity ---------------------------------------------------------
    # The rotation-proof link: the same bytes served from somewhere else.
    if http.get("body_sha256"):
        yield "http.body_sha256", http["body_sha256"]
    if http.get("favicon_mmh3") not in (None, "", 0):
        yield "http.favicon_mmh3", http["favicon_mmh3"]
    if tls.get("cert_sha256"):
        yield "tls.cert_sha256", tls["cert_sha256"]
    # A reused keypair survives certificate rotation, so this outlives the
    # cert hash it was issued under.
    if tls.get("spki_sha256"):
        yield "tls.spki_sha256", tls["spki_sha256"]

    # --- structural -------------------------------------------------------
    if tls.get("serial"):
        yield "tls.serial", tls["serial"]
    subject = tls.get("subject_dn") or tls.get("subject_cn")
    if subject and not _is_default_cert(subject):
        yield "tls.subject_cn", subject
    for san in tls.get("sans") or []:
        # A certificate naming its own host links nothing.
        if san and san.lower().lstrip("*.") != target.lower():
            yield "tls.san", san

    if kind == "domain":
        apex = psl.apex_for_selector(target)
        if apex:
            yield "dns.apex", apex
        # The nameserver SET, not each server: one shared nameserver with a
        # mass provider is meaningless, the whole set is an account.
        if dns.get("ns"):
            yield "dns.ns_set", dns["ns"]
        if dns.get("soa_email"):
            yield "dns.soa_email", dns["soa_email"]
        if whois.get("registrant_email"):
            yield "whois.registrant_email", whois["registrant_email"]
        if whois.get("registrar"):
            yield "whois.registrar", whois["registrar"]

    # Resolution and co-tenancy only mean something on dedicated hosting.
    if not on_shared_infra:
        for address in (dns.get("a") or []) + (dns.get("aaaa") or []):
            yield "net.resolved_ip", address
        if tls.get("resolved_ip"):
            yield "net.resolved_ip", tls["resolved_ip"]

    # --- behavioural ------------------------------------------------------
    if http.get("jarm"):
        yield "tls.jarm", http["jarm"]
    if tls.get("ja3s"):
        yield "tls.ja4s", tls["ja3s"]
    if result.get("ports"):
        yield "net.port_set", result["ports"]
    title = (http.get("title") or "").strip()
    if title and title.lower() not in _DEFAULT_TITLES:
        yield "http.title", title

    # --- contextual -------------------------------------------------------
    # Recorded so a finding can be described, never so one can be made.
    if http.get("server"):
        yield "http.server", http["server"]
    if tls.get("issuer"):
        yield "tls.issuer", tls["issuer"]
    if http.get("asn"):
        yield "net.asn", http["asn"]
    for tech in http.get("tech") or []:
        yield "http.tech", tech


def summarize(result: dict[str, Any]) -> str:
    """A compact rendering of what one pass found."""
    if result.get("error"):
        return f"observe failed: {result['error']}"
    http, tls = result.get("http") or {}, result.get("tls") or {}
    bits = []
    if http.get("status"):
        bits.append(f"http {http['status']}")
    if http.get("body_sha256"):
        bits.append(f"body {http['body_sha256'][:12]}")
    if http.get("favicon_mmh3"):
        bits.append(f"favicon {http['favicon_mmh3']}")
    if tls.get("cert_sha256"):
        bits.append(f"cert {tls['cert_sha256'][:12]}")
    if tls.get("self_signed"):
        bits.append("self-signed")
    if result.get("ports"):
        bits.append(f"ports {result['ports']}")
    if (result.get("cdn") or {}).get("is_cdn"):
        bits.append(f"cdn:{result['cdn'].get('provider') or 'yes'}")
    missing = result.get("tools_missing") or []
    if missing:
        bits.append(f"[missing: {', '.join(sorted(set(missing)))}]")
    return "  ".join(bits) or "nothing observed"


def known_types() -> set[str]:
    """Selector types this extractor can emit - used by a test to catch a
    typo'd type name before it silently becomes class contextual."""
    return set(TYPES)
