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

from ..store import cdn as cdn_ranges
from ..store import psl
from ..store.selectors import TYPES

# Above this many SANs a certificate belongs to a hosting provider rather
# than an operator. See the gate in selectors_from for the measurement.
MAX_OPERATOR_SANS = 16

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
    """Whether a certificate subject identifies a stock build.

    Spacing is normalised first: tools emit both "CN = localhost" and
    "CN=localhost", and matching on one form let the other straight
    through. A live sweep recorded "cn=localhost, ou=it, o=myorg,
    l=default, st=default, c=ru" as a structural link past this filter.

    That one is kept deliberately - see _DEFAULT_CERT_MARKERS.
    """
    if not subject:
        return False
    lowered = " ".join(subject.lower().replace("=", " = ").split())
    return any(marker in lowered for marker in _DEFAULT_CERT_MARKERS)

def _common_name(subject: str) -> str | None:
    """The CN out of a distinguished name.

    Only needed for sources that hand over a DN and no separate CN - the
    retired Cert Spotter rows and openssl's `tls_live` grab. tlsx returns
    subject_cn directly, and that is preferred over parsing.

    RFC 4514 escapes a literal comma as `\\,`, which appears for real in this
    repo's data: `o=alibaba (china) technology co.\\, ltd.`. Splitting on a
    bare comma would cut that in half, so the escape is honoured.
    """
    parts, current, escaped = [], [], False
    for ch in subject:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ",":
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    for part in parts:
        key, _, value = part.partition("=")
        if key.strip().lower() == "cn" and value.strip():
            return value.strip()
    return None


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
    cdn_failed = "cdn" in (result.get("errors") or {})
    on_shared_infra = bool(cdn.get("is_cdn"))

    # --- identity ---------------------------------------------------------
    # The rotation-proof link: the same bytes served from somewhere else.
    #
    # Except off a CDN edge address. Probing an IP that belongs to a CDN
    # returns the CDN's own default response, and its digest is identical on
    # every edge node - a live sweep linked three Cloudflare addresses to
    # each other that way. A DOMAIN behind a CDN is different: the bytes are
    # the operator's, so only the IP case is suppressed.
    probing_cdn_edge = kind == "ip" and (on_shared_infra or cdn_failed)
    # A body hash only means "the same page is being served" when a page was
    # actually served. On an error response the bytes are the CDN's or the
    # server's, not the operator's, and hashing them links every host whose
    # origin happens to be down. This selector's own `never` field said so -
    # "anything at all when the body is an empty response, a default nginx
    # or Apache welcome page, or a shared CDN error page" - and nothing
    # enforced it, so three STAC4749 domains under three different
    # registrations were promoted on Cloudflare's 521 "Web Server Is Down"
    # page. Its hash is on 103 scans index-wide, well under any rarity
    # threshold, so pricing could never have caught it either.
    #
    # The hash is still recorded, demoted: two tracked hosts serving the
    # same error page IS a weak signal about shared hosting, and it is the
    # same treatment tls.default_subject already gets rather than discarding
    # a fact because it cannot carry weight.
    status = http.get("status")
    served_a_page = isinstance(status, int) and 200 <= status < 400
    if http.get("body_sha256") and not probing_cdn_edge:
        yield (("http.body_sha256" if served_a_page else "http.error_page_sha256"),
               http["body_sha256"])
    if (http.get("favicon_mmh3") not in (None, "", 0) and not probing_cdn_edge
            and served_a_page):
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
    # A stock subject is not nothing - two tracked hosts sharing one are
    # running the same build - but it is not a structural link either, since
    # every unconfigured deployment of that software carries it. So it is
    # recorded at behavioural strength rather than discarded, which is what
    # an earlier version did to "cn=localhost, ou=it, o=myorg, l=default,
    # st=default, c=ru" - a subject shared by two tracked 7-Eleven
    # impersonation domains.
    #
    # A default subject keeps the whole DN, because the combination of stock
    # fields IS the fingerprint. A real one keeps only the CN: the DN carried
    # a tool's formatting with it, so the same Microsoft certificate was
    # stored as both "c = us, st = wa, ..., cn = *.sharepoint.com" and
    # "cn=*.sharepoint.com" and the two never linked - and neither form can
    # be looked up against an index, which holds the bare name.
    subject = tls.get("subject_dn") or tls.get("subject_cn")
    if subject:
        if _is_default_cert(subject):
            yield "tls.default_subject", subject
        else:
            cn = tls.get("subject_cn") or _common_name(subject)
            if cn:
                yield "tls.subject_cn", cn
    # A certificate naming a handful of hosts is the operator requesting them
    # together - the structural link this selector exists for. A certificate
    # naming dozens is a cloud provider's, and recording every name makes any
    # two tenants behind it share dozens of "structural" selectors: one
    # Aliyun OSS host in this repo's data contributed 58 SANs and one Azure
    # blob host 53, out of 148 in the whole table.
    #
    # The cap, not a provider list, because the shape is the tell and no list
    # could stay current. The source reporting's shared certificate named 8
    # hosts, so the bar sits comfortably above the real cases.
    sans = [s for s in (tls.get("sans") or []) if s]
    if len(sans) <= MAX_OPERATOR_SANS:
        for san in sans:
            # A certificate naming its own host links nothing.
            if san.lower().lstrip("*.") != target.lower():
                yield "tls.san", san
    elif sans:
        # Not silence: the count itself says "provider certificate", which is
        # worth knowing beside a finding and can never promote one.
        yield "tls.multi_san_cert", str(len(sans))

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

    # Resolution only means something on dedicated hosting.
    #
    # The gate has to fail CLOSED. The first version read cdncheck's verdict
    # and nothing else, so when cdncheck errored - which it did, on a bad
    # flag - is_cdn came back False and four Cloudflare addresses were
    # recorded as structural links for example.com. A broken detector
    # silently re-enabled exactly the noise the gate exists to stop.
    #
    # So: cdncheck's verdict on the target, plus the vendored CIDR list on
    # each address, and when cdncheck failed the local list is the only
    # thing standing between us and that noise.
    if not on_shared_infra:
        # Deduplicated: the DNS answer and the address tlsx connected to are
        # normally the same, so without this every domain yielded its own
        # address twice. Harmless in the store - record() is keyed on
        # (type, value, indicator) - but it made the extractor's output read
        # as two facts, and anything counting yields would have believed it.
        addresses = list(dns.get("a") or []) + list(dns.get("aaaa") or [])
        if tls.get("resolved_ip"):
            addresses.append(tls["resolved_ip"])
        seen_addresses = set()
        for address in addresses:
            if address in seen_addresses or cdn_ranges.is_cdn(address):
                continue
            seen_addresses.add(address)
            yield "net.resolved_ip", address

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
