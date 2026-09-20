"""Selectors: the facts that link one indicator to another.

## Why this exists

Everything else in this store is *indicator-centric*: a fact is recorded
against one indicator and compared only against that indicator's own past.
That answers "what changed?" and cannot answer "who else has this?".

Infrastructure hunting is the second question. The SilkParasite reporting
that prompted this module worked entirely that way: one cloned decoy page's
SHA-256 body hash appeared on 13 hosts, one TLS certificate on 8, and three
malware families were tied together by a shared domain *registration* rather
than a shared server. Each of those is a value that several indicators have
in common, which is exactly what this table indexes.

Six of the ten change specs in `changes.py` already hold such values -
`cert_hash`, `webamon_fingerprint`, `ptr`, `resolved_ip`, `cert`.sans and
`ip_hostnames`. They are stored per-indicator and compared only to
themselves, so the links they imply have never been visible.

## Why selectors are classed

The obvious failure mode is noise. In this repo's own live data, the values
most widely shared between indicators are `Server: cloudflare` (8
indicators, 3 actors), `Apache`, and `Let's Encrypt` issuers (5 indicators,
3 actors). Those are not leads. Meanwhile `nginx/1.29.3` - specific enough
to look meaningful, and cited in the source reporting - returns more than
10,000 hits on a global scan index.

So a selector's *type* carries a class, fixed once, here, and the class caps
how much that value can ever prove. A contextual selector cannot promote a
candidate no matter how many indicators share it. This is the same
discipline as `graph/nodes/rank.py`: decide it in code, before anything
spends tokens reasoning about it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

import duckdb

from ..util import rows

SCHEMA = """
CREATE TABLE IF NOT EXISTS selectors (
    selector_type   TEXT NOT NULL,
    selector_value  TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    indicator_type  TEXT,
    actor           TEXT,
    source          TEXT,
    first_seen      TIMESTAMP,
    last_seen       TIMESTAMP,
    UNIQUE (selector_type, selector_value, indicator_value)
);
-- The whole point: "who else has this value" must be an index seek.
CREATE INDEX IF NOT EXISTS sel_lookup ON selectors (selector_type, selector_value);
CREATE INDEX IF NOT EXISTS sel_indicator ON selectors (indicator_value);

CREATE TABLE IF NOT EXISTS selector_stats (
    selector_type  TEXT NOT NULL,
    selector_value TEXT NOT NULL,
    local_count    BIGINT,
    global_count   BIGINT,
    global_source  TEXT,
    checked_at     TIMESTAMP,
    UNIQUE (selector_type, selector_value)
);
"""


# --------------------------------------------------------------------------- #
# The taxonomy
# --------------------------------------------------------------------------- #

# Ordered weakest to strongest so comparisons read naturally.
CLASS_ORDER = ("contextual", "behavioural", "structural", "identity")



@dataclass(frozen=True)
class SelectorType:
    """One kind of linking fact.

    name      dotted, `<domain>.<attribute>`, stable - it is a stored value
    cls       what a shared value can prove (see CLASS_ORDER)
    means     what it means when two indicators share this value
    never     what it does NOT prove, which is the part that gets forgotten
    """
    name: str
    cls: str
    means: str
    never: str = ""


def _t(name: str, cls: str, means: str, never: str = "") -> SelectorType:
    return SelectorType(name, cls, means, never)


TYPES: dict[str, SelectorType] = {t.name: t for t in (

    # --- identity: a shared value is close to conclusive -------------------
    # These are content or key digests. Two hosts holding the same one did not
    # arrive there by coincidence; they were configured from the same source.
    _t("tls.cert_sha256", "identity",
       "the same leaf certificate is installed on both hosts - the operator "
       "copied a keypair, so they share a deployment",
       "that the hosts are the same machine, or that the cert is not shared "
       "hosting boilerplate - check the issuer and rarity first"),
    _t("http.body_sha256", "identity",
       "byte-identical response bodies: the same page is being served. The "
       "strongest rotation-proof link there is, because it survives the "
       "domain, the IP and the provider all changing",
       "anything at all when the body is an empty response, a default nginx "
       "or Apache welcome page, or a shared CDN error page"),
    _t("http.favicon_mmh3", "identity",
       "the same favicon - typically the same panel, kit or product build",
       "operator identity for a widely deployed product's stock favicon"),
    _t("tls.spki_sha256", "identity",
       "the same public key across certificates - the operator reused a "
       "keypair when reissuing, so it holds where tls.cert_sha256 and "
       "tls.serial both change. Computed locally from the certificate; "
       "tlsx has no SPKI output and reading one from it left this selector "
       "empty for its whole existence",
       "anything when the key belongs to a hosting provider's shared "
       "certificate - and note that neither index can reverse-look-up an "
       "SPKI digest, so this is the one identity selector that can never "
       "be priced. It rests on its class and the local gates alone"),
    _t("file.sha256", "identity",
       "the same file was staged on both hosts",
       "that both hosts are adversary-controlled - it may be a common tool"),
    _t("webamon.fp_dom", "identity",
       "Webamon's DOM digest matches - the same rendered page, as their "
       "scanner normalizes it. Survives the cosmetic edits that change a "
       "raw body hash",
       "the same thing as http.body_sha256. It is a different digest over a "
       "different input: example.com's body hashes to ff67a9d7... while its "
       "fingerprint.dom is f4726eb4..., so the two never match and must "
       "never share a selector type"),
    _t("webamon.fp_ssl", "identity",
       "Webamon's certificate digest matches. Rare by construction - "
       "example.com's value returns 2 scans index-wide",
       "comparability with tls.spki_sha256 or tls.cert_sha256; it is their "
       "hash over their own extraction, matchable only against itself"),

    # --- structural: strong, but coincidence is possible --------------------
    # Configuration and registration facts. Two of these, of different types,
    # is the bar for promoting a candidate.
    _t("tls.serial", "structural",
       "the same certificate serial from the same issuer - a reissue of one "
       "certificate rather than two independent ones"),
    _t("tls.subject_cn", "structural",
       "certificates issued for the same name"),
    _t("tls.san", "structural",
       "both hosts appear on a certificate naming the other - the operator "
       "requested them together"),
    _t("dns.apex", "structural",
       "subdomains of one registered domain. This is the registration-level "
       "link: separate hosts, separate servers, one purchase",
       "a shared server - and nothing at all on a domain that sells "
       "subdomains to the public"),
    _t("dns.ns_set", "structural",
       "the same nameserver set - the same DNS provider and often the same "
       "account",
       "a link when the nameservers belong to a mass provider such as "
       "Cloudflare"),
    _t("dns.soa_email", "structural",
       "the same zone contact address"),
    _t("whois.registrant_email", "structural",
       "the same registrant contact registered both domains"),

    _t("net.reverse_dns", "structural",
       "the same PTR hostname - often the same physical or virtual host"),
    _t("net.resolved_ip", "structural",
       "both names resolve to the same address",
       "co-tenancy on shared hosting, which is not a link - check cdncheck "
       "or the ASN first"),
    _t("dns.mx_set", "structural",
       "the same mail-exchanger set - the same mail provider and usually the "
       "same account. Rarer than an NS set, because most malicious domains "
       "publish no MX at all",
       "a link on a mass provider's MX (Google, Microsoft, Zoho)"),
    _t("webamon.fp_dom_structure", "structural",
       "the same DOM structure with the text changed - how a cloned kit is "
       "recognised after the operator edits the branding. This is the "
       "selector for the source reporting's cloned decoy page",
       "the same page: every site built from one template shares it, which "
       "is why it is structural and not identity"),
    _t("webamon.fp_cert_san", "structural",
       "the same SAN list, as one digest. Stronger than a single shared SAN: "
       "it means both certificates name exactly the same set of hosts"),
    _t("webamon.fp_domains", "structural",
       "the page loads resources from the same set of domains - the same "
       "kit's backend and CDN choices"),
    _t("webamon.fp_ns_set", "structural",
       "Webamon's digest of the nameserver set",
       "a link on a mass provider - the same caveat as dns.ns_set, and the "
       "rarity gate cannot read a digest, so check the plaintext set too"),
    _t("webamon.fp_mx_set", "structural",
       "Webamon's digest of the mail-exchanger set"),


    # --- behavioural: corroborates, never promotes alone --------------------
    # How the service behaves. Distinctive in combination, individually shared
    # by every host running the same stack.
    _t("tls.jarm", "behavioural",
       "the same TLS stack and configuration - consistent with the same C2 "
       "family or the same build",
       "operator identity: JARM identifies software, not owners"),
    _t("tls.ja4s", "behavioural",
       "the server side of the handshake matches"),
    _t("whois.registrar", "behavioural",
       "both registered through the same registrar - worth noting beside a "
       "stronger link, since a bulk-registering operator tends to stay with "
       "one registrar",
       "a link on its own: registrars have millions of customers. This was "
       "classed structural while its own description said otherwise, and "
       "NameSilo duly appeared as a six-indicator 'link' in a live sweep"),
    _t("tls.default_subject", "behavioural",
       "the same stock certificate subject - a self-signed cert left at its "
       "install-time defaults. Identifies the software build, the way JARM "
       "does, and is genuinely useful: two tracked hosts carrying the same "
       "one are running the same tool",
       "operator identity. Every unconfigured deployment of that software "
       "shares it, so it corroborates a link and cannot make one"),
    _t("net.port_set", "behavioural",
       "the same open-port pattern. Unusual high ports are the interesting "
       "case - the source reporting keyed on RDP-over-TLS at 64350, 64330, "
       "65535 and 65111",
       "a link on a common set such as 22/80/443"),
    _t("http.header_set", "behavioural",
       "the same unusual response-header combination - typically the same "
       "server build or reverse proxy config"),
    _t("net.passive_port_set", "behavioural",
       "a third-party scan index saw the same open-port pattern on both. "
       "Useful because nobody had to send a packet for it",
       "the ports that are open NOW. The observation is someone else's, at "
       "an unknown time, so it can corroborate a link and must never be "
       "confused with net.port_set, which nmap confirmed"),
    _t("net.historical_ip", "behavioural",
       "both names resolved to the same address at some point in passive "
       "DNS history - which is how infrastructure reuse survives a rotation "
       "that current resolution no longer shows",
       "co-residence. Two domains on one address four years apart share "
       "nothing; only overlapping first/last-seen windows make it a lead, "
       "which is why this is not net.resolved_ip"),
    _t("net.cohosted_domain", "behavioural",
       "a third-party index sees both names on one address. Corroborates a "
       "link established some other way; on its own it is a statement about "
       "the hosting, not the operator",
       "a link on shared hosting, where every pair of addresses shares "
       "thousands of tenants. Backfilling it without that gate produced 5320 "
       "selectors from this repo's own data, nearly all Cloudflare tenants"),
    _t("http.error_page_sha256", "behavioural",
       "both hosts serve the same error page. Weak, but not nothing: the "
       "same origin-down page from the same CDN is a statement about shared "
       "hosting, and an unusual custom error page can be a real tell",
       "a link, and especially not a shared deployment. Cloudflare's 521 "
       "'Web Server Is Down' page promoted three domains under three "
       "different registrations before this type existed, because a body "
       "hash was recorded whatever the status code said"),
    _t("http.title", "behavioural",
       "the same page title. Weak alone, useful when the title is itself "
       "distinctive and the body hash differs only by a timestamp"),
    _t("webamon.fp_header_order", "behavioural",
       "the response headers arrive in the same ORDER, which is a property "
       "of the server build and proxy chain rather than its configuration - "
       "the HTTP analogue of JARM"),
    _t("webamon.fp_cert_config", "behavioural",
       "the same certificate configuration - key type, extensions, validity "
       "window shape",
       "a link: 1.3 million scans share example.com's value"),
    _t("webamon.fp_cert_issuer", "behavioural",
       "the same issuer, as a digest",
       "a link - the plaintext form is tls.issuer, which is contextual for "
       "the same reason"),
    _t("webamon.fp_cookie_names", "behavioural",
       "the same cookie names - usually the same application or panel"),

    # --- contextual: colour only, structurally unable to promote ------------
    # These exist so findings can be described, not so leads can be made.
    _t("net.asn", "contextual",
       "hosted in the same autonomous system",
       "a link. Millions of hosts share an ASN; this is background"),
    _t("net.prefix", "contextual",
       "the same announced prefix - tighter than an ASN, still shared "
       "infrastructure"),
    _t("http.server", "contextual",
       "the same Server header",
       "a link, ever. Even a specific version string such as nginx/1.29.3 "
       "matches more than 10,000 hosts on a public index"),
    _t("tls.issuer", "contextual",
       "certificates from the same CA",
       "a link: almost everything is Let's Encrypt"),
    _t("tls.multi_san_cert", "contextual",
       "both hosts present a certificate naming about as many hosts - which "
       "says they are behind hosting of a similar shape",
       "a link. It is recorded in place of the SAN list when a certificate "
       "names more than MAX_OPERATOR_SANS hosts, so that a provider's "
       "certificate cannot manufacture dozens of structural selectors"),
    _t("http.tech", "contextual",
       "the same detected technology"),
    _t("webamon.fp_tech", "contextual",
       "the same detected technology set",
       "a link: 22 million scans share example.com's value"),
    _t("webamon.fp_asn", "contextual",
       "the same set of ASNs served the page's resources",
       "a link: 6.8 million scans share example.com's value"),
    _t("webamon.fp_links", "contextual",
       "the same outbound link set",
       "a link: 2.9 million scans share example.com's value"),
    _t("webamon.fp_scripts", "contextual",
       "the page loads the same set of scripts",
       "a link: 17.8 million scans share example.com's value"),
    _t("webamon.fp_cookies", "contextual",
       "the page sets the same cookies, values included",
       "a link: 48.8 million scans share example.com's value"),
    _t("brand.impersonated", "contextual",
       "both names are lexically close to the same brand - which is a "
       "statement about the lure, not the operator",
       "a link, ever. Every phishing kit targeting one brand shares it; "
       "1962 scans match 'microsoft'. It is here to be displayed beside a "
       "finding, and would have labelled update-sentinelone.com on sight"),
    _t("net.cpe", "contextual",
       "a scan index fingerprinted the same product and version on both",
       "a link: a CPE names software, and popular software is everywhere"),
    _t("net.country", "contextual", "hosted in the same country"),
)}


# Which observation a selector was read off. Independence is per ARTEFACT,
# not per type: two selectors describing one thing you looked at once are
# one fact however many columns they fill.
#
# The rule was already written down for SANs - "two SANs off one
# certificate are one fact, not two" - and applied only to the literal
# case. Everything else on that certificate still counted separately, so a
# link carrying tls.cert_sha256, tls.spki_sha256 and tls.serial read as
# three independent facts when it is one certificate seen once. Adding the
# SPKI digest made it worse, because it inflated every certificate link by
# one more.
#
# Only strict containment is grouped. A certificate CONTAINS its serial,
# subject, SANs, issuer and public key, so sharing the certificate
# guarantees sharing all of them. An address DETERMINES its PTR, ASN,
# prefix and country the same way. Registration and DNS are left
# ungrouped: an operator can change registrar without changing nameservers
# and vice versa, so those really are separate facts.
_ARTEFACTS: dict[str, tuple[str, ...]] = {
    "certificate": (
        "tls.cert_sha256", "tls.spki_sha256", "tls.serial", "tls.subject_cn",
        "tls.san", "tls.issuer", "tls.default_subject", "tls.multi_san_cert",
        "webamon.fp_ssl", "webamon.fp_cert_san", "webamon.fp_cert_config",
        "webamon.fp_cert_issuer",
    ),
    "page": (
        "http.body_sha256", "http.error_page_sha256", "http.title",
        "webamon.fp_dom", "webamon.fp_dom_structure",
    ),
    "address": (
        "net.resolved_ip", "net.reverse_dns", "net.asn", "net.prefix",
        "net.country",
    ),
}

ARTEFACT: dict[str, str] = {
    selector_type: artefact
    for artefact, selector_types in _ARTEFACTS.items()
    for selector_type in selector_types
}


def artefact(selector_type: str) -> str:
    """What was observed to produce this selector.

    A type with no group is its own artefact - the safe default, because
    grouping two genuinely separate facts would weaken a real link, which
    is the more expensive mistake of the two.
    """
    return ARTEFACT.get(selector_type, selector_type)


# Selectors whose value is a whole SET, matched only in its entirety. A list
# handed to record_many is otherwise stored one member at a time, which
# quietly turns "the same nameserver set" into "shares any one nameserver" -
# the mass-provider match the set form exists to prevent. Seen for real
# twice: a live sweep recorded ns1, ns2 and ns3.dnsowl.com as three separate
# links, and net.passive_port_set stored 445, 3389 and 5985 as three.
#
# Derived from the names rather than hand-listed, because the hand-listed
# version is what was wrong both times - a new *_set type has to be
# remembered, and twice it was not.
SET_VALUED = frozenset(name for name in TYPES if name.endswith("_set"))


def selector_class(selector_type: str) -> str:
    """The class of a type. Unknown types are contextual: a new selector has
    to be classed deliberately before it can carry weight."""
    spec = TYPES.get(selector_type)
    return spec.cls if spec else "contextual"


def can_promote(selector_type: str) -> bool:
    """Whether a shared value of this type may promote a candidate at all.

    Contextual and behavioural types return False no matter how rare the
    value or how many indicators share it. That is the guard against a
    finding built on `Server: cloudflare`.
    """
    return selector_class(selector_type) in ("identity", "structural")


def rank(selector_type: str) -> int:
    return CLASS_ORDER.index(selector_class(selector_type))


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #

def record(con: duckdb.DuckDBPyConnection, *, indicator_value: str,
           selector_type: str, selector_value: Any, observed_at,
           indicator_type: str | None = None, actor: str | None = None,
           source: str | None = None) -> bool:
    """Record one selector. Returns True if it was new.

    Values are normalized by `normalize()` so that a hash written in upper
    case by one tool and lower case by another does not become two selectors
    that fail to link.
    """
    value = normalize(selector_type, selector_value)
    if value is None:
        return False
    existed = con.execute(
        "SELECT 1 FROM selectors WHERE selector_type = ? AND selector_value = ? "
        "AND indicator_value = ?", [selector_type, value, indicator_value]).fetchone()
    con.execute(
        """INSERT INTO selectors (selector_type, selector_value, indicator_value,
               indicator_type, actor, source, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (selector_type, selector_value, indicator_value) DO UPDATE SET
               last_seen = excluded.last_seen,
               actor = coalesce(excluded.actor, selectors.actor),
               indicator_type = coalesce(excluded.indicator_type, selectors.indicator_type)""",
        [selector_type, value, indicator_value, indicator_type, actor, source,
         observed_at, observed_at])
    return existed is None


def record_many(con: duckdb.DuckDBPyConnection, *, indicator_value: str,
                found: Iterable[tuple[str, Any]], observed_at,
                indicator_type: str | None = None, actor: str | None = None,
                source: str | None = None) -> list[str]:
    """Record many selectors for one indicator. Returns the types that were new."""
    fresh = []
    for selector_type, value in found:
        if selector_type in SET_VALUED:
            values = [value]          # the set IS the value
        else:
            values = value if isinstance(value, (list, tuple, set)) else [value]
        for one in values:
            if record(con, indicator_value=indicator_value, selector_type=selector_type,
                      selector_value=one, observed_at=observed_at,
                      indicator_type=indicator_type, actor=actor, source=source):
                fresh.append(selector_type)
    return fresh


# Values that are technically present but link nothing. Recording them would
# bury the real selectors under thousands of rows pointing at the same
# well-known emptiness.
_EMPTY_BODY_SHA256 = {
    # sha256 of b"" - a host that answered with no body at all
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

_JUNK = {"", "-", "none", "null", "unknown", "n/a", "localhost"}


def normalize(selector_type: str, value: Any) -> str | None:
    """Canonical string form, or None if the value carries no signal.

    Case and whitespace are normalized so the same fact from two tools
    becomes one selector. Hex digests are lowercased; hostnames are
    lowercased and stripped of a trailing dot.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (list, tuple, set)):
        # A set-valued selector (ports, nameservers) is one selector whose
        # value is the sorted set, so two hosts match only on the whole set.
        parts = [str(v).strip().lower() for v in value if str(v).strip()]
        if not parts:
            return None
        # Numeric members sort numerically. A lexical sort turned the ports
        # 53, 443, 3389 into "3389,443,53", which still matches itself but
        # is unreadable in a digest and sorts differently from every other
        # tool's port list.
        parts.sort(key=lambda p: (0, int(p), "") if p.isdigit() else (1, 0, p))
        return ",".join(parts)

    text = str(value).strip()
    if not text or text.lower() in _JUNK:
        return None

    if selector_type.endswith(("_sha256", "_mmh3", "jarm", "ja4s", "serial")):
        text = text.lower()
    if selector_type.startswith(("dns.", "net.reverse_dns", "tls.subject_cn", "tls.san")):
        text = text.lower().rstrip(".")
    if selector_type in ("whois.registrant_email", "dns.soa_email"):
        text = text.lower()

    if selector_type == "http.body_sha256" and text in _EMPTY_BODY_SHA256:
        return None
    return text


# --------------------------------------------------------------------------- #
# Reading - the question the old store could not answer
# --------------------------------------------------------------------------- #

def sharing(con: duckdb.DuckDBPyConnection, selector_type: str,
            selector_value: Any) -> list[dict[str, Any]]:
    """Every indicator carrying this selector value."""
    value = normalize(selector_type, selector_value)
    if value is None:
        return []
    return rows(con,
                "SELECT indicator_value, indicator_type, actor, source, "
                "first_seen, last_seen FROM selectors "
                "WHERE selector_type = ? AND selector_value = ? "
                "ORDER BY first_seen", [selector_type, value])


def for_indicator(con: duckdb.DuckDBPyConnection,
                  indicator_value: str) -> list[dict[str, Any]]:
    return rows(con,
                "SELECT selector_type, selector_value, source, first_seen, last_seen "
                "FROM selectors WHERE indicator_value = ? "
                "ORDER BY selector_type", [indicator_value])


def _usable(con: duckdb.DuckDBPyConnection, selector_type: str,
            selector_value: Any) -> bool:
    """Class AND value.

    A type can be structural while a particular value of it names a mass
    provider and links nothing - `dns.ns_set` on Cloudflare's nameservers is
    the case this exists for. The second check is the priced one: a value
    with more index-wide hits than PROVIDER_SCALE_GLOBAL_COUNT describes the
    internet, and no vendored list could have named it in advance, because
    nobody knows which DOM digest is on 17 million sites until they ask.
    """
    from .rarity import globally_common, value_is_provider_scale

    if not can_promote(selector_type):
        return False
    if value_is_provider_scale(selector_type, selector_value):
        return False
    return not globally_common(con, selector_type, selector_value)


def shared(con: duckdb.DuckDBPyConnection, *, min_indicators: int = 2,
           promotable_only: bool = True) -> list[dict[str, Any]]:
    """Selector values held by more than one indicator - the link candidates.

    `promotable_only` keeps contextual and behavioural types out by default,
    because otherwise the answer is dominated by `Server: cloudflare` and
    `Let's Encrypt` and the real links are buried.
    """
    result = rows(con, """
        SELECT selector_type, selector_value,
               count(DISTINCT indicator_value) AS indicators,
               count(DISTINCT actor) FILTER (WHERE actor IS NOT NULL) AS actors,
               string_agg(DISTINCT indicator_value, ', ') AS values,
               string_agg(DISTINCT actor, ', ') AS who,
               min(first_seen) AS first_seen, max(last_seen) AS last_seen
        FROM selectors
        GROUP BY 1, 2
        HAVING count(DISTINCT indicator_value) >= ?
        ORDER BY 3 DESC, 1""", [min_indicators])
    if promotable_only:
        result = [r for r in result
                  if _usable(con, r["selector_type"], r["selector_value"])]
    for r in result:
        r["selector_class"] = selector_class(r["selector_type"])
    return result


def neighbours(con: duckdb.DuckDBPyConnection, indicator_value: str, *,
               promotable_only: bool = True) -> list[dict[str, Any]]:
    """Indicators linked to this one, and by which selectors.

    One row per neighbour, with the selector types that connect them and the
    strongest class among those - which is what the corroboration rule needs.
    """
    result = rows(con, """
        WITH mine AS (
            SELECT selector_type, selector_value FROM selectors
            WHERE indicator_value = ?
        )
        SELECT s.indicator_value, s.actor,
               count(DISTINCT s.selector_type) AS via_types,
               string_agg(DISTINCT s.selector_type, ', ') AS via,
               string_agg(DISTINCT s.selector_type || '=' || s.selector_value, '|') AS pairs,
               max(s.last_seen) AS last_seen
        FROM selectors s JOIN mine m
          ON s.selector_type = m.selector_type AND s.selector_value = m.selector_value
        WHERE s.indicator_value <> ?
        GROUP BY 1, 2
        ORDER BY 3 DESC""", [indicator_value, indicator_value])
    out = []
    for r in result:
        pairs = [p.split("=", 1) for p in (r.pop("pairs", "") or "").split("|") if "=" in p]
        types = [t.strip() for t in (r["via"] or "").split(",") if t.strip()]
        if promotable_only:
            # Filter on the type AND the value it matched on, so a link that
            # exists only through a mass provider is not offered.
            usable = {t for t, v in pairs if _usable(con, t, v)}
            types = [t for t in types if t in usable]
            if not types:
                continue
        r["via"] = types
        r["strongest"] = max((selector_class(t) for t in types),
                             key=CLASS_ORDER.index, default="contextual")
        out.append(r)
    return out
