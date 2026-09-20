#!/usr/bin/env python3
"""Replay stored observations into the selectors table.

    python scripts/backfill_selectors.py              # against the live store
    python scripts/backfill_selectors.py --db X.duckdb --dry-run

Nothing new is collected. Every value this extracts is already in
`observations`, recorded per-indicator and compared only against its own
past. Projecting it into `selectors` is what makes "who else has this?"
answerable, and it works on history as far back as the data goes.

The point of running it first is that it needs no probe VM, no API and no
network: if the redesign is right, the links should appear immediately out
of data already on disk.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import duckdb

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cti.sources import observe as observe_source  # noqa: E402
from cti.store import cdn, psl, selectors as S  # noqa: E402
from cti.store.connection import db_path  # noqa: E402
from cti.store.schema import init_schema  # noqa: E402
from cti.sources.pivot import is_shared_hosting_hostname  # noqa: E402
from cti.tracking.analytics import SHARED_HOSTING_ASNS  # noqa: E402

# observations_wide column -> selector type. Only columns whose value is a
# fact about the host that another host could share; per-indicator state such
# as http_status or infostealer_count is not a selector.
SCALAR_MAP = {
    "tls_sha256": "tls.cert_sha256",
    "tls_issuer": "tls.issuer",
    "tls_subject": "tls.subject_cn",
    "cert_sha256": "tls.cert_sha256",     # retired Cert Spotter rows, same fact
    "cert_issuer": "tls.issuer",
    "http_server": "http.server",
    "http_title": "http.title",
    "ptr_hostname": "net.reverse_dns",
    "asn": "net.asn",
    # NOT http.body_sha256 and tls.spki_sha256, which is what these were
    # mapped to. They are Webamon's own digests over their own extraction:
    # example.com's body hashes to ff67a9d7... while its fingerprint.dom is
    # f4726eb4..., verified byte-for-byte. Mapping them onto our hash types
    # put a value into the identity class that can never match a real body
    # or key digest, and had its rarity judged against the wrong population.
    "webamon_fingerprint_dom": "webamon.fp_dom",
    "webamon_fingerprint_ssl": "webamon.fp_ssl",
    "country_code": "net.country",
}

# JSON columns whose members are each a selector value of their own.
LIST_MAP = {
    "tls_sans": "tls.san",
    "cert_sibling_hostnames": "tls.san",
    "resolved_ip": "net.resolved_ip",
    "ip_hostnames": "net.cohosted_domain",
    "discovered_hostnames": "net.cohosted_domain",
}

# JSON columns that are one selector whose value is the whole sorted set.
SET_MAP = {
    "nmap_ports": "net.port_set",
    "shodan_ports": "net.port_set",
}


# Selectors that are only meaningful on dedicated infrastructure. On a CDN or
# big-cloud address every pair shares thousands of tenants, so recording them
# there manufactures links. This is the same judgment `pivot_and_expand` and
# the `ip_hostnames` spec already make; the first version of this backfill
# skipped it and produced 5320 co-hosting selectors, nearly all Cloudflare.
_NEEDS_DEDICATED_HOST = {"net.cohosted_domain", "net.resolved_ip"}


def shared_value(selector_type: str, value: object, shared_ips: set[str]) -> bool:
    """Whether this selector VALUE points at shared infrastructure.

    The per-indicator gate is not enough. A domain has no ASN of its own, so
    a domain resolving to a Cloudflare address passed straight through it and
    two unrelated domains behind the same CDN address became a "link". The
    shared-hosting-ness lives in the value, not the indicator.

    `is_shared_hosting_hostname` had no caller anywhere in the repo before
    this; it is the hostname half of a guard whose ASN half was already wired
    up.
    """
    text = str(value)
    if selector_type == "net.resolved_ip":
        return text in shared_ips or cdn.is_cdn(text)
    if selector_type in ("net.reverse_dns", "net.cohosted_domain"):
        return is_shared_hosting_hostname(text)
    return False


def extract(row: dict, *, shared_hosting: bool = False,
            shared_ips: set[str] | None = None) -> list[tuple[str, object]]:
    """Selectors implied by one legacy observations_wide row.

    Rows written by the observe pass are handled by backfill_observe, which
    replays them through observe.selectors_from - the one place the
    extraction rules live. Letting this column mapping see them too produced
    BOTH results: a stock certificate subject arrived here as a structural
    tls.subject_cn and there as a behavioural tls.default_subject, and the
    structural one is exactly what the demotion exists to prevent.
    """
    if (row.get("source") or "") in _OBSERVE_SOURCES:
        return []

    found: list[tuple[str, object]] = []

    for column, selector_type in SCALAR_MAP.items():
        value = row.get(column)
        if value in (None, ""):
            continue
        if selector_type == "tls.subject_cn":
            # Both rules the live path applies, from the same functions. These
            # columns hold whatever the tool that wrote them formatted: a full
            # DN from openssl's grab, and the same certificate's DN spelled
            # differently by tlsx. Recording either verbatim put one fact into
            # two selector values that could never match.
            if observe_source._is_default_cert(str(value)):
                selector_type = "tls.default_subject"
            else:
                value = observe_source._common_name(str(value)) or value
        found.append((selector_type, value))

    for column, selector_type in LIST_MAP.items():
        raw = row.get(column)
        if not raw:
            continue
        try:
            members = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, ValueError):
            continue
        members = [m.get("name") or m.get("value") if isinstance(m, dict) else m
                   for m in (members or [])]
        members = [m for m in members if m]
        # The provider-certificate cap, same threshold as the live path. One
        # Aliyun OSS host's certificate names 58 hosts and one Azure blob
        # host's 53; without this the legacy columns reintroduced 1679 SAN
        # selectors after the live path had been capped to 148.
        if selector_type == "tls.san" and len(members) > observe_source.MAX_OPERATOR_SANS:
            if members:
                found.append(("tls.multi_san_cert", str(len(members))))
            continue
        for member in members:
            found.append((selector_type, member))

    for column, selector_type in SET_MAP.items():
        raw = row.get(column)
        if not raw:
            continue
        try:
            members = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, ValueError):
            continue
        members = [m.get("port") if isinstance(m, dict) else m for m in (members or [])]
        members = [m for m in members if m is not None]
        if members:
            found.append((selector_type, members))

    # The registration-level link. A subdomain's apex is the fact that ties
    # `help.hoster-kg.com` to `evo.hoster-kg.com` without a shared server.
    if (row.get("indicator_type") or "").startswith("domain"):
        apex = psl.apex_for_selector(row["indicator_value"])
        if apex:
            found.append(("dns.apex", apex))

    if shared_hosting:
        found = [(t, v) for t, v in found if t not in _NEEDS_DEDICATED_HOST]
    if shared_ips is not None:
        found = [(t, v) for t, v in found if not shared_value(t, v, shared_ips)]
    return found


# Columns written by the observe pass, grouped back into the shape
# observe.selectors_from expects. Reconstructing the pass and reusing that
# function is deliberate: it is the ONE place the extraction rules live -
# the CDN-edge suppression, the stock-subject demotion, the self-naming SAN
# check - and a second copy here would drift from it silently.
_OBSERVE_SOURCES = ("observe_http", "observe_tls", "observe_dns")


def _as_observe_result(rows_for_indicator: list[dict]) -> dict:
    """Rebuild an observe-shaped dict from stored observation rows."""
    http, tls, dns, whois, cdn_info = {}, {}, {}, {}, {}
    for row in rows_for_indicator:
        source = row.get("source")
        if source == "observe_http":
            http = {"status": row.get("http_status"), "title": row.get("http_title"),
                    "server": row.get("http_server"),
                    "body_sha256": row.get("body_sha256"),
                    "favicon_mmh3": row.get("favicon_mmh3"),
                    "content_type": row.get("content_type"),
                    "final_url": row.get("http_final_url"),
                    "tech": _json_list(row.get("http_tech")),
                    "headers": _json_list(row.get("http_headers"))}
        elif source == "observe_tls":
            tls = {"cert_sha256": row.get("tls_sha256"), "issuer": row.get("tls_issuer"),
                   "subject_dn": row.get("tls_subject"),
                   "sans": _json_list(row.get("tls_sans")),
                   "serial": row.get("tls_serial"),
                   "spki_sha256": row.get("tls_spki_sha256"),
                   "self_signed": row.get("tls_self_signed"),
                   "tls_version": row.get("tls_version")}
        elif source == "observe_dns":
            dns = {"a": [], "aaaa": [], "ns": _json_list(row.get("dns_ns")),
                   "mx": _json_list(row.get("dns_mx")),
                   "txt": _json_list(row.get("dns_txt"))}
            whois = {"registrar": row.get("whois_registrar"),
                     "registrant_email": row.get("whois_registrant_email"),
                     "created": row.get("whois_created")}
            if row.get("cdn_provider"):
                cdn_info = {"is_cdn": True, "provider": row["cdn_provider"]}
    return {"http": http, "tls": tls, "dns": dns, "whois": whois,
            "cdn": cdn_info, "errors": {}}


def _json_list(raw):
    if not raw:
        return []
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, ValueError):
        return []
    return value if isinstance(value, (list, dict)) else []


def backfill_observe(con: duckdb.DuckDBPyConnection) -> int:
    """Replay stored observe passes through the live extraction rules.

    Needed because the observation rows outlive the selectors: a rule change
    means the selectors should be rebuilt, and rebuilding them from the store
    costs no probe traffic at all.
    """
    columns = [r[0] for r in con.execute("DESCRIBE observations_wide").fetchall()]
    placeholders = ", ".join(f"'{s}'" for s in _OBSERVE_SOURCES)
    grouped: dict[tuple, list[dict]] = {}
    for row in con.execute(
            f"SELECT {', '.join(columns)} FROM observations_wide "
            f"WHERE source IN ({placeholders}) ORDER BY observed_at").fetchall():
        record = dict(zip(columns, row))
        key = (record["indicator_value"], record["indicator_type"],
               record["actor"], record["observed_at"])
        grouped.setdefault(key, []).append(record)

    written = 0
    for (value, indicator_type, actor, observed_at), rows_ in grouped.items():
        kind = "ip" if (indicator_type or "").startswith("ipv") else "domain"
        result = _as_observe_result(rows_)
        written += len(S.record_many(
            con, indicator_value=value,
            found=observe_source.selectors_from(result, target=value, kind=kind),
            observed_at=observed_at, indicator_type=indicator_type,
            actor=actor, source="observe"))
    return written


def backfill(con: duckdb.DuckDBPyConnection, *, dry_run: bool = False) -> dict:
    columns = ["id", "observed_at", "indicator_value", "indicator_type", "actor", "source"]
    columns += sorted(set(SCALAR_MAP) | set(LIST_MAP) | set(SET_MAP))
    available = {r[0] for r in con.execute("DESCRIBE observations_wide").fetchall()}
    columns = [c for c in columns if c in available]

    seen = con.execute("SELECT count(*) FROM observations_wide").fetchone()[0]
    written = 0
    by_type: dict[str, int] = {}

    # Which indicators sit on shared hosting, resolved once.
    shared_hosts = {r[0] for r in con.execute(
        "SELECT DISTINCT indicator_value FROM observations_wide WHERE asn IN "
        f"({', '.join(str(a) for a in SHARED_HOSTING_ASNS)})").fetchall()}
    # Addresses known to be shared hosting, from our own observations plus
    # anything whose PTR names a CDN.
    shared_ips = {r[0] for r in con.execute(
        "SELECT DISTINCT indicator_value FROM observations_wide WHERE asn IN "
        f"({', '.join(str(a) for a in SHARED_HOSTING_ASNS)})").fetchall()}
    shared_ips |= {r[0] for r in con.execute(
        "SELECT DISTINCT indicator_value FROM observations_wide "
        "WHERE ptr_hostname IS NOT NULL").fetchall()
        if is_shared_hosting_hostname(
            con.execute("SELECT ptr_hostname FROM observations_wide WHERE indicator_value = ? "
                        "AND ptr_hostname IS NOT NULL LIMIT 1", [r[0]]).fetchone()[0] or "")}
    suppressed = 0

    for row in con.execute(
            f"SELECT {', '.join(columns)} FROM observations_wide ORDER BY observed_at").fetchall():
        record = dict(zip(columns, row))
        on_shared = record["indicator_value"] in shared_hosts
        everything = extract(record)
        kept = extract(record, shared_hosting=on_shared, shared_ips=shared_ips)
        suppressed += len(everything) - len(kept)
        for selector_type, value in kept:
            normalized = S.normalize(selector_type, value)
            if normalized is None:
                continue
            by_type[selector_type] = by_type.get(selector_type, 0) + 1
            if dry_run:
                written += 1
                continue
            if S.record(con, indicator_value=record["indicator_value"],
                        selector_type=selector_type, selector_value=value,
                        observed_at=record["observed_at"],
                        indicator_type=record.get("indicator_type"),
                        actor=record.get("actor"),
                        source=f"backfill:{record.get('source')}"):
                written += 1
    if not dry_run:
        written += backfill_observe(con)
    return {"observations_read": seen, "selectors_written": written,
            "by_type": by_type, "shared_hosting_suppressed": suppressed,
            "shared_hosting_indicators": len(shared_hosts)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", type=Path, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    path = args.db or db_path()
    con = duckdb.connect(str(path), read_only=args.dry_run)
    if not args.dry_run:
        init_schema(con)

    stats = backfill(con, dry_run=args.dry_run)
    print(f"read {stats['observations_read']} observations, "
          f"{'would write' if args.dry_run else 'wrote'} {stats['selectors_written']} selectors")
    print(f"suppressed {stats['shared_hosting_suppressed']} co-hosting/resolution "
          f"selectors on {stats['shared_hosting_indicators']} shared-hosting indicators\n")
    for selector_type, n in sorted(stats["by_type"].items(), key=lambda kv: -kv[1]):
        print(f"  {selector_type:26s} {S.selector_class(selector_type):12s} {n:>6}")

    if not args.dry_run:
        links = S.shared(con)
        print(f"\n{len(links)} promotable selector value(s) shared by more than one indicator:\n")
        for link in links[:25]:
            print(f"  [{link['selector_class']:10s}] {link['selector_type']:22s} "
                  f"{str(link['selector_value'])[:34]:36s} "
                  f"{link['indicators']} indicators, {link['actors']} actor(s)")
        noisy = S.shared(con, promotable_only=False)
        suppressed = len(noisy) - len(links)
        print(f"\n  ({suppressed} further shared values suppressed as behavioural/contextual - "
              f"the Server-header and issuer noise)")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
