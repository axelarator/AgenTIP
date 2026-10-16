---
name: infrastructure-pivoting
description: Use when asked who else shares an indicator's certificate, page, favicon, nameservers, registrant or address; when deciding whether two hosts are the same operation; when reading the digest's "Corroborated infrastructure links" section or the selectors/selector_stats tables; or when a request says "pivot" or "probe" on a cluster's infrastructure — those two are defined terms here and mean different traffic. Provides the selector taxonomy, the corroboration rule that promotes a link, the rarity bar, and a per-selector playbook of what each shared value proves and what it never proves.
---

# Infrastructure pivoting

Everything else in this system asks *what changed about this host*. This
skill is the other question: **who else has this?**

The two are not variations on each other. A change is observed on one
indicator and compared to its own past. A link is a value two indicators
hold in common, and it is what turns a list of IOCs into a campaign.

## The one rule

A candidate link is **promoted** when either:

- **one identity fact** matches, or
- **two independent structural facts** match.

A *fact* is one thing you looked at, not one column it filled. Two SANs
off one certificate are one fact; so are that certificate's hash, serial,
subject and public key. Independence is counted per **artefact** —
`certificate`, `page`, `address`, or the selector's own type when it
belongs to no group — because a certificate contains its serial and an
address determines its PTR, so sharing the one guarantees sharing the
other.

This is not a refinement of the SAN rule, it *is* the SAN rule. It was
written down for SANs and applied only there, so a link carrying
`tls.cert_sha256`, `tls.spki_sha256` and `tls.serial` read as three
independent facts when it is one certificate seen once — and adding the
SPKI digest inflated every certificate link by one more.

Behavioural and contextual selectors are recorded beside a finding. They
never promote one, whatever their number. That is not a style
preference: it is the guard against building a finding on `Server:
cloudflare`, which eight of this repo's own indicators share.

**The rule already ran before you see anything.** `cti/store/expand.py`
applies it in code, and the digest's "Corroborated infrastructure links"
section is its output. Your job is never to decide whether the link
exists — it is to say what the link *means*: one operator's rotation,
one provider's tenants, one kit deployed by several people, or a real
campaign.

## Two gates the rule sits behind

**Class caps what a TYPE can prove.** Fixed once, in
`cti/store/selectors.py`, and it cannot be argued up by a good story.

**Rarity caps what a VALUE can prove.** `ns1.evil-actor.com` and
`ns1.cloudflare.com` are the same type and mean completely different
things. Three checks, and a value failing any one of them cannot
promote:

- a vendored list of mass DNS providers (`mass_dns_providers.txt`),
- a vendored list of CDN ranges, fail-closed: when `cdncheck` errors the
  address is treated as a CDN, never as dedicated,
- a global count from Webamon — how many scans index-wide share the
  value. Above 10,000 it describes the internet, not an operator. This
  is the only one that can catch a value no list could have named in
  advance: a DOM digest on 17 million sites, say.

None of the three is sufficient alone, and two live false positives got
through gaps between them — see "What has actually gone wrong" below.

<!-- BEGIN GENERATED TAXONOMY -->

## What each selector proves

_Generated from `cti/store/selectors.py` by `scripts/render_selector_skill.py`. Do not edit by hand: the code is the authority and a test checks this block against it._

### identity — one is enough

A content or key digest. Two hosts holding the same one did not arrive there by coincidence; they were configured from the same source.

- **`file.sha256`** — the same file was staged on both hosts.
  - *Never:* that both hosts are adversary-controlled - it may be a common tool.
- **`http.body_sha256`** — byte-identical response bodies: the same page is being served. The strongest rotation-proof link there is, because it survives the domain, the IP and the provider all changing.
  - *Never:* anything at all when the body is an empty response, a default nginx or Apache welcome page, or a shared CDN error page.
- **`http.favicon_mmh3`** — the same favicon - typically the same panel, kit or product build.
  - *Never:* operator identity for a widely deployed product's stock favicon.
- **`tls.cert_sha256`** — the same leaf certificate is installed on both hosts - the operator copied a keypair, so they share a deployment.
  - *Never:* that the hosts are the same machine, or that the cert is not shared hosting boilerplate - check the issuer and rarity first.
- **`tls.spki_sha256`** — the same public key across certificates - the operator reused a keypair when reissuing, so it holds where tls.cert_sha256 and tls.serial both change. Computed locally from the certificate; tlsx has no SPKI output and reading one from it left this selector empty for its whole existence.
  - *Never:* anything when the key belongs to a hosting provider's shared certificate - and note that neither index can reverse-look-up an SPKI digest, so this is the one identity selector that can never be priced. It rests on its class and the local gates alone.
- **`webamon.fp_dom`** — Webamon's DOM digest matches - the same rendered page, as their scanner normalizes it. Survives the cosmetic edits that change a raw body hash.
  - *Never:* the same thing as http.body_sha256. It is a different digest over a different input: example.com's body hashes to ff67a9d7... while its fingerprint.dom is f4726eb4..., so the two never match and must never share a selector type.
- **`webamon.fp_ssl`** — Webamon's certificate digest matches. Rare by construction - example.com's value returns 2 scans index-wide.
  - *Never:* comparability with tls.spki_sha256 or tls.cert_sha256; it is their hash over their own extraction, matchable only against itself.

### structural — two independent ones promote

Configuration and registration facts. Coincidence is possible, which is why two are needed, of different types.

- **`dns.apex`** — subdomains of one registered domain. This is the registration-level link: separate hosts, separate servers, one purchase.
  - *Never:* a shared server - and nothing at all on a domain that sells subdomains to the public.
- **`dns.mx_set`** — the same mail-exchanger set - the same mail provider and usually the same account. Rarer than an NS set, because most malicious domains publish no MX at all.
  - *Never:* a link on a mass provider's MX (Google, Microsoft, Zoho).
- **`dns.ns_set`** — the same nameserver set - the same DNS provider and often the same account.
  - *Never:* a link when the nameservers belong to a mass provider such as Cloudflare.
- **`dns.soa_email`** — the same zone contact address.
- **`net.resolved_ip`** — both names resolve to the same address.
  - *Never:* co-tenancy on shared hosting, which is not a link - check cdncheck or the ASN first.
- **`net.reverse_dns`** — the same PTR hostname - often the same physical or virtual host.
- **`tls.san`** — both hosts appear on a certificate naming the other - the operator requested them together.
- **`tls.serial`** — the same certificate serial from the same issuer - a reissue of one certificate rather than two independent ones.
- **`tls.subject_cn`** — certificates issued for the same name.
- **`webamon.fp_cert_san`** — the same SAN list, as one digest. Stronger than a single shared SAN: it means both certificates name exactly the same set of hosts.
- **`webamon.fp_dom_structure`** — the same DOM structure with the text changed - how a cloned kit is recognised after the operator edits the branding. This is the selector for the source reporting's cloned decoy page.
  - *Never:* the same page: every site built from one template shares it, which is why it is structural and not identity.
- **`webamon.fp_domains`** — the page loads resources from the same set of domains - the same kit's backend and CDN choices.
- **`webamon.fp_mx_set`** — Webamon's digest of the mail-exchanger set.
- **`webamon.fp_ns_set`** — Webamon's digest of the nameserver set.
  - *Never:* a link on a mass provider - the same caveat as dns.ns_set, and the rarity gate cannot read a digest, so check the plaintext set too.
- **`whois.registrant_email`** — the same registrant contact registered both domains.

### behavioural — corroborates, never promotes

How the service behaves. Distinctive in combination, individually shared by every host running the same stack.

- **`flow.app_proto`** — FlowCarp classed a session to both as the same application protocol from its statistics alone - most useful on a port where nothing parsed a banner.
  - *Never:* a link on a common protocol. Only non-generic labels are recorded; 'tls' or 'http' on a web port is what every host says.
- **`http.client_divergence`** — the server answers a Windows client differently from a scanner - a different status class, title, certificate or landing host when win116 asks than when the probe does. Payload gating: the real file for a victim's machine, a decoy or a 404 for everyone else. The value names what diverged, so two hosts gating the same way share it.
  - *Never:* operator identity, and not a verdict on its own: a CDN's bot challenge or a geo rule can diverge too. Read it beside what each client was actually served.
- **`http.error_page_sha256`** — both hosts serve the same error page. Weak, but not nothing: the same origin-down page from the same CDN is a statement about shared hosting, and an unusual custom error page can be a real tell.
  - *Never:* a link, and especially not a shared deployment. Cloudflare's 521 'Web Server Is Down' page promoted three domains under three different registrations before this type existed, because a body hash was recorded whatever the status code said.
- **`http.header_order`** — the response headers arrive in the same ORDER - a property of the server build and proxy chain rather than its configuration, the HTTP analogue of JARM. Our own collection; webamon.fp_header_order is the same idea as a third party's digest.
  - *Never:* anything off a CDN, and a link on a stock server: every default nginx of one version sends the same order.
- **`http.header_set`** — the same unusual response-header combination - typically the same server build or reverse proxy config. Standard headers (date, content-type, caching, security headers) are dropped before the set is formed, so what is left is the part an operator or kit added.
  - *Never:* anything off a CDN: the edge writes its own headers.
- **`http.title`** — the same page title. Weak alone, useful when the title is itself distinctive and the body hash differs only by a timestamp.
- **`net.cohosted_domain`** — a third-party index sees both names on one address. Corroborates a link established some other way; on its own it is a statement about the hosting, not the operator.
  - *Never:* a link on shared hosting, where every pair of addresses shares thousands of tenants. Backfilling it without that gate produced 5320 selectors from this repo's own data, nearly all Cloudflare tenants.
- **`net.historical_ip`** — both names resolved to the same address at some point in passive DNS history - which is how infrastructure reuse survives a rotation that current resolution no longer shows.
  - *Never:* co-residence. Two domains on one address four years apart share nothing; only overlapping first/last-seen windows make it a lead, which is why this is not net.resolved_ip.
- **`net.passive_port_set`** — a third-party scan index saw the same open-port pattern on both. Useful because nobody had to send a packet for it.
  - *Never:* the ports that are open NOW. The observation is someone else's, at an unknown time, so it can corroborate a link and must never be confused with net.port_set, which nmap confirmed.
- **`net.port_set`** — the same open-port pattern. Unusual high ports are the interesting case - the source reporting keyed on RDP-over-TLS at 64350, 64330, 65535 and 65111.
  - *Never:* a link on a common set such as 22/80/443.
- **`ssh.hassh_server`** — the same SSH server build and crypto configuration (HASSH of the server's KEXINIT).
  - *Never:* operator identity: a default OpenSSH on one distro release is everywhere.
- **`tls.default_subject`** — the same stock certificate subject - a self-signed cert left at its install-time defaults. Identifies the software build, the way JARM does, and is genuinely useful: two tracked hosts carrying the same one are running the same tool.
  - *Never:* operator identity. Every unconfigured deployment of that software shares it, so it corroborates a link and cannot make one.
- **`tls.ja3s`** — the older, coarser server-hello digest - the same TLS library and settings answering the client tlsx sends.
  - *Never:* operator identity, and it is not comparable with tls.ja4s.
- **`tls.ja4s`** — the server side of the handshake matches: the same TLS version, cipher and extension choices in reply to the same client hello.
  - *Never:* operator identity. Read passively from Zeek (ssl.log) for a session our own probe opened; never filled from a JA3S value, which was stored here by mistake until netwatch and could not match anything.
- **`tls.ja4ts`** — the same TCP stack answering the SYN - window size, options and their order, so the same OS and kernel tuning.
  - *Never:* a link on a stock OS: every default Ubuntu host shares it.
- **`tls.ja4x`** — the certificate was generated the same WAY - the same issuer and subject field order and the same extensions, which is a property of the tool or script that minted it (a C2 framework's default cert, a kit's generator), not of the names in it.
  - *Never:* a link between operators: every Let's Encrypt certificate shares a handful of values, so this means something only off a self-signed or private-CA certificate.
- **`tls.jarm`** — the same TLS stack and configuration - consistent with the same C2 family or the same build.
  - *Never:* operator identity: JARM identifies software, not owners.
- **`webamon.fp_cert_config`** — the same certificate configuration - key type, extensions, validity window shape.
  - *Never:* a link: 1.3 million scans share example.com's value.
- **`webamon.fp_cert_issuer`** — the same issuer, as a digest.
  - *Never:* a link - the plaintext form is tls.issuer, which is contextual for the same reason.
- **`webamon.fp_cookie_names`** — the same cookie names - usually the same application or panel.
- **`webamon.fp_header_order`** — the response headers arrive in the same ORDER, which is a property of the server build and proxy chain rather than its configuration - the HTTP analogue of JARM.
- **`whois.registrar`** — both registered through the same registrar - worth noting beside a stronger link, since a bulk-registering operator tends to stay with one registrar.
  - *Never:* a link on its own: registrars have millions of customers. This was classed structural while its own description said otherwise, and NameSilo duly appeared as a six-indicator 'link' in a live sweep.

### contextual — describes only

Structurally unable to promote a candidate, no matter how many indicators share the value.

- **`brand.impersonated`** — both names are lexically close to the same brand - which is a statement about the lure, not the operator.
  - *Never:* a link, ever. Every phishing kit targeting one brand shares it; 1962 scans match 'microsoft'. It is here to be displayed beside a finding, and would have labelled update-sentinelone.com on sight.
- **`http.server`** — the same Server header.
  - *Never:* a link, ever. Even a specific version string such as nginx/1.29.3 matches more than 10,000 hosts on a public index.
- **`http.tech`** — the same detected technology.
- **`net.asn`** — hosted in the same autonomous system.
  - *Never:* a link. Millions of hosts share an ASN; this is background.
- **`net.country`** — hosted in the same country.
- **`net.cpe`** — a scan index fingerprinted the same product and version on both.
  - *Never:* a link: a CPE names software, and popular software is everywhere.
- **`net.prefix`** — the same announced prefix - tighter than an ASN, still shared infrastructure.
- **`tls.issuer`** — certificates from the same CA.
  - *Never:* a link: almost everything is Let's Encrypt.
- **`tls.multi_san_cert`** — both hosts present a certificate naming about as many hosts - which says they are behind hosting of a similar shape.
  - *Never:* a link. It is recorded in place of the SAN list when a certificate names more than MAX_OPERATOR_SANS hosts, so that a provider's certificate cannot manufacture dozens of structural selectors.
- **`webamon.fp_asn`** — the same set of ASNs served the page's resources.
  - *Never:* a link: 6.8 million scans share example.com's value.
- **`webamon.fp_cookies`** — the page sets the same cookies, values included.
  - *Never:* a link: 48.8 million scans share example.com's value.
- **`webamon.fp_links`** — the same outbound link set.
  - *Never:* a link: 2.9 million scans share example.com's value.
- **`webamon.fp_scripts`** — the page loads the same set of scripts.
  - *Never:* a link: 17.8 million scans share example.com's value.
- **`webamon.fp_tech`** — the same detected technology set.
  - *Never:* a link: 22 million scans share example.com's value.

<!-- END GENERATED TAXONOMY -->

## Time, scores and hunting

A shared value is a link only if the two holders had it **at the same
time**. Every selector is stored with the spans in which it was observed
(passive DNS keeps its own record windows), and the relatedness score
(`cti/store/relatedness.py`) weighs each shared artefact by class x rarity
x time overlap: identity 0.85, structural 0.56, behavioural 0.12 (all
behavioural facts together capped at 0.35, inside `weak`), contextual 0.
A gap decays the weight - 30 days for addresses, 180 for content and
key digests. Artefacts combine as `1 - prod(1 - w)`, so the rule above
holds: one rare identity fact, or two independent structural ones,
lands in `strong`. Anything measured on a CDN edge weighs nothing; a
default or catch-all certificate counts as behavioural.

The case this exists for: kakatown.com sat on 192.252.186.62 from 2019-08
to 2020-08, and the JadeProx vendor trio arrived there in 2026-04. Same
address, 2,270 days apart: `noise`.

**Hunting** - `hunt_query` (MCP), `python -m graph hunt '<query>'`, or the
dashboard's Hunt page. Censys-style `key:value` terms over everything the
store has observed, with AND / OR / NOT / parentheses:

    tls.default_subject:* AND net.port:8443 AND NOT role:rejected
    (net.resolved_ip:192.252.186.62 OR net.historical_ip:192.252.186.62) during:[2026-01-01,2026-12-31]
    cluster:jadeprox role:candidate band:probable
    changed:tls.cert_sha256 since:7d

Keys are selector types plus `net.port`, `indicator`, `type`, `cluster`,
`role`, `band`, `vantage`, `changed`; `seen:` / `during:` set the time
window. A hit says an indicator carried a value. `hunt_pairs(a)` says
what `a` is most like across the whole store, scored pairwise;
`hunt_pairs(a, b)` lists what two indicators share, when, and what it is
worth. A hunt rule file can carry the same syntax as `query:`.

## Pivoting vs. probing

These are different operations against someone else's infrastructure and
a request's wording does not reliably distinguish them.

**Pivot** — `pivot_observable`, `pivot_cluster`, `pivot_and_expand`, and
everything in this skill. Passive lookups (RDAP, RIPEstat, Webamon,
ThreatFox, HoneyLabs, subfinder/Wayback) plus a light-touch live check
from the probe VM: DNS, one ordinary TLS handshake, one HTTP GET. The
same traffic any visitor generates, nothing crafted. **Runs
automatically**; no need to wait for a separate ask.

**Probe** — a JARM scan (deliberately malformed ClientHellos), the
fingerprint-queue pipeline, or `active_scan`'s nmap / dirsearch paths.
Crafted or loud traffic, routed exclusively through the lab probe VM.
**Only when explicitly asked**, and never as a default follow-up to a
pivot.

If a request says "probe" with no other context, that alone means the
active pipeline — do not downgrade it to a lookup because a lookup is
faster. Conversely, "pivot on infrastructure" that clearly means
fingerprinting (JARM/JA4 named, a vantage point named) is a probing
request. Confirm only if still ambiguous after applying this rule.

The build, the runbook and the failure history for the probe VM are in
`docs/probe-vm.md`, not here.

## Validin is manual-only

`validin_*` tools are capped at **10 lookups a day and 50 a month**, and
the monthly cap is the binding one. They are never reachable from the
sweep or the graph — two independent gates enforce that — and every
lookup needs a stated reason.

Spend one only on something nothing else can answer:

- `tls.cert_sha256` — Webamon publishes no leaf-certificate digest,
- `whois.registrant_email` / `whois.registrar` — Webamon's index carries
  no registration data at all,
- passive DNS history and CT history — no CLI on the probe VM does
  either, and crt.sh no longer ingests.

Call `validin_status` first. For everything else use Webamon, which is
effectively unmetered by comparison.

## What has actually gone wrong

Each of these promoted a link that was not one, on real data in this
repo. They are here because the shape recurs, not as trivia.

**A CDN error page.** Three domains under three *different*
registrations shared a body hash — the strongest shape of link this
system can report. The page was Cloudflare's 521 "Web Server Is Down".
The bytes were the CDN's, not the operator's. Rarity could not catch it:
that hash is on 103 scans index-wide. A body hash is now only recorded
when the status says a page was served.

**A provider's certificate.** One Aliyun OSS host contributed 58 SAN
selectors and one Azure blob host 53, out of 148 in the whole table. Any
two tenants behind either shared dozens of "structural" links. Above 16
SANs a certificate is a provider's, and only a count is recorded.

**A registrar.** NameSilo appeared as a six-indicator link because
`whois.registrar` was classed structural while its own description said
it was useful only as a second selector.

**A free DNS provider.** `ns1/2/3.dnsowl.com` — NameSilo's free DNS —
was recorded as three separate structural links. A nameserver *set* is
one selector whose value is the whole set, never one per member.

**A generic page.** Two domains shared a body hash and were promoted.
The page is on 37,333 scans index-wide. The global count caught this one.

The common shape: **a value that is genuinely identical and genuinely
means nothing**, because something other than the operator put it there.
Before believing a link, ask who chose that value — the operator, or
their hosting provider.

## Reading the evidence

A link's strength is not only its selectors. **A shared value across
different registered domains is worth more than the same value across
one.** Two subdomains of one apex sharing a certificate is a wildcard
cert doing its job. Two separately registered domains sharing a *leaf*
certificate is one operator.

`held_back` on a link item is how many candidates the rule declined. A
day with 2 promoted and 206 held back is a working filter, not a missed
campaign — say so rather than treating the ratio as a gap.
