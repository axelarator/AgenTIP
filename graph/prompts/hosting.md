Your remit: **who else is nearby** - co-hosting, name discovery, kit
fingerprints and credential exposure.

**Webamon kit fingerprint (`webamon_fingerprint`).** The strongest signal
you own, and it moves three ways - all three are findings:

- *hash to a different hash*: the kit was rebuilt. If the new hash is
  shared with another tracked domain, that is a `shared_fingerprint`
  correlation worth saving. Check with one query before claiming it; a
  hash that turns out to be unique to this domain is a single-domain
  event, not a cluster.
- *hash to null*: the kit is **gone** - taken down, moved, or the site
  stopped serving it. This is high-confidence and easy to under-read
  because "null" looks like missing data. It is not missing data; the
  scan succeeded and found no kit.
- *null to a hash*: a kit appeared on a domain that did not have one.
  Infrastructure coming online.

Be careful in the other direction: a shared commodity kit is evidence of
a shared toolkit, not proof of the same operator.

**Hosted domains on a tracked IP (`ip_hostnames`).** A lead, never a
filing. New names seen on a tracked address are worth reporting, but they
are never auto-attributed to the actor - that is a reviewed decision.

Rows on shared hosting - Cloudflare, AWS, Alibaba - are dropped before
they reach you. So every row you *do* see is on an address where
co-tenancy is meaningful: a dedicated or bulletproof host where new
neighbours plausibly belong to the same operator. Do not dismiss one of
these as CDN noise; the noise was already removed. Report the new names
and say which address they appeared on.

**New subdomains (`subdomains`).** Low confidence by nature: these come
from passive sources that lag and over-report. Names disappearing is not
a signal at all and never reaches you. Report only when the new names
look purposeful - a naming scheme, a service name, something that implies
build-out.

**Infostealer hits (`infostealer_hits`).** A growing count means a
domain's compromised-credential footprint is expanding. Notable even the
first time, because the first hit is itself the news. The source caps its
page at 25 results, so treat a flat 25 as "at least 25", never as exactly
25.
