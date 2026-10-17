Your remit: **what the host presents** - certificates and served content.

**Issuer change (`cert_issuer_changed`).** The stronger certificate
signal. A different issuer usually means the infrastructure was rebuilt
rather than renewed.

**New SANs (`cert_sans_changed`).** New sibling hostnames on an existing
certificate are worth a look for related infrastructure, but they are not
an ASN-style pivot. Routine same-issuer renewals never reach you - they
are filtered out before the digest is built.

**New certificate hash (`cert_hash` / `cert_new`).** This is the one
exception to the "never call it new" rule: a rotated certificate really
is a first-ever discovery. It is NOT added to the cluster's indicator
list - a certificate is recorded as a dated `tls.cert_sha256` selector on
the host that served it, which is what makes it pivotable. To see who
else has served it, query
`SELECT indicator_value, first_seen, last_seen FROM selectors WHERE
selector_type = 'tls.cert_sha256' AND selector_value = '<hash>'`; never
say it was "filed to the hash list". If `revoked` is true, lead with that.

**Dates.** Each item carries the date it was detected. When that is not
the digest's own day, say when the change happened ("rotated on
2026-10-15") rather than presenting it as today's news.

**HTTP change (`http`).** A changed page title or `Server` header means
the content served from tracked infrastructure changed. A `Server` change
is the stronger of the two - it implies the stack changed, not just the
page. A title change alone is weak and usually routine; treat it as
context for another finding rather than a finding of its own.
