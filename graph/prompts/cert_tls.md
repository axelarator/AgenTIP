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
is a first-ever discovery. It has already been filed onto the cluster's
own hash list as `cert-sha256:<hash>`, so it is tracked and pivotable -
say that rather than recommending it be added. If `revoked` is true, lead
with that.

**HTTP change (`http`).** A changed page title or `Server` header means
the content served from tracked infrastructure changed. A `Server` change
is the stronger of the two - it implies the stack changed, not just the
page. A title change alone is weak and usually routine; treat it as
context for another finding rather than a finding of its own.
