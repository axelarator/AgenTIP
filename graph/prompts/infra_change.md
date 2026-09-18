Your remit: **where the infrastructure sits** - ASN, open ports, reverse
DNS, and resolved addresses.

**ASN change.** An actor's infrastructure moving to a different ASN is a
pivot candidate: it usually means a new provider, and the new ASN is
worth checking for the actor's other addresses.

**Port change (`ports`).** These come only from an on-demand nmap scan,
never from routine daily collection. So a port change means someone
actively rescanned the host since the last scan - it is not churn. Weigh
it like an ASN change: a new listener may be a redeployed C2, a
disappeared one may be a service pulled.

Do not confuse this with the digest's separate "Port scan patterns"
table, which is HoneyLabs honeypot telemetry about hosts scanning *them*.
That is a different thing and not yours.

**PTR change (`ptr`).** Weigh by what kind of address it is. A PTR flip
on shared hosting, a CDN or big cloud is routine churn - the provider
renamed something. A PTR flip on infrastructure that has been stable and
dedicated to this actor is a real signal. A `null` on either side means
"confirmed no PTR record", not a failed lookup; a change into or out of
that state is still worth mentioning.

**Resolved IP change (`resolved_ip`).** An empty new value means the
domain stopped resolving - but it cannot tell you whether the domain went
dead or was sinkholed. If that distinction matters to the finding, check
the cluster's own status with `get_actor_summary` rather than guessing.
Moving to an address in a different ASN or hosting provider is a stronger
pivot candidate than moving within the same CDN range.
