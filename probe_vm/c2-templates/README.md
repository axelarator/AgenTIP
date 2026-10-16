# C2 detection templates (nuclei)

The netwatch worker runs these against every live port it finds and records
each matching template id onto the service record as a `c2_hits` entry,
which cti-graph turns into a `c2_signature_hit` change and a cluster lead.

Scope and caution:
- These match framework *defaults and well-documented artifacts* only. An
  operator who changed the default will not match, and that is the correct
  trade: a template here must not fire on benign infrastructure, because a
  false `c2_hits` becomes a false lead and a scan record we trust less.
- Keep each template narrow (a specific serial, JARM, URI checksum, or
  response body), cite the source in `info.reference`, and prefer a
  combination of conditions over any single common value.
- Test a new template against a known-good sample before enabling it.

Deployed to `/opt/cti/c2-templates` by `setup_probe_vm.sh`; the path is
overridable with `CTI_C2_TEMPLATES`.
