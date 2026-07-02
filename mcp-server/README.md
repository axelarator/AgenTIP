# cti-tools

Self-hosted MCP server + CLI for threat cluster tracking. No external
API calls — everything is local JSON under `../data/clusters/` (shared
at the repo root so every harness surface sees the same store), with a
regenerated markdown view alongside each. `core.py` is the single
source of truth; `stix.py`, `server.py`, and `cli.py` are thin surfaces
over it, which is what makes the same tool behave identically whether
it's called over MCP, over Bash, or exported as STIX.

## Install

From the repo root:

```bash
./setup.sh
```

or manually:

```bash
cd mcp-server
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[test]'
```

Cluster data is read/written under `<repo root>/data/clusters/` by
default (computed relative to `core.py`'s location). Override with the
`CTI_DATA_DIR` environment variable if you want clusters stored
somewhere else — e.g. a separate private repo, or an isolated directory
for tests (the test suite does this automatically via a fixture).

## Run tests

```bash
cd mcp-server && source .venv/bin/activate
pytest
```

## Run standalone (sanity check)

```bash
python -m cti_tools.cli create-cluster "Fox Tempest" --description "..."
python -m cti_tools.cli update-profile "Fox Tempest" --adversary "unattributed" --confidence 40
python -m cti_tools.cli update-ttp "Fox Tempest" T1553.002 "Subvert Trust Controls: Code Signing" 3 --notes "..."
python -m cti_tools.cli export-navigator "Fox Tempest"
python -m cti_tools.cli export-stix "Fox Tempest"
```

## Wiring into each harness

**Claude Code** — native MCP support. `.mcp.json` at the repo root
(written by `setup.sh`) already points at
`mcp-server/.venv/bin/python -m cti_tools.server` with `cwd` set to
`mcp-server`. Drop `skills/threat-cluster-tracking/` into
`.claude/skills/`.

**GitHub Copilot (VS Code)** — MCP support lives in VS Code's own MCP
settings (`Cmd/Ctrl+Shift+P` → "MCP: Add Server"). Point it at the same
interpreter/args as `.mcp.json` uses. Skills go wherever your VS Code
Copilot build reads Agent Skills from — check `docs.github.com` for the
current path, it's moved a couple of times.

**Pi** — core Pi's loop is deliberately Read/Write/Edit/Bash only, no
built-in MCP client. Two options:

1. If you're on `oh-my-pi` or another fork/extension with MCP support,
   wire it the same way as above.
2. Otherwise, skip MCP entirely for Pi and let the skill drive the CLI
   directly through the Bash tool — that's why `cli.py` exists as a
   parallel surface, not an afterthought. `.pi/skills/threat-cluster-tracking/`
   is already populated; Pi reads the CLI usage straight out of its
   `SKILL.md`.

### Why `.mcp.json` uses absolute paths, not `${workspaceFolder}`

Not every MCP client expands workspace-relative variables the same way
(or at all) for stdio server configs, and a wrong assumption here fails
silently as "server won't start" with little signal. `setup.sh` bakes in
absolute paths for your actual checkout instead. Re-run it if you move
or re-clone the repo.

### Providers

Point Pi (or any harness) at Ollama for local runs:

```bash
pi --provider ollama --model qwen3.5:9b
```

and swap to `--provider anthropic` (Claude subscription) when a task
needs frontier-level reasoning (multi-step TTP correlation, ambiguous
cluster merges) that the local model is thrashing on. Because both
providers drive the exact same skill and tool surface, that swap is the
cleanest isolated model-effect comparison you can run — harness and
capabilities held constant, only the model changes.

## STIX 2.1 export/import

`export_stix_bundle` / `cti export-stix` renders a cluster as a STIX 2.1
`bundle`:

- one **Intrusion Set** (the cluster itself — name, description,
  aliases, confidence is *not* a native Intrusion Set property so it
  stays local-only, first_seen, last_seen),
- one **Attack Pattern** per TTP entry, keyed to its ATT&CK technique ID
  via `external_references` (`source_name: mitre-attack`), plus a
  non-standard `x_cti_agent_coverage_status` custom property carrying
  the 0-4 coverage score,
- one **Relationship** (`uses`) per TTP, linking the Intrusion Set to
  its Attack Pattern, carrying the TTP's notes as its description,
- one **Note** per hunt log entry, linked back to the Intrusion Set.

The Intrusion Set's STIX id is minted once at cluster creation and
persisted (`stix_id` in the cluster JSON), so re-exporting the same
cluster always yields the same id — a receiving system can tell it's an
update, not a duplicate. Attack Pattern ids are derived deterministically
from the ATT&CK technique ID (UUIDv5 under a fixed namespace in
`stix.py`), so the same technique gets the same id across every cluster
and every export, without needing MITRE's own STIX corpus bundled in.

`import_stix_bundle` / `cti import-stix` does the reverse: given a
bundle with at least one Intrusion Set, it creates a new cluster (or
merges into an existing one with `--overwrite`, unioning in TTPs and
appending hunt log notes without touching existing detections/gaps).

This is hand-rolled JSON, not the `stix2` library — the object graph is
small and a hard dependency on a validating library isn't worth it for a
tool whose whole design point is "no external services, minimal deps."
If a downstream consumer needs strict spec validation, run the exported
bundle through `stix2validator` before sharing it.

## Report ingestion

`ingest_report(source, cluster_name=None)` / `cti ingest-report <source>`
fetches a threat report (URL or local file — `report_ingest.py` strips
HTML to text; PDFs aren't supported yet, extract text first e.g. with
`pdftotext`) and regex-extracts hashes (md5/sha1/sha256), domains, IPs
(private/reserved ranges filtered out), URLs, and ATT&CK technique IDs.
Extracted data is filed into a cluster — created automatically if it
doesn't exist — with observables deduped by value (repeats just add a
new source to that observable's provenance) and new TTPs added at
coverage status 0 without ever touching an already-tracked TTP's
status/notes.

If `cluster_name` is omitted, it's inferred from the report text via a
few vendor-style naming regexes (Microsoft weather names, CrowdStrike
animal names, Mandiant/Proofpoint numbered clusters, or a name next to
"ransomware"/"malware"/etc.). This is a heuristic, not attribution —
zero or multiple candidates raises rather than guessing wrong. Use
`analyze_report` / `cti analyze-report <source>` to preview extraction
and candidate names without writing anything first.

`get_observables(name)` / `cti get-observables <name>` returns just the
hashes/domains/ips/urls tracked for a cluster (with provenance and
first/last seen) plus the list of report sources ingested — the fast
path to "what's tied to this cluster" instead of the full cluster dump.

## Extending toward Censys / hunt.io / Validin

Add new functions to `core.py` (e.g. `censys_query(cert_hash)`), mirror
them as a tool in `server.py` and a subcommand in `cli.py`, and mention
them in the skill's "Tool availability" section. Keep API keys out of
this repo — read them from environment variables in `core.py`, never
hardcode them, and don't let a skill or MCP tool description reference a
literal key value.
