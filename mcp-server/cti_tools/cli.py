"""CLI wrapper around core.py.

For harnesses that don't speak MCP natively — vanilla Pi's core loop is
just Read/Write/Edit/Bash, so it drives these tools by invoking this CLI
through the Bash tool, guided by the SKILL.md playbook. Same JSON store
as server.py, so output is identical regardless of which harness ran it.

Usage:
    python -m cti_tools.cli <command> [args...]
"""
from __future__ import annotations

import argparse
import json
import sys

from . import core
from .report_ingest import UnsupportedSource


def _print(obj) -> None:
    print(json.dumps(obj, indent=2))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cti")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list-clusters")

    g = sub.add_parser("get-cluster")
    g.add_argument("name")

    c = sub.add_parser("create-cluster")
    c.add_argument("name")
    c.add_argument("--description", default="")

    pr = sub.add_parser("update-profile")
    pr.add_argument("name")
    pr.add_argument("--description")
    pr.add_argument("--adversary")
    pr.add_argument("--capability")
    pr.add_argument("--infrastructure")
    pr.add_argument("--victim")
    pr.add_argument("--aliases", help="comma-separated list, replaces existing")
    pr.add_argument("--confidence", type=int)
    pr.add_argument("--first-seen")
    pr.add_argument("--last-seen")

    u = sub.add_parser("update-ttp")
    u.add_argument("name")
    u.add_argument("technique_id")
    u.add_argument("technique_name")
    u.add_argument("status", type=int)
    u.add_argument("--notes", default="")

    h = sub.add_parser("append-hunt-log")
    h.add_argument("name")
    h.add_argument("entry")

    d = sub.add_parser("add-detection")
    d.add_argument("detection_id")
    d.add_argument("description")
    d.add_argument("technique_ids", help="comma-separated ATT&CK technique IDs this detection covers")
    d.add_argument("status", nargs="?", default="draft")
    d.add_argument("--cluster", help="cluster this investigation came from (optional provenance); "
                                      "also returns that cluster's refreshed view")

    tu = sub.add_parser("get-technique-usage")
    tu.add_argument("technique_id", nargs="?", default=None,
                     help="omit for the full matrix across every tracked technique")

    rel = sub.add_parser("add-relationship")
    rel.add_argument("name")
    rel.add_argument("relationship_type", help='e.g. "uses", "related-to"')
    rel.add_argument("target_cluster")
    rel.add_argument("--description", default="")
    rel.add_argument("--source", default="")

    gap = sub.add_parser("add-gap")
    gap.add_argument("name")
    gap.add_argument("description")
    gap.add_argument("priority", nargs="?", default="medium")

    n = sub.add_parser("export-navigator")
    n.add_argument("name")

    obs = sub.add_parser("get-observables")
    obs.add_argument("name")

    fo = sub.add_parser("find-observable")
    fo.add_argument("value", help="hash (with or without algo prefix), domain, ip, or url")

    po = sub.add_parser("pivot-observable")
    po.add_argument("value", help="hash, domain, ip, or url to pivot on via RDAP/RIPEstat/VirusTotal")

    pc = sub.add_parser("pivot-cluster")
    pc.add_argument("name", help="cluster whose domains/ips get a lifecycle status sweep")

    pe = sub.add_parser("pivot-and-expand")
    pe.add_argument("value", help="domain or ip to pivot and expand from")
    pe.add_argument("cluster_name", help="existing cluster to file new indicators onto")
    pe.add_argument("--include-cohosted", action="store_true",
                     help="also file reverse-IP co-hosted domains (shared-hosting noise by default)")

    aob = sub.add_parser("add-observable")
    aob.add_argument("name")
    aob.add_argument("category", choices=list(core.OBSERVABLE_CATEGORIES))
    aob.add_argument("value")
    aob.add_argument("source")

    rob = sub.add_parser("remove-observable")
    rob.add_argument("name")
    rob.add_argument("category", choices=list(core.OBSERVABLE_CATEGORIES))
    rob.add_argument("value", help="matched case-insensitively; for hashes, with or without algo prefix")

    ar = sub.add_parser("analyze-report")
    ar.add_argument("source", help="URL or local file path")

    ir = sub.add_parser("ingest-report")
    ir.add_argument("source", help="URL or local file path")
    ir.add_argument("--name", help="cluster name; inferred from the report if omitted")
    ir.add_argument("--no-create", action="store_true",
                     help="fail instead of creating a new cluster if none matches")

    es = sub.add_parser("export-stix")
    es.add_argument("name")

    ee = sub.add_parser("export-stix-ecosystem")
    ee.add_argument("name")

    ims = sub.add_parser("import-stix")
    ims.add_argument("bundle_path", help="path to a STIX 2.1 bundle JSON file, or '-' for stdin")
    ims.add_argument("--name", help="override the cluster name (default: Intrusion Set name)")
    ims.add_argument("--overwrite", action="store_true",
                      help="merge into an existing cluster instead of failing")

    args = p.parse_args(argv)

    try:
        if args.command == "list-clusters":
            _print(core.list_clusters())
        elif args.command == "get-cluster":
            _print(core.get_cluster(args.name))
        elif args.command == "create-cluster":
            _print(core.create_cluster(args.name, args.description))
        elif args.command == "update-profile":
            aliases = args.aliases.split(",") if args.aliases is not None else None
            aliases = [a.strip() for a in aliases] if aliases else aliases
            _print(core.update_profile(
                args.name, args.description, args.adversary, args.capability,
                args.infrastructure, args.victim, aliases, args.confidence,
                args.first_seen, args.last_seen))
        elif args.command == "update-ttp":
            _print(core.update_ttp(args.name, args.technique_id,
                                    args.technique_name, args.status, args.notes))
        elif args.command == "append-hunt-log":
            _print(core.append_hunt_log(args.name, args.entry))
        elif args.command == "add-detection":
            technique_ids = [t.strip() for t in args.technique_ids.split(",") if t.strip()]
            _print(core.add_detection(args.detection_id, args.description,
                                       technique_ids, args.status, args.cluster))
        elif args.command == "get-technique-usage":
            _print(core.get_technique_usage(args.technique_id))
        elif args.command == "add-relationship":
            _print(core.add_relationship(args.name, args.relationship_type,
                                          args.target_cluster, args.description, args.source))
        elif args.command == "add-gap":
            _print(core.add_gap(args.name, args.description, args.priority))
        elif args.command == "export-navigator":
            _print(core.export_navigator_layer(args.name))
        elif args.command == "get-observables":
            _print(core.get_observables(args.name))
        elif args.command == "find-observable":
            _print(core.find_observable(args.value))
        elif args.command == "pivot-observable":
            _print(core.pivot_observable(args.value))
        elif args.command == "pivot-cluster":
            _print(core.pivot_cluster(args.name))
        elif args.command == "pivot-and-expand":
            _print(core.pivot_and_expand(args.value, args.cluster_name,
                                          include_cohosted=args.include_cohosted))
        elif args.command == "add-observable":
            _print(core.add_observable(args.name, args.category, args.value, args.source))
        elif args.command == "remove-observable":
            _print(core.remove_observable(args.name, args.category, args.value))
        elif args.command == "analyze-report":
            _print(core.analyze_report(args.source))
        elif args.command == "ingest-report":
            _print(core.ingest_report(args.source, args.name,
                                       create_if_missing=not args.no_create))
        elif args.command == "export-stix":
            _print(core.export_stix_bundle(args.name))
        elif args.command == "export-stix-ecosystem":
            _print(core.export_stix_ecosystem(args.name))
        elif args.command == "import-stix":
            raw = sys.stdin.read() if args.bundle_path == "-" else open(args.bundle_path).read()
            bundle = json.loads(raw)
            _print(core.import_stix_bundle(bundle, args.name, args.overwrite))
    except (core.ClusterNotFound, FileExistsError, ValueError,
            FileNotFoundError, UnsupportedSource) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
