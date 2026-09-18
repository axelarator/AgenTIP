"""One-off/occasional script to regenerate cti_tools/attack_data/
enterprise_attack_techniques.json from the official MITRE STIX corpus.

Not run at install time or by any tool/server code - this tool makes no
network calls at runtime by design. Re-run manually when a new ATT&CK
Enterprise release ships:

    python scripts/refresh_attack_data.py

Fetches the full STIX bundle (~50MB) from mitre-attack/attack-stix-data
on GitHub, reduces it to a flat technique_id -> name/tactics/revoked
lookup (a few hundred KB), and overwrites the bundled JSON in place.
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

SOURCE_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
              "master/enterprise-attack/enterprise-attack.json")
OUTPUT_PATH = (Path(__file__).resolve().parents[1] / "cti_tools" / "attack_data"
               / "enterprise_attack_techniques.json")


def main() -> None:
    with urllib.request.urlopen(SOURCE_URL, timeout=120) as resp:
        bundle = json.loads(resp.read())

    raw = {}
    stix_id_to_ext = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        ext_id = next((r["external_id"] for r in obj.get("external_references", [])
                       if r.get("source_name") == "mitre-attack"), None)
        if not ext_id:
            continue
        raw[ext_id] = obj
        stix_id_to_ext[obj["id"]] = ext_id

    revoked_by = {}
    for obj in bundle["objects"]:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
            revoked_by[obj["source_ref"]] = obj["target_ref"]

    techniques = {}
    for ext_id, obj in raw.items():
        tactics = sorted({p["phase_name"] for p in obj.get("kill_chain_phases", [])
                           if p.get("kill_chain_name") == "mitre-attack"})
        is_sub = obj.get("x_mitre_is_subtechnique", False)
        name = obj["name"]
        display_name = name
        if is_sub:
            parent = raw.get(ext_id.split(".")[0])
            if parent:
                display_name = f"{parent['name']}: {name}"

        entry = {
            "name": name,
            "display_name": display_name,
            "tactics": tactics,
            "is_subtechnique": is_sub,
            "revoked": bool(obj.get("revoked")),
            "deprecated": bool(obj.get("x_mitre_deprecated")),
        }
        replacement_stix_id = revoked_by.get(obj["id"])
        if replacement_stix_id:
            entry["revoked_by"] = stix_id_to_ext.get(replacement_stix_id)
        techniques[ext_id] = entry

    OUTPUT_PATH.write_text(json.dumps(techniques, indent=1, sort_keys=True) + "\n")
    print(f"wrote {len(techniques)} techniques to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
