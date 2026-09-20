#!/usr/bin/env python3
"""Write the selector taxonomy into the pivoting skill, from the code.

    python scripts/render_selector_skill.py            # rewrite in place
    python scripts/render_selector_skill.py --check    # fail if stale

The skill must not carry its own copy of the taxonomy. `selectors.py`
decides what a shared value proves and `expand.py` applies that decision;
a skill that restated it in prose would drift the first time a type was
reclassed, and an agent reading it would then be arguing with a rule that
has already run. That is not hypothetical - `whois.registrar` moved
structural -> behavioural, and `http.body_sha256` acquired a status
condition, while this text was being written.

The graph's `infrastructure` prompt solves the same problem at load time
(`graph/sdk.selector_taxonomy`). A skill is a static file on disk, so it
gets a generator and a test instead.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cti.store.selectors import CLASS_ORDER, TYPES  # noqa: E402

SKILL = (Path(__file__).resolve().parents[1] / "skills" /
         "infrastructure-pivoting" / "SKILL.md")
BEGIN = "<!-- BEGIN GENERATED TAXONOMY -->"
END = "<!-- END GENERATED TAXONOMY -->"

_HEADINGS = {
    "identity": ("identity — one is enough",
                 "A content or key digest. Two hosts holding the same one "
                 "did not arrive there by coincidence; they were configured "
                 "from the same source."),
    "structural": ("structural — two independent ones promote",
                   "Configuration and registration facts. Coincidence is "
                   "possible, which is why two are needed, of different "
                   "types."),
    "behavioural": ("behavioural — corroborates, never promotes",
                    "How the service behaves. Distinctive in combination, "
                    "individually shared by every host running the same "
                    "stack."),
    "contextual": ("contextual — describes only",
                   "Structurally unable to promote a candidate, no matter "
                   "how many indicators share the value."),
}


def render() -> str:
    by_class: dict[str, list] = {c: [] for c in CLASS_ORDER}
    for spec in TYPES.values():
        by_class[spec.cls].append(spec)

    lines = [BEGIN, "",
             "## What each selector proves",
             "",
             "_Generated from `cti/store/selectors.py` by "
             "`scripts/render_selector_skill.py`. Do not edit by hand: the "
             "code is the authority and a test checks this block against "
             "it._",
             ""]
    for cls in reversed(CLASS_ORDER):
        heading, blurb = _HEADINGS[cls]
        lines += [f"### {heading}", "", blurb, ""]
        for spec in sorted(by_class[cls], key=lambda s: s.name):
            lines.append(f"- **`{spec.name}`** — {spec.means}.")
            if spec.never:
                lines.append(f"  - *Never:* {spec.never}.")
        lines.append("")
    lines.append(END)
    return "\n".join(lines)


def current(text: str) -> str:
    start, end = text.index(BEGIN), text.index(END) + len(END)
    return text[start:end]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the skill is out of date")
    args = ap.parse_args()

    text = SKILL.read_text()
    fresh = render()
    if current(text) == fresh:
        print(f"{SKILL.name}: up to date ({len(TYPES)} selector types)")
        return 0
    if args.check:
        print(f"{SKILL.name} is STALE - run scripts/render_selector_skill.py",
              file=sys.stderr)
        return 1
    SKILL.write_text(text.replace(current(text), fresh))
    print(f"{SKILL.name}: rewritten ({len(TYPES)} selector types)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
