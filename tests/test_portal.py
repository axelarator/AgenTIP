"""The Svelte portal: the rules that outlive any particular component.

There is no browser here, so this does not test rendering. It tests the
three things that would be silently wrong for a long time if they broke:
the escaping rule, the committed build output, and the route shapes that
existing bookmarks depend on.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
UI = REPO / "dashboard" / "ui"
SRC = UI / "src"
BUILD = REPO / "dashboard" / "static-next"


def _sources():
    return sorted(list(SRC.rglob("*.svelte")) + list(SRC.rglob("*.js")))


# --------------------------------------------------------------------------- #
# The escaping rule
# --------------------------------------------------------------------------- #

def test_no_source_file_uses_the_raw_html_escape_hatch():
    """The rule the old app stated at the top of app.js and this rewrite
    inherits: observable values, hunt-log entries and narrative prose come
    from ingested, sometimes adversary-authored reports.

    Svelte escapes `{value}` by default, so the port preserves this for
    free - unless someone reaches for `{@html}`, which reintroduces the
    whole problem. The profile page now also renders http_title,
    tls_subject, whois_registrant_email and http_headers straight out of
    payload, which is attack surface this change created.
    """
    offenders = [str(p.relative_to(REPO)) for p in _sources()
                 if "{@html" in p.read_text()]
    assert offenders == []


def test_no_source_file_assigns_innerhtml():
    offenders = [str(p.relative_to(REPO)) for p in _sources()
                 if re.search(r"\.innerHTML\s*=", p.read_text())]
    assert offenders == []


# --------------------------------------------------------------------------- #
# The committed build
# --------------------------------------------------------------------------- #

def test_the_build_output_is_committed():
    """The lab VM serves this directly and has no node on the serving path.
    A missing build means the portal 404s after a deploy."""
    assert (BUILD / "index.html").is_file()
    assets = list((BUILD / "assets").glob("*.js"))
    assert assets, "no bundle in dashboard/static-next/assets"


def test_the_build_is_not_older_than_its_sources():
    """A stale bundle serves an old UI silently - nothing errors, the page
    just does not have the change in it. Rebuild before committing."""
    newest_source = max(p.stat().st_mtime for p in _sources())
    newest_build = max(p.stat().st_mtime
                       for p in BUILD.rglob("*") if p.is_file())
    assert newest_build >= newest_source, (
        "dashboard/static-next is older than dashboard/ui/src - "
        "run `npm run build` in dashboard/ui")


def test_vite_does_not_build_over_the_live_dashboard():
    """emptyOutDir deletes what it finds. Pointed at ../static that is the
    working dashboard, and one stray build during the rewrite would take
    it out."""
    config = (UI / "vite.config.js").read_text()
    assert '"../static-next"' in config or "'../static-next'" in config
    assert '"../static"' not in config and "'../static'" not in config


def test_the_toolchain_is_pinned_and_clean():
    pkg = json.loads((UI / "package.json").read_text())
    assert "dependencies" not in pkg or not pkg["dependencies"], \
        "the shipped bundle must have no runtime dependencies"
    assert set(pkg["devDependencies"]) == {
        "@sveltejs/vite-plugin-svelte", "svelte", "vite"}


# --------------------------------------------------------------------------- #
# Routes existing bookmarks depend on
# --------------------------------------------------------------------------- #

def test_the_router_preserves_the_old_hash_shapes():
    router = (SRC / "lib" / "router.js").read_text()
    for shape in ("cluster", "techniques", "queue", "tracking",
                  "narratives", "runs", "search"):
        assert f'case "{shape}"' in router, shape


def test_an_old_tracking_bookmark_redirects_to_the_profile():
    """#/tracking/<ip> was the old detail route. It should land on the
    better page rather than break."""
    router = (SRC / "lib" / "router.js").read_text()
    tracking = router[router.index('case "tracking"'):]
    assert 'name: "indicator"' in tracking[:300]


def test_the_router_splits_before_decoding():
    """Load-bearing for selector values. nginx/1.29.3 arrives encoded, and
    decoding first would tear it in half at the slash."""
    router = (SRC / "lib" / "router.js").read_text()
    split_at = router.index(".split(")
    decode_at = router.index(".map(decodeURIComponent)")
    assert split_at < decode_at


# --------------------------------------------------------------------------- #
# The complaint this portal exists to answer
# --------------------------------------------------------------------------- #

def test_indicator_values_are_never_truncated():
    """truncate() exists for prose - a hunt-log entry, a TTP note. An
    indicator that has been shortened cannot be pasted anywhere, which is
    the entire reason for this work."""
    chip = (SRC / "components" / "IndicatorChip.svelte").read_text()
    copy = (SRC / "components" / "CopyValue.svelte").read_text()
    assert "truncate" not in chip and "truncate" not in copy
    assert "user-select: all" in copy


def test_the_copy_helper_works_without_a_secure_context():
    """The portal is served over plain HTTP on a LAN address, so
    navigator.clipboard is unavailable - the fallback is the normal path
    here, not an edge case."""
    copy = (SRC / "lib" / "copy.js").read_text()
    assert "isSecureContext" in copy and "execCommand" in copy
