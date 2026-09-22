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
BUILD = REPO / "dashboard" / "static"


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
    assert assets, "no bundle in dashboard/static/assets"


def test_the_build_is_not_older_than_its_sources():
    """A stale bundle serves an old UI silently - nothing errors, the page
    just does not have the change in it. Rebuild before committing."""
    newest_source = max(p.stat().st_mtime for p in _sources())
    newest_build = max(p.stat().st_mtime
                       for p in BUILD.rglob("*") if p.is_file())
    assert newest_build >= newest_source, (
        "dashboard/static is older than dashboard/ui/src - "
        "run `npm run build` in dashboard/ui")


def test_the_build_lands_where_the_server_serves_it():
    """The bundle is committed and served straight from dashboard/static -
    the VM has no node. A build that went anywhere else would leave the
    live dashboard stale with nothing failing."""
    config = (UI / "vite.config.js").read_text()
    assert '"../static"' in config
    assert 'base: "/"' in config, "assets must resolve from the site root"
    server = (REPO / "dashboard" / "server.py").read_text()
    assert 'Path(__file__).parent / "static"' in server


def test_no_staging_mount_or_old_ui_remains():
    """The rewrite was served at /next until cutover. Left in place it would
    serve a second, stale copy of the app forever."""
    server = (REPO / "dashboard" / "server.py").read_text()
    assert "/next" not in server and "static-next" not in server
    assert not (REPO / "dashboard" / "static-next").exists()
    for old in ("app.js", "styles.css"):
        assert not (BUILD / old).exists(), f"the previous UI's {old} is still here"


def test_the_built_page_references_assets_from_the_site_root():
    html = (BUILD / "index.html").read_text()
    assert 'src="/assets/' in html and "/next/" not in html


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


# --------------------------------------------------------------------------- #
# What the feedback round changed
# --------------------------------------------------------------------------- #

def test_a_hash_chip_links_by_value_and_never_guesses_a_type():
    """A certificate digest and an SPKI digest are both 64 hex characters.
    Guessing sent two of the three hashes in one finding to a body-hash
    page that found nothing."""
    chip = (SRC / "components" / "IndicatorChip.svelte").read_text()
    assert "tls.cert_sha256" not in chip and "http.body_sha256" not in chip
    assert "href.selector(bare)" in chip


def test_the_timeline_can_be_narrowed_without_scrolling():
    """172 observations over 27 days is a lot of scrolling to reach last
    week."""
    view = (SRC / "views" / "Indicator.svelte").read_text()
    assert "windowDays" in view and "jumpDate" in view


def test_dropdowns_use_the_themed_component_not_a_bare_select():
    """A native select reads as browser chrome dropped into the page."""
    for name in ("Indicator.svelte", "Indicators.svelte"):
        view = (SRC / "views" / name).read_text()
        assert "<select" not in view, f"{name} still has a bare select"


def test_selector_prose_is_framed_by_whether_it_is_actually_shared():
    """The taxonomy's `means` is written for the shared case. Shown beside
    one host's attribute unlabelled, it reads as a non-sequitur."""
    c = (SRC / "components" / "SelectorMeaning.svelte").read_text()
    assert "If shared, it would mean" in c
    assert "Nothing else recorded carries this value" in c


def test_a_held_back_link_names_its_selectors_and_why_they_cannot_promote():
    """"corroborating selectors only - nothing that can promote" is
    accurate and answers nothing."""
    c = (SRC / "components" / "HeldBack.svelte").read_text()
    assert "These two share" in c
    assert "behavioural" in c and "contextual" in c
    assert "one identity selector, or two structural selectors" in c


# --------------------------------------------------------------------------- #
# The port: theme, statuses, and the pure-JS modules
# --------------------------------------------------------------------------- #

import shutil
import subprocess


def _theme_tokens() -> set[str]:
    css = (SRC / "app.css").read_text()
    return set(re.findall(r"(--[a-z0-9-]+)\s*:", css))


def test_every_css_variable_a_component_uses_exists_in_the_theme():
    """The first cut of the portal used --muted, --panel and --chip-bg.
    None of them exist, so each fell back to a hard-coded light-mode colour
    and ignored dark mode entirely - 27 uses, invisible to the build, the
    linter and every other test."""
    tokens = _theme_tokens()
    unknown = {}
    for path in _sources():
        if path.suffix != ".svelte":
            continue
        for name in re.findall(r"var\((--[a-z0-9-]+)", path.read_text()):
            # a chip's colour pair is built at runtime from a stem
            if name not in tokens:
                unknown.setdefault(name, []).append(path.name)
    assert unknown == {}


def test_no_component_hard_codes_a_colour():
    """A literal colour does not follow the theme. Tokens only."""
    offenders = []
    for path in _sources():
        if path.suffix != ".svelte":
            continue
        for m in re.finditer(r"rgba?\(\s*\d|#[0-9a-fA-F]{3,8}\b", path.read_text()):
            offenders.append(f"{path.name}: {m.group(0)}")
    assert offenders == []


def test_every_status_the_backend_can_produce_has_a_label_and_a_colour():
    """indicator_status can return IP-ladder and domain-ladder values. One
    without an entry silently renders as a default grey "never enriched",
    which is exactly the lie the domain ladder was written to stop."""
    query = (REPO / "cti" / "store" / "query.py").read_text()
    produced = set()
    for fn in ("_tracking_status", "_domain_status"):
        body = query[query.index(f"def {fn}"):]
        body = body[:body.index("\ndef ")]
        produced |= set(re.findall(r'return "([a-z-]+)"', body))
    assert produced, "found no statuses - the parse broke"
    labels = (SRC / "lib" / "labels.js").read_text()
    status_block = labels[labels.index("export const STATUS = {"):labels.index("export const STATUS_ORDER")]
    defined = set(re.findall(r'^\s*"?([a-z-]+)"?:', status_block, re.M))
    assert produced <= defined, sorted(produced - defined)


def test_every_view_is_routed_and_every_route_has_a_view():
    app = (SRC / "App.svelte").read_text()
    router = (SRC / "lib" / "router.js").read_text()
    files = {p.stem for p in (SRC / "views").glob("*.svelte")}
    imported = set(re.findall(r'views/(\w+)\.svelte', app))
    assert files == imported, f"orphaned or missing: {files ^ imported}"
    names = set(re.findall(r'name: "([a-z]+)"', router))
    routed = set(re.findall(r'\$route\.name === "([a-z]+)"', app)) | {"overview"}
    assert names <= routed, f"router names with no view: {names - routed}"


def _node(script: str):
    node = shutil.which("node")
    if not node or not (UI / "node_modules").is_dir():
        pytest.skip("node or dashboard/ui/node_modules not available")
    # router.js reads `location` when it is imported; node has none.
    script = 'globalThis.location = { hash: "" };\n' + script
    out = subprocess.run([node, "--input-type=module", "-e", script],
                         capture_output=True, text=True, cwd=UI, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_the_router_parses_the_old_and_new_shapes():
    got = _node("""
      const { parseHash: p } = await import("./src/lib/router.js");
      console.log(JSON.stringify([
        p("#/"), p("#/cluster/jadeprox"), p("#/cluster/jadeprox/observables"),
        p("#/techniques"), p("#/techniques/T1071"), p("#/tracking"),
        p("#/tracking/1.2.3.4"), p("#/indicator/evil.example"),
        p("#/selector/abc"), p("#/selector/http.server/nginx%2F1.29.3"),
        p("#/search/a%2Fb"), p("#/nonsense")]));
    """)
    assert got[0]["name"] == "overview"
    assert got[1] == {"name": "cluster", "slug": "jadeprox", "tab": "diamond"}
    assert got[2]["tab"] == "observables"
    assert got[3]["name"] == "techniques" and got[4] == {"name": "technique", "id": "T1071"}
    # the old tracking bookmarks land on the better page
    assert got[5]["name"] == "indicators"
    assert got[6] == {"name": "indicator", "value": "1.2.3.4"}
    # one segment = value only, two = explicit type
    assert got[8] == {"name": "selector", "type": None, "value": "abc"}
    assert got[9]["type"] == "http.server" and got[9]["value"] == "nginx/1.29.3", \
        "an encoded slash must survive the split"
    assert got[10]["query"] == "a/b"
    assert got[11]["name"] == "overview"


def test_selector_type_names_are_never_mistaken_for_indicators():
    """The narrative writes `tls.cert_sha256` and `workers.dev` in backticks
    alike. One is a selector type and must not become a link to an indicator
    page that does not exist."""
    got = _node("""
      import { looksLikeIndicator as f, looksLikeHash as h } from "./src/lib/format.js";
      const t = ["tls.cert_sha256", "http.body_sha256", "net.resolved_ip",
                 "workers.dev", "evil.example", "203.0.113.9", "a.b",
                 "cert-sha256:" + "a".repeat(64), "a".repeat(64), "not a value"];
      console.log(JSON.stringify(t.map((v) => [f(v), h(v)])));
    """)
    assert got[0:3] == [[False, False]] * 3
    assert got[3] == [True, False] and got[4] == [True, False]
    assert got[5] == [True, False]
    assert got[7][1] is True and got[8][1] is True
    assert got[9] == [False, False]


def test_report_sources_group_repeat_ingests_of_one_report():
    got = _node("""
      import { groupReportSources as g } from "./src/lib/reports.js";
      const r = (ing, n) => ({ source: "https://x/report", ingested: ing,
        observables_found: { domains: n }, ttps_found: ["T1"] });
      const out = g([r("2026-09-02", 0), r("2026-09-01", 5),
                     { source: "other", ingested: "2026-09-03", observables_found: {} }]);
      console.log(JSON.stringify(out.map((x) => [x.source, x.attempts.length,
        x.observableCounts.domains, x.lastIngested])));
    """)
    assert got[0] == ["https://x/report", 2, 5, "2026-09-02"]
    assert got[1][1] == 1


def test_dates_are_shown_as_written_not_shifted_by_the_browser_zone():
    """The API's timestamps are naive. Running them through new Date()
    reinterprets them in the local zone and moves every time by the offset."""
    got = _node("""
      import { formatDate as d, formatDateOnly as o } from "./src/lib/format.js";
      console.log(JSON.stringify([d("2026-09-21T06:32:15"), d("2026-09-21 06:32:15"),
        d(null), o("2025-09"), o("2022-12-01T00:00:00Z"), o(null), o("free text")]));
    """)
    assert got == ["2026-09-21 06:32", "2026-09-21 06:32", "—",
                   "2025-09-01", "2022-12-01", None, "free text"]


def test_code_inside_bold_is_parsed_not_shown_with_its_backticks():
    """The model writes **Cert rotation on `host`** routinely. The first
    tokenizer matched the whole bold span as one plain token, so the
    backticks rendered literally. Found by driving the built app, not by any
    build step or type check."""
    got = _node("""
      const { inline } = await import("./src/lib/markdown.js");
      console.log(JSON.stringify(inline(
        "**Cert rotation on `webconf.shop-api.workers.dev`** (medium): done")));
    """)
    assert [(t["t"], t["v"]) for t in got] == [
        ("text", "Cert rotation on "), ("indicator", "webconf.shop-api.workers.dev"),
        ("text", " (medium): done")]
    assert got[0]["strong"] is True and "strong" not in got[2]
    assert "`" not in "".join(t["v"] for t in got)


def test_a_full_hash_in_backticks_becomes_a_chip_and_an_abbreviated_one_does_not():
    """The narrative prompt now asks for full hashes. An abbreviated one
    (`0ca9769a…`) is not a hash and must not link anywhere."""
    got = _node("""
      const { inline } = await import("./src/lib/markdown.js");
      const h = "8ed8767a759e2ecdc712f05c483a77a2546a80b2432cad8e6246afb9dd519fa2";
      console.log(JSON.stringify([
        inline("`" + h + "`")[0], inline("`cert-sha256:" + h + "`")[0],
        inline("`0ca9769a…`")[0], inline("`tls.cert_sha256`")[0],
        inline("`203.0.113.9`")[0], inline("`workers.dev`")[0]]));
    """)
    assert [t["t"] for t in got] == ["hash", "hash", "code", "code", "indicator", "indicator"]
    assert len(got[0]["v"]) == 64, "the value is carried whole"


def test_blocks_lists_and_headings_parse():
    got = _node("""
      const { parse } = await import("./src/lib/markdown.js");
      console.log(JSON.stringify(parse(
        "## Title\\n\\ntext **b**\\n- one\\n- two\\n1. first\\n2. second\\n\\n"))
        .replace(/\\s+/g, " "));
    """)
    assert [b["type"] for b in got] == ["heading", "p", "list", "list"]
    assert got[2]["ordered"] is False and len(got[2]["items"]) == 2
    assert got[3]["ordered"] is True and len(got[3]["items"]) == 2


def test_markup_in_narrative_text_stays_text():
    """The narrative is over adversary-influenced content. Tags in it are
    just characters to a tokenizer that never builds HTML."""
    got = _node("""
      const { inline } = await import("./src/lib/markdown.js");
      console.log(JSON.stringify(inline("<img src=x onerror=alert(1)> **<b>x</b>**")));
    """)
    assert all(t["t"] in ("text", "code", "indicator", "hash") for t in got)
    assert "<img src=x onerror=alert(1)>" in "".join(t["v"] for t in got)
