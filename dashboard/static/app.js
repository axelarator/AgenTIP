"use strict";

/* ---------- tiny safe DOM builder (never innerHTML on data-derived text —
   hunt-log/observable strings originate from ingested, sometimes
   adversary-authored, report content) ---------- */
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.appendChild(c.nodeType ? c : document.createTextNode(String(c)));
  }
  return el;
}

async function api(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

const CATEGORY_LABELS = {
  hashes: "Hashes", domains: "Domains", ips: "IPs", urls: "URLs", emails: "Emails",
  cves: "CVEs", wallets: "Wallets", ja4: "JA4", ja4s: "JA4S", ja4h: "JA4H",
  ja4l: "JA4L", ja4x: "JA4X", ja4t: "JA4T", ja4ts: "JA4TS", ja4ssh: "JA4SSH", jarm: "JARM",
};
const FINGERPRINT_CATEGORIES = new Set(["ja4", "ja4s", "ja4h", "ja4l", "ja4x", "ja4t", "ja4ts", "ja4ssh", "jarm"]);
const COVERAGE_LABELS = ["no coverage", "idea only", "built, unvalidated", "validated, in production", "validated + tuned"];
const DETECTION_STATUS = { draft: ["det-draft", "Draft"], unvalidated: ["det-unvalidated", "Unvalidated"], published: ["det-published", "Published"] };

const state = { clusters: [] };

/* ---------- shared formatting / small components ---------- */
function formatDate(iso) {
  if (!iso) return "—";
  const m = String(iso).match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/);
  return m ? `${m[1]} ${m[2]}` : String(iso);
}

// Date-only variant for first_seen/last_seen fields specifically: those
// are shown alongside each other in several places and should always
// read as plain YYYY-MM-DD, never a mix of date-only/datetime/month-only/
// free-text (cluster-level first_seen/last_seen come from update_profile's
// free-text params, and real data includes e.g. "2025-09" and
// "2022-12-01T00:00:00Z" alongside plain dates - see core.py's _date_only,
// which this mirrors). A day-less YYYY-MM value is padded to its 1st, the
// conventional stand-in for "day unknown". Returns null (not "—") for
// blank so callers can pick their own fallback text; anything without at
// least YYYY-MM passes through unmangled.
function formatDateOnly(iso) {
  if (!iso) return null;
  const m = String(iso).match(/^(\d{4})-(\d{2})(?:-(\d{2}))?/);
  return m ? `${m[1]}-${m[2]}-${m[3] || "01"}` : String(iso);
}

function truncate(text, n) {
  if (!text) return "";
  return text.length > n ? text.slice(0, n).trimEnd() + "…" : text;
}

function confidenceColor(c) {
  if (c == null) return "var(--ink-3)";
  if (c >= 75) return "var(--cov-4-ink)";
  if (c >= 50) return "var(--cov-3-ink)";
  if (c >= 25) return "var(--cov-2-ink)";
  return "var(--cov-1-ink)";
}

function confidenceBadge(c) {
  if (c == null) return h("span", { class: "chip chip--neutral" }, "confidence unknown");
  return h("span", { class: "confidence-bar" },
    h("span", { class: "confidence-bar__track" },
      h("span", { class: "confidence-bar__fill", style: `width:${c}%;background:${confidenceColor(c)}` })),
    h("span", { style: "font-family:var(--font-mono);font-size:12px;color:var(--ink-2);" }, `${c}%`));
}

function coverageChip(status) {
  return h("span", { class: "chip", style: `background:var(--cov-${status}-bg);color:var(--cov-${status}-ink)` },
    COVERAGE_LABELS[status] ?? `status ${status}`);
}

function priorityChip(p) {
  const key = ["low", "medium", "high"].includes(p) ? p : "low";
  return h("span", { class: "chip", style: `background:var(--pri-${key}-bg);color:var(--pri-${key}-ink)` }, key);
}

function detStatusChip(status) {
  const [key, label] = DETECTION_STATUS[status] || ["det-draft", status || "unknown"];
  return h("span", { class: "chip", style: `background:var(--${key}-bg);color:var(--${key}-ink)` }, label);
}

const TRACKING_STATUS = {
  "in-network": ["track-in-network", "In network"],
  active: ["track-active", "Active"],
  moved: ["track-moved", "Moved"],
  quiet: ["track-quiet", "Quiet"],
  absent: ["track-absent", "Absent"],
};
function trackingStatusChip(status) {
  const [key, label] = TRACKING_STATUS[status] || ["track-quiet", status || "never enriched"];
  return h("span", { class: "chip", style: `background:var(--${key}-bg);color:var(--${key}-ink)` }, label);
}

function clusterChip(name) {
  const match = state.clusters.find((c) => c.name === name);
  return h("a", { class: "chip chip--neutral", style: "text-decoration:none;", href: match ? `#/cluster/${match.slug}` : "#" }, name);
}

function trackingIpChip(ip) {
  return h("a", { class: "chip chip--mono chip--neutral", style: "text-decoration:none;",
    href: `#/tracking/${encodeURIComponent(ip)}` }, ip);
}

// probe_pending_fingerprints.py's own provenance strings (core.py's
// pending-fingerprint entries are filed with these two exact formats -
// see JARM/Zeek add_observable calls): the source names the resolved IP
// and port, so an Arkime session-viewer deep link can be rebuilt from the
// text alone. Field names (`ip`, `port`) and query syntax confirmed live
// against this lab's Arkime instance (10.20.0.18:8005/api/fields).
//
// An Arkime link is only ever built from one of these two provenance
// formats - i.e. only for an IP that was actually sourced from a probe
// (an active JARM probe, or its Zeek-passive corroboration of that same
// probe's handshake) - never from HoneyLabs/Shodan enrichment data, which
// has no relationship to this lab's own captured traffic and previously
// produced a link that (correctly) usually showed nothing. The trailing
// timestamp accepts either the newer full UTC timestamp (precise probe
// time, giving a tight Arkime window - see arkimeSessionUrl) or the older
// date-only form still present in provenance strings filed before that
// precision was added (falls back to a full-day window).
const JARM_SOURCE_RE = /^JARM against (.+):(\d+) via .+, (\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?)$/;
const ZEEK_SOURCE_RE = /^Zeek passive \(tap107, via OpenSearch\) handshake against (.+):(\d+) \(([\d.]+)\), (\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?)$/;
const ARKIME_BASE = "http://10.20.0.18:8005/sessions";
// How wide a window to open around a precisely-known probe time - wide
// enough to allow for a little clock/ingestion lag, tight enough that
// the link points at "the point in time probing took place", not a
// whole-day guess.
const ARKIME_PROBE_WINDOW_SECS = 5 * 60;

// Both probe_pending_fingerprints.py source formats name the resolved IP
// and port the probe/Zeek capture actually hit, plus when it ran - see
// the JARM/Zeek add_observable calls in that script. Parsed once here and
// reused both for the Arkime deep link and for the fingerprint table's
// Target/Checked columns, so a JARM/JA4+ value doesn't require hovering a
// truncated link label to see what it relates to.
function parseProbeSource(source) {
  const zeek = source.match(ZEEK_SOURCE_RE);
  if (zeek) return { target: zeek[1], port: zeek[2], ip: zeek[3], when: zeek[4] };
  const jarm = source.match(JARM_SOURCE_RE);
  if (jarm) {
    // A JARM probe fires straight at the tracked domain/IP, before any
    // Zeek-side DNS resolution is recorded - so `target` is only known to
    // be an IP (and therefore Arkime-queryable) when it already looks
    // like one; a domain target still shows in the table, just without a
    // session link.
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(jarm[1]);
    return { target: jarm[1], port: jarm[2], ip: isIp ? jarm[1] : null, when: jarm[3] };
  }
  return null;
}

// Query syntax (`ip`, `port` fields) and startTime/stopTime semantics
// confirmed live against this lab's Arkime instance (10.20.0.18:8005).
// Windowed tightly around the actual point in time the probe ran when
// that's known precisely (the common case now); a bare date (older
// provenance strings) falls back to the full UTC day, as before.
function arkimeSessionUrl(source) {
  const p = parseProbeSource(source);
  if (!p || !p.ip) return null;
  const precise = p.when.includes("T");
  const ts = Date.parse(precise ? p.when : `${p.when}T00:00:00Z`) / 1000;
  const start = precise ? ts - ARKIME_PROBE_WINDOW_SECS : ts;
  const stop = precise ? ts + ARKIME_PROBE_WINDOW_SECS : ts + 86400;
  const params = new URLSearchParams({
    expression: `ip == ${p.ip} && port == ${p.port}`,
    startTime: String(start), stopTime: String(stop),
  });
  return { url: `${ARKIME_BASE}?${params.toString()}`, label: "Arkime" };
}

// pivot_and_expand's provenance notes (core.py) name the exact lookup
// service verbatim ("... via VirusTotal resolution history", "... via
// Hackertarget reverse-IP") - matched here to rebuild a link to that
// service's own public page for the observable in question, since the
// note itself is free text, not a URL. (Cert Spotter CT log notes used to
// link to crt.sh, which has since shut down - no replacement public
// CT-log search is linked here until one is confirmed working.)
function pivotSourceUrl(source, category, value) {
  if (/VirusTotal/i.test(source)) {
    const bare = category === "hashes" && value.includes(":") ? value.split(":", 2)[1] : value;
    return { url: `https://www.virustotal.com/gui/search/${encodeURIComponent(bare)}`, label: "VirusTotal" };
  }
  const arkime = arkimeSessionUrl(source);
  if (arkime) return arkime;
  // Hackertarget's reverse-IP tool has no confirmed deep-link-by-IP query
  // param - left as plain text below. Credentials for Arkime/OpenSearch are
  // never embedded here; the browser's own auth challenge handles login.
  return null;
}

function sourceLink(source, category, value) {
  let parsed = null;
  try { parsed = new URL(source); } catch (_) { /* provenance note (e.g. a pivot record), not a URL */ }
  if (parsed && (parsed.protocol === "http:" || parsed.protocol === "https:")) {
    return h("a", { class: "source-link", href: source, target: "_blank", rel: "noopener noreferrer" }, parsed.hostname.replace(/^www\./, ""));
  }
  const pivot = pivotSourceUrl(source, category, value);
  if (pivot) {
    return h("a", { class: "source-link", href: pivot.url, target: "_blank", rel: "noopener noreferrer", title: source }, pivot.label);
  }
  return h("span", { class: "source-note", title: source }, truncate(source, 42));
}

/* ---------- sidebar ---------- */
async function initSidebar() {
  // Tracking DB can be transiently 503 (daily job holding the write
  // lock) - that badge failing to load shouldn't take the rest of the
  // sidebar (cluster nav) down with it.
  const [clusters, pending, tracking] = await Promise.all([
    api("/api/clusters"), api("/api/pending-fingerprints"),
    api("/api/tracking/observables").catch(() => ({ observables: [] })),
  ]);
  state.clusters = clusters;
  document.getElementById("cluster-count").textContent = clusters.length;
  renderClusterList(clusters);
  const badge = document.getElementById("queue-badge");
  if (pending.length) { badge.textContent = String(pending.length); badge.hidden = false; }
  const inNetworkCount = tracking.observables.filter((o) => o.status === "in-network").length;
  const trackBadge = document.getElementById("tracking-badge");
  if (inNetworkCount) { trackBadge.textContent = String(inNetworkCount); trackBadge.hidden = false; }
}

function renderClusterList(clusters, filter = "") {
  const list = document.getElementById("cluster-list");
  list.textContent = "";
  const f = filter.trim().toLowerCase();
  const filtered = clusters.filter((c) => !f
    || c.name.toLowerCase().includes(f)
    || c.slug.includes(f)
    || (c.aliases || []).some((a) => a.toLowerCase().includes(f)));
  if (!filtered.length) { list.appendChild(h("div", { class: "empty-state" }, "No clusters match.")); return; }
  for (const c of filtered) {
    const lastSeen = formatDateOnly(c.last_seen);
    list.appendChild(h("a", { class: "cluster-row", href: `#/cluster/${c.slug}`, "data-slug": c.slug },
      h("div", { class: "cluster-row__top" },
        h("span", { class: "cluster-row__dot", style: `background:${confidenceColor(c.confidence)}` }),
        h("span", { class: "cluster-row__name" }, c.name)),
      h("div", { class: "cluster-row__meta" }, lastSeen ? `last seen ${lastSeen}` : "no activity logged")));
  }
}

function updateActiveStates(route) {
  document.querySelectorAll(".nav-link").forEach((a) => a.classList.toggle("is-active", a.dataset.route === route.name));
  document.querySelectorAll(".cluster-row").forEach((a) => a.classList.toggle("is-active", route.name === "cluster" && a.dataset.slug === route.slug));
}

/* ---------- overview ---------- */
function statTile(label, value, accent) {
  return h("div", { class: "stat-tile" },
    h("div", { class: "stat-tile__label" }, label),
    h("div", { class: "stat-tile__value" + (accent ? " stat-tile__value--accent" : "") }, String(value)));
}

function activityItem(entry) {
  return h("div", { class: "timeline-item" },
    h("div", { class: "timeline-item__head" },
      h("span", { class: "timeline-item__date" }, formatDate(entry.date)),
      h("a", { class: "timeline-item__cluster-link", href: `#/cluster/${entry.slug}/hunt_log` }, entry.cluster)),
    h("div", { class: "timeline-item__body" }, truncate(entry.entry, 320)));
}

async function viewOverview() {
  const stats = await api("/api/stats");
  const grid = h("div", { class: "stat-grid" },
    statTile("Clusters", stats.cluster_count),
    statTile("Observables tracked", stats.observable_count),
    statTile("TTPs logged", stats.ttp_count),
    statTile("Detections", stats.detection_count),
    statTile("Open gaps", stats.gap_count),
    statTile("Pending fingerprints", stats.pending_fingerprint_count, stats.pending_fingerprint_count > 0));
  const activity = h("div", { class: "card" },
    h("div", { class: "card__title" }, "Recent hunt activity"),
    ...(stats.recent_activity.length ? stats.recent_activity.map(activityItem) : [h("div", { class: "empty-state" }, "No hunt log entries yet.")]));
  return h("div", {},
    h("div", { class: "view-header" },
      h("div", { class: "view-title" }, "Overview"),
      h("div", { class: "view-sub" }, "Snapshot across every tracked cluster.")),
    grid, activity);
}

/* ---------- cluster detail ---------- */
function renderDiamond(data) {
  const d = data.diamond || {};
  const quad = (label, text) => h("div", { class: "card" }, h("div", { class: "card__title" }, label), h("p", {}, text || "—"));
  const grid = h("div", { class: "diamond-grid" },
    quad("Adversary", d.adversary), quad("Capability", d.capability),
    quad("Infrastructure", d.infrastructure), quad("Victim", d.victim));
  const gaps = data.gaps || [];
  if (!gaps.length) return h("div", {}, grid);
  const order = { high: 0, medium: 1, low: 2 };
  const top = [...gaps].sort((a, b) => (order[a.priority] ?? 3) - (order[b.priority] ?? 3)).slice(0, 3);
  return h("div", {}, grid,
    h("div", { class: "card" },
      h("div", { class: "card__title" }, `Open gaps (${gaps.length})`),
      ...top.map(gapItem)));
}

function renderTtps(data) {
  const container = h("div", {});
  const tableWrap = h("div", { class: "table-wrap" });
  const input = h("input", { type: "search", placeholder: "Filter techniques…", oninput: (e) => draw(e.target.value) });
  container.appendChild(h("div", { class: "filter-row" }, input));
  container.appendChild(tableWrap);
  function draw(filter = "") {
    const f = filter.trim().toLowerCase();
    const rows = data.ttps.filter((t) => !f || t.id.toLowerCase().includes(f) || t.name.toLowerCase().includes(f));
    tableWrap.textContent = "";
    if (!rows.length) { tableWrap.appendChild(h("div", { class: "empty-state" }, "No matching techniques.")); return; }
    tableWrap.appendChild(h("table", { class: "data-table" },
      h("thead", {}, h("tr", {}, h("th", {}, "Technique"), h("th", {}, "Name"), h("th", {}, "Coverage"), h("th", {}, "Notes"), h("th", {}, "Updated"))),
      h("tbody", {}, ...rows.map((t) => h("tr", {},
        h("td", { class: "mono" }, t.id),
        h("td", {}, t.name),
        h("td", {}, coverageChip(t.status)),
        h("td", {}, truncate(t.notes, 140)),
        h("td", { class: "mono" }, formatDate(t.updated)))))));
  }
  draw();
  return container;
}

// JA4+/JARM values are opaque fingerprints - what an analyst actually
// wants to know at a glance is which IP:port they were captured against
// and when, not the fingerprint's own first/last-seen bookkeeping. One row
// per (value, source) pair, since a probe can reproduce the same
// fingerprint against the same or a different target on a later date.
function renderFingerprintTable(items) {
  const rows = [];
  for (const o of items) {
    const sources = o.sources && o.sources.length ? o.sources : [null];
    for (const s of sources) {
      const p = s ? parseProbeSource(s) : null;
      rows.push({ value: o.value, target: p ? `${p.target}:${p.port}` : null, date: p ? p.when : null, raw: s, arkime: s ? arkimeSessionUrl(s) : null });
    }
  }
  return h("table", { class: "data-table" },
    h("thead", {}, h("tr", {}, h("th", {}, "Value"), h("th", {}, "Target"), h("th", {}, "Checked"), h("th", {}, "Session"))),
    h("tbody", {}, ...rows.map((r) => h("tr", {},
      h("td", { class: "mono" }, r.value),
      h("td", { class: "mono" }, r.target || (r.raw ? truncate(r.raw, 40) : "—")),
      h("td", { class: "mono" }, r.date ? formatDate(r.date) : "—"),
      h("td", {}, r.arkime ? h("a", { class: "source-link", href: r.arkime.url, target: "_blank", rel: "noopener noreferrer" }, "View in Arkime →") : "—")))));
}

// ip/domain observables get a profile card (key identifiers + an
// expandable history timeline) instead of a flat table row - hashes/urls
// have no ports/ASN/history story, so they keep the plain table.
const PROFILE_CATEGORIES = new Set(["ips", "domains"]);

const LIFECYCLE_STATUS = {
  active: "track-active", routed: "track-active",
  dead: "track-absent", sinkholed: "track-absent",
  expired: "track-absent", unrouted: "track-absent",
};
function lifecycleStatusChip(status) {
  const key = LIFECYCLE_STATUS[status] || "track-quiet";
  return h("span", { class: "chip", style: `background:var(--${key}-bg);color:var(--${key}-ink)` },
    status || "unchecked");
}

// One dated event per observation/asn-change row, oldest-affecting-last -
// same shape viewTrackingDetail builds, reused here so a cluster's
// per-observable profile and the standalone Live Tracking page render
// history identically from one function.
function buildProfileTimeline(profile) {
  if (!profile || profile.error) return [];
  const events = [
    ...profile.observations.map((o) => ({ date: o.observed_at, kind: "observation", data: o })),
    ...profile.asn_changes.map((c) => ({ date: c.detected_at, kind: "asn_change", data: c })),
  ].sort((a, b) => b.date.localeCompare(a.date));
  return events.map((e) => trackingEventItem(profile.ip, e));
}

function latestObservationBySource(profile, source) {
  if (!profile || profile.error) return null;
  for (let i = profile.observations.length - 1; i >= 0; i--) {
    if (profile.observations[i].source === source) return profile.observations[i];
  }
  return null;
}

function renderObservableProfileCard(o, category, profile) {
  const d = o.status_detail || {};
  const chips = [];
  if (category === "ips") {
    const asn = (d.asn || [])[0];
    if (asn != null) chips.push(h("span", { class: "chip chip--neutral" }, `AS${asn}` + (d.as_holder ? ` ${d.as_holder}` : "")));
    if (d.prefix) chips.push(h("span", { class: "chip chip--neutral chip--mono" }, d.prefix));
    const shodan = latestObservationBySource(profile, "shodan");
    if (shodan && (shodan.shodan_ports || []).length) {
      chips.push(h("span", { class: "chip chip--neutral chip--mono" }, `ports: ${shodan.shodan_ports.join(", ")}`));
    }
    if (shodan && (shodan.shodan_tags || []).length) {
      chips.push(...shodan.shodan_tags.map((t) => h("span", { class: "chip chip--neutral" }, t)));
    }
  } else if (category === "domains") {
    if ((d.nameservers || []).length) chips.push(h("span", { class: "chip chip--neutral chip--mono" }, d.nameservers[0]));
    for (const ip of (d.resolved || [])) chips.push(h("span", { class: "chip chip--neutral chip--mono" }, ip));
  }
  const threatfox = latestObservationBySource(profile, "threatfox");
  for (const m of (threatfox ? threatfox.threatfox_matches || [] : []).slice(0, 3)) {
    chips.push(h("span", { class: "chip", style: "background:var(--track-in-network-bg);color:var(--track-in-network-ink)" },
      m.malware || m.threat_type || "IOC match"));
  }

  const header = h("div", { class: "view-header" },
    h("div", { class: "view-title mono" }, o.value),
    h("div", { class: "view-sub" },
      lifecycleStatusChip(o.status), " ",
      `first seen ${formatDateOnly(o.first_seen) || "—"} · last seen ${formatDateOnly(o.last_seen) || "—"}`));

  const timelineWrap = h("div", {});
  let expanded = false;
  const toggle = h("button", { class: "category-pill", onclick: () => {
    expanded = !expanded;
    toggle.textContent = expanded ? "Hide history" : "Show history";
    timelineWrap.textContent = "";
    if (expanded) {
      const events = buildProfileTimeline(profile);
      timelineWrap.appendChild(events.length
        ? h("div", { class: "card" }, ...events)
        : h("div", { class: "empty-state" }, "No history yet — run pivot_cluster to start tracking this indicator."));
    }
  } }, "Show history");

  return h("div", { class: "card" }, header,
    chips.length ? h("div", { class: "link-list" }, ...chips) : null,
    h("div", { class: "filter-row" }, toggle), timelineWrap);
}

// Hashes are the one observable category with two genuinely different
// kinds of value under one bucket: a certificate's own SHA256 fingerprint
// (auto-filed by pivot_cluster from Cert Spotter for an already-tracked
// domain - see core.py's _file_cert_hash) vs. an actual malware file hash
// (added by hand, typically via add_observable's metadata= param after a
// VirusTotal pivot - see core._record_vt_file_hashes). The `cert-sha256:`
// value prefix already makes this unambiguous in the raw value, but the
// explicit hash_kind field (when present) plus this dedicated table make
// it visible without reading the value string closely - the user's own
// ask: never let a certificate hash be mistaken for a file hash.
function isCertHash(o) {
  return o.hash_kind === "certificate" || o.value.startsWith("cert-sha256:");
}

function renderHashesTable(items) {
  return h("div", { class: "table-wrap" }, h("table", { class: "data-table" },
    h("thead", {}, h("tr", {}, h("th", {}, "Value"), h("th", {}, "Type"), h("th", {}, "Detail"),
      h("th", {}, "First seen"), h("th", {}, "Last seen"), h("th", {}, "Sources"))),
    h("tbody", {}, ...items.map((o) => {
      const isCert = isCertHash(o);
      const typeChip = isCert
        ? h("span", { class: "chip", style: "background:var(--track-in-network-bg);color:var(--track-in-network-ink)" }, "Certificate hash")
        : (o.filenames || []).length
          ? h("span", { class: "chip chip--neutral" }, "File hash")
          : h("span", { class: "chip chip--neutral" }, "Hash");
      let detail;
      if (isCert) {
        detail = h("div", {},
          o.cert_for ? h("span", { class: "chip chip--mono chip--neutral" }, o.cert_for) : "—",
          o.cert_revoked ? h("span", { class: "chip", style: "background:var(--track-absent-bg);color:var(--track-absent-ink);margin-left:4px;" }, "revoked") : null);
      } else if ((o.filenames || []).length) {
        detail = h("div", { class: "mono" }, o.filenames.join(", "));
      } else {
        detail = "—";
      }
      return h("tr", {},
        h("td", { class: "mono" }, o.value),
        h("td", {}, typeChip),
        h("td", {}, detail),
        h("td", { class: "mono" }, formatDateOnly(o.first_seen) || "—"),
        h("td", { class: "mono" }, formatDateOnly(o.last_seen) || "—"),
        h("td", {}, h("div", { class: "link-list" }, ...(o.sources || []).slice(0, 3).map((s) => sourceLink(s, "hashes", o.value)))));
    }))));
}

async function renderObservables(data) {
  const cats = Object.entries(data.observables).filter(([, v]) => v.length > 0);
  if (!cats.length) return h("div", { class: "empty-state" }, "No observables tracked yet.");
  let active = cats[0][0];
  const pillsRow = h("div", { class: "filter-row" });
  const searchInput = h("input", { type: "search", placeholder: "Filter values…", oninput: () => draw() });
  const tableWrap = h("div", { class: "table-wrap" });
  const profileCache = new Map(); // observable value -> tracking-history fetch (once per value)
  let drawToken = 0;

  function fetchProfile(value) {
    if (!profileCache.has(value)) {
      profileCache.set(value, api(`/api/tracking/observables/${encodeURIComponent(value)}`)
        .catch((e) => ({ error: String(e) })));
    }
    return profileCache.get(value);
  }

  async function draw() {
    const myToken = ++drawToken;
    pillsRow.textContent = "";
    pillsRow.appendChild(h("div", { class: "category-pills" }, ...cats.map(([cat, items]) =>
      h("button", { class: "category-pill" + (cat === active ? " is-active" : ""), onclick: () => { active = cat; draw(); } },
        CATEGORY_LABELS[cat] || cat, h("span", { class: "num" }, items.length)))));
    const f = searchInput.value.trim().toLowerCase();
    const items = cats.find(([c]) => c === active)[1].filter((o) => !f || o.value.toLowerCase().includes(f));
    tableWrap.textContent = "";
    if (!items.length) { tableWrap.appendChild(h("div", { class: "empty-state" }, "No matching values.")); return; }
    if (FINGERPRINT_CATEGORIES.has(active)) { tableWrap.appendChild(renderFingerprintTable(items)); return; }
    if (active === "hashes") { tableWrap.appendChild(renderHashesTable(items)); return; }
    if (PROFILE_CATEGORIES.has(active)) {
      tableWrap.appendChild(h("div", { class: "empty-state" }, "Loading profiles…"));
      const profiles = await Promise.all(items.map((o) => fetchProfile(o.value)));
      if (myToken !== drawToken) return; // a newer draw (search/pill switch) superseded this one
      tableWrap.textContent = "";
      tableWrap.appendChild(h("div", {}, ...items.map((o, i) => renderObservableProfileCard(o, active, profiles[i]))));
      return;
    }
    tableWrap.appendChild(h("table", { class: "data-table" },
      h("thead", {}, h("tr", {}, h("th", {}, "Value"), h("th", {}, "First seen"), h("th", {}, "Last seen"), h("th", {}, "Sources"))),
      h("tbody", {}, ...items.map((o) => h("tr", {},
        h("td", { class: "mono" }, o.value),
        h("td", { class: "mono" }, formatDateOnly(o.first_seen) || "—"),
        h("td", { class: "mono" }, formatDateOnly(o.last_seen) || "—"),
        h("td", {}, h("div", { class: "link-list" }, ...(o.sources || []).slice(0, 3).map((s) => sourceLink(s, active, o.value)))))))));
  }
  const container = h("div", {}, pillsRow, h("div", { class: "filter-row" }, searchInput), tableWrap);
  await draw();
  return container;
}

function renderDetections(data) {
  if (!data.detections.length) return h("div", { class: "empty-state" }, "No detections filed against this cluster yet.");
  return h("div", { class: "table-wrap" }, h("table", { class: "data-table" },
    h("thead", {}, h("tr", {}, h("th", {}, "ID"), h("th", {}, "Description"), h("th", {}, "Status"), h("th", {}, "Covers"))),
    h("tbody", {}, ...data.detections.map((d) => h("tr", {},
      h("td", { class: "mono" }, d.id),
      h("td", {}, d.description),
      h("td", {}, detStatusChip(d.status)),
      h("td", {}, h("div", { class: "link-list" }, ...(d.covers_ttps || d.technique_ids || []).map((t) => h("span", { class: "chip chip--mono chip--neutral" }, t)))))))));
}

function gapItem(g) {
  return h("div", { class: "gap-item" },
    h("div", { class: "gap-item__head" }, priorityChip(g.priority), h("span", { class: "gap-item__date" }, formatDate(g.created))),
    h("div", { class: "gap-item__body" }, g.description));
}

function renderGaps(data) {
  if (!data.gaps.length) return h("div", { class: "empty-state" }, "No open gaps.");
  const order = { high: 0, medium: 1, low: 2 };
  const sorted = [...data.gaps].sort((a, b) => (order[a.priority] ?? 3) - (order[b.priority] ?? 3));
  return h("div", { class: "card" }, ...sorted.map(gapItem));
}

function renderHuntLog(data) {
  if (!data.hunt_log.length) return h("div", { class: "empty-state" }, "No hunt log entries yet.");
  const sorted = [...data.hunt_log].sort((a, b) => b.date.localeCompare(a.date));
  return h("div", { class: "card" }, ...sorted.map((e) => h("div", { class: "timeline-item" },
    h("div", { class: "timeline-item__head" }, h("span", { class: "timeline-item__date" }, formatDate(e.date))),
    h("div", { class: "timeline-item__body" }, e.entry))));
}

function reportSourceCell(source) {
  let parsed = null;
  try { parsed = new URL(source); } catch (_) { /* local path (e.g. from a file-based ingest_report call), not a URL */ }
  if (parsed && (parsed.protocol === "http:" || parsed.protocol === "https:")) {
    return h("a", { class: "source-link", href: source, target: "_blank", rel: "noopener noreferrer" }, source);
  }
  return h("span", { class: "source-note" }, source);
}

function techniqueChip(id) {
  return h("a", { class: "chip chip--mono chip--neutral", style: "text-decoration:none;", href: `#/techniques/${encodeURIComponent(id)}` }, id);
}

// report_sources is one entry per ingest_report call against this cluster
// (core.py appends, never overwrites) - re-running ingest_report on a
// source already fully merged just files another entry with all-zero
// counts (see _merge_observables: `added` only counts values not already
// tracked). Grouping by source here keeps that repeat-ingest history
// (visible via the "x N" badge's tooltip) without showing N near-identical
// rows for what's operationally a single report.
function groupReportSources(reports) {
  const bySource = new Map();
  for (const r of reports) {
    if (!bySource.has(r.source)) bySource.set(r.source, []);
    bySource.get(r.source).push(r);
  }
  return [...bySource.values()].map((entries) => {
    const attempts = [...entries].sort((a, b) => (a.ingested || "").localeCompare(b.ingested || ""));
    const counts = {};
    for (const a of attempts) {
      for (const [cat, v] of Object.entries(a.observables_found || {})) counts[cat] = (counts[cat] || 0) + v;
    }
    const ttps = [...new Set(attempts.flatMap((a) => a.ttps_found || []))];
    const skippedByKey = new Map();
    for (const a of attempts) {
      for (const s of a.fingerprint_queue_skipped || []) skippedByKey.set(`${s.category}:${s.value}`, s);
    }
    return {
      source: attempts[0].source, attempts, observableCounts: counts, ttps,
      skipped: [...skippedByKey.values()],
      lastIngested: attempts[attempts.length - 1].ingested,
    };
  });
}

function renderReports(data) {
  const reports = data.report_sources || [];
  if (!reports.length) return h("div", { class: "empty-state" }, "No reports ingested into this cluster yet.");
  const grouped = groupReportSources(reports).sort((a, b) => (b.lastIngested || "").localeCompare(a.lastIngested || ""));
  return h("div", { class: "table-wrap" }, h("table", { class: "data-table" },
    h("thead", {}, h("tr", {},
      h("th", {}, "Ingested"), h("th", {}, "Source"), h("th", {}, "Times"),
      h("th", {}, "Observables found"), h("th", {}, "TTPs found"), h("th", {}, "Skipped"))),
    h("tbody", {}, ...grouped.map((g) => {
      const total = Object.values(g.observableCounts).reduce((a, v) => a + v, 0);
      const breakdown = Object.entries(g.observableCounts).filter(([, v]) => v > 0)
        .map(([cat, v]) => `${CATEGORY_LABELS[cat] || cat} ${v}`).join(", ");
      return h("tr", {},
        h("td", { class: "mono" }, formatDate(g.attempts[0].ingested)),
        h("td", {}, reportSourceCell(g.source)),
        h("td", {}, g.attempts.length > 1
          ? h("span", {
              class: "chip chip--neutral", title: g.attempts.map((a) => {
                const n = Object.values(a.observables_found || {}).reduce((x, v) => x + v, 0);
                return `${formatDate(a.ingested)} — ${n} observables, ${(a.ttps_found || []).length} ttps`;
              }).join("\n"),
            }, `×${g.attempts.length}`)
          : "—"),
        h("td", { title: breakdown || undefined }, String(total)),
        h("td", {}, g.ttps.length
          ? h("div", { class: "link-list" }, ...g.ttps.slice(0, 6).map(techniqueChip),
              g.ttps.length > 6 ? h("span", { class: "chip chip--neutral" }, `+${g.ttps.length - 6}`) : null)
          : h("span", { class: "source-note" }, "none")),
        h("td", {}, g.skipped.length
          ? h("span", { class: "chip chip--neutral", title: g.skipped.map((s) => `${s.value}: ${s.reason}`).join("\n") }, String(g.skipped.length))
          : "—"));
    }))));
}

function renderRelationships(data) {
  const rels = data.relationships || [];
  if (!rels.length) return h("div", { class: "empty-state" }, "No relationships recorded.");
  return h("div", { class: "card" }, ...rels.map((r) => h("div", { class: "rel-item" },
    h("div", { class: "rel-item__head" }, h("span", { class: "chip chip--neutral" }, r.relationship_type), clusterChip(r.target_cluster), h("span", { class: "rel-item__date" }, formatDate(r.created))),
    r.description ? h("div", { class: "gap-item__body" }, r.description) : null)));
}

async function viewCluster(slug, tab) {
  const data = await api(`/api/clusters/${encodeURIComponent(slug)}`);
  const tabs = [
    ["diamond", "Diamond", null],
    ["reports", "Reports", groupReportSources(data.report_sources || []).length],
    ["ttps", "TTPs", data.ttps.length],
    ["observables", "Observables", Object.values(data.observables).reduce((a, v) => a + v.length, 0)],
    ["detections", "Detections", data.detections.length],
    ["gaps", "Gaps", data.gaps.length],
    ["hunt_log", "Hunt log", data.hunt_log.length],
  ];
  if ((data.relationships || []).length) tabs.push(["relationships", "Relationships", data.relationships.length]);
  const activeTab = tabs.some((t) => t[0] === tab) ? tab : "diamond";

  const header = h("div", { class: "cluster-header" },
    h("div", { class: "cluster-header__title-row" }, h("div", { class: "cluster-header__name" }, data.name), confidenceBadge(data.confidence)),
    data.aliases.length ? h("div", { class: "cluster-header__aliases" }, ...data.aliases.map((a) => h("span", { class: "chip chip--neutral" }, a))) : null,
    h("div", { class: "cluster-header__desc" }, data.description),
    h("div", { class: "cluster-header__meta" },
      h("span", {}, "First seen ", h("b", {}, formatDateOnly(data.first_seen) || "—")),
      h("span", {}, "Last seen ", h("b", {}, formatDateOnly(data.last_seen) || "—")),
      h("span", {}, "STIX ID ", h("b", { style: "font-family:var(--font-mono);font-size:11.5px;font-weight:500;" }, data.stix_id))));

  const tabStrip = h("div", { class: "tabs" }, ...tabs.map(([key, label, count]) =>
    h("button", { class: "tab" + (key === activeTab ? " is-active" : ""), onclick: () => { location.hash = `#/cluster/${slug}/${key}`; } },
      label, count != null ? h("span", { class: "tab__count" }, count) : null)));

  const renderers = {
    diamond: renderDiamond, reports: renderReports, ttps: renderTtps, observables: renderObservables,
    detections: renderDetections, gaps: renderGaps, hunt_log: renderHuntLog, relationships: renderRelationships,
  };
  const body = await renderers[activeTab](data); // renderObservables is async; await is a no-op for the rest
  return h("div", {}, header, tabStrip, body);
}

/* ---------- technique matrix ---------- */
async function viewTechniques() {
  const res = await api("/api/techniques");
  const techniques = res.techniques.slice().sort((a, b) => b.used_by.length - a.used_by.length);
  const tableWrap = h("div", { class: "table-wrap" });
  const input = h("input", { type: "search", placeholder: "Filter by technique ID or name…", oninput: (e) => draw(e.target.value) });
  function draw(filter = "") {
    const f = filter.trim().toLowerCase();
    const rows = techniques.filter((t) => !f || t.technique_id.toLowerCase().includes(f) || t.name.toLowerCase().includes(f));
    tableWrap.textContent = "";
    if (!rows.length) { tableWrap.appendChild(h("div", { class: "empty-state" }, "No matching techniques.")); return; }
    tableWrap.appendChild(h("table", { class: "data-table" },
      h("thead", {}, h("tr", {}, h("th", {}, "Technique"), h("th", {}, "Name"), h("th", {}, "Used by"), h("th", {}, "Detections"))),
      h("tbody", {}, ...rows.map((t) => h("tr", {},
        h("td", { class: "mono" }, h("a", { href: `#/techniques/${t.technique_id}`, style: "color:var(--accent);text-decoration:none;font-weight:600;" }, t.technique_id)),
        h("td", {}, t.name),
        h("td", {}, h("div", { class: "link-list" },
          h("span", { class: "num", style: "font-family:var(--font-mono);margin-right:4px;" }, t.used_by.length),
          ...t.used_by.slice(0, 4).map((u) => clusterChip(u.cluster)),
          t.used_by.length > 4 ? h("span", { class: "chip chip--neutral" }, `+${t.used_by.length - 4}`) : null)),
        h("td", { class: "num" }, String(t.detections.length)))))));
  }
  draw();
  return h("div", {},
    h("div", { class: "view-header" },
      h("div", { class: "view-title" }, "Technique matrix"),
      h("div", { class: "view-sub" }, `${techniques.length} distinct ATT&CK techniques logged across every tracked cluster.`)),
    h("div", { class: "filter-row" }, input), tableWrap);
}

async function viewTechniqueDetail(id) {
  const t = await api(`/api/techniques/${encodeURIComponent(id)}`);
  const usedBy = h("div", { class: "card" },
    h("div", { class: "card__title" }, `Used by (${t.used_by.length})`),
    ...(t.used_by.length
      ? [h("div", { class: "table-wrap" }, h("table", { class: "data-table" },
          h("thead", {}, h("tr", {}, h("th", {}, "Cluster"), h("th", {}, "Coverage"), h("th", {}, "Notes"))),
          h("tbody", {}, ...t.used_by.map((u) => h("tr", {}, h("td", {}, clusterChip(u.cluster)), h("td", {}, coverageChip(u.status)), h("td", {}, u.notes))))))]
      : [h("div", { class: "empty-state" }, "No tracked cluster currently logs this technique.")]));
  const detections = t.detections.length ? h("div", { class: "card" },
    h("div", { class: "card__title" }, `Detections (${t.detections.length})`),
    ...t.detections.map((d) => h("div", { class: "gap-item" },
      h("div", { class: "gap-item__head" }, h("span", { class: "chip chip--mono chip--neutral" }, d.id), detStatusChip(d.status)),
      h("div", { class: "gap-item__body" }, d.description)))) : null;
  return h("div", {},
    h("div", { class: "view-header" },
      h("div", { class: "view-title" }, `${t.technique_id} — ${t.name}`),
      h("div", { class: "view-sub" }, h("a", { href: "#/techniques", style: "color:var(--accent);" }, "← back to technique matrix"))),
    usedBy, detections);
}

/* ---------- fingerprint queue ---------- */
async function viewQueue() {
  const items = await api("/api/pending-fingerprints");
  const header = h("div", { class: "view-header" },
    h("div", { class: "view-title" }, "Fingerprint queue"),
    h("div", { class: "view-sub" }, "Domains/IPs tracked since the last JA4+/JARM probe pass — not yet actively fingerprinted."));
  if (!items.length) return h("div", {}, header, h("div", { class: "empty-state" }, "Queue is empty — everything tracked has been probed."));
  return h("div", {}, header, h("div", { class: "table-wrap" }, h("table", { class: "data-table" },
    h("thead", {}, h("tr", {}, h("th", {}, "Cluster"), h("th", {}, "Category"), h("th", {}, "Value"), h("th", {}, "Queued"))),
    h("tbody", {}, ...items.map((i) => h("tr", {},
      h("td", {}, clusterChip(i.cluster)),
      h("td", {}, CATEGORY_LABELS[i.category] || i.category),
      h("td", { class: "mono" }, i.value),
      h("td", { class: "mono" }, formatDate(i.queued_at))))))));
}

/* ---------- live tracking ---------- */
const TRACKING_STATUS_ORDER = { "in-network": 0, active: 1, moved: 2, quiet: 3, absent: 4, "never-enriched": 5 };

function trackingRefreshButton() {
  return h("button", {
    style: "background:none;border:none;padding:0;font:inherit;font-weight:600;color:var(--accent);cursor:pointer;text-decoration:underline;",
    onclick: () => render(),
  }, "Refresh");
}

async function viewTracking() {
  const res = await api("/api/tracking/observables");
  const header = h("div", { class: "view-header" },
    h("div", { class: "view-title" }, "Live tracking"),
    h("div", { class: "view-sub" },
      `${res.count} tracked indicator${res.count === 1 ? "" : "s"} — status derived from the daily enrichment pipeline. `,
      trackingRefreshButton()));
  if (!res.observables.length) return h("div", {}, header, h("div", { class: "empty-state" }, "No tracked indicators yet."));

  const rows = [...res.observables].sort((a, b) =>
    (TRACKING_STATUS_ORDER[a.status] ?? 9) - (TRACKING_STATUS_ORDER[b.status] ?? 9)
    || a.indicator_value.localeCompare(b.indicator_value));

  const tableWrap = h("div", { class: "table-wrap" }, h("table", { class: "data-table" },
    h("thead", {}, h("tr", {},
      h("th", {}, "Indicator"), h("th", {}, "Status"), h("th", {}, "Actor"),
      h("th", {}, "Latest honeylabs"), h("th", {}, "ASN"), h("th", {}, "Last Zeek match"))),
    h("tbody", {}, ...rows.map((r) => h("tr", {},
      h("td", {}, trackingIpChip(r.indicator_value)),
      h("td", {}, trackingStatusChip(r.status)),
      h("td", {}, r.actor || "—"),
      h("td", { class: "mono" }, r.hl_observed_at ? `${formatDate(r.hl_observed_at)} (${r.hl_events ?? 0} events)` : "—"),
      h("td", { class: "mono" }, r.asn != null ? `AS${r.asn} ${r.netname || ""}` : "—"),
      h("td", { class: "mono" }, r.zeek_day ? `${r.zeek_day} (${r.zeek_direction}, ${r.zeek_hit_count} hits)` : "—"))))));
  return h("div", {}, header, tableWrap);
}

function trackingEventItem(ip, e) {
  if (e.kind === "asn_change") {
    const c = e.data;
    return h("div", { class: "timeline-item" },
      h("div", { class: "timeline-item__head" },
        h("span", { class: "timeline-item__date" }, formatDate(e.date)),
        h("span", { class: "chip chip--neutral" }, c.change_type),
        h("span", { class: "chip chip--neutral" }, c.confidence)),
      h("div", { class: "timeline-item__body" },
        `AS${c.old_asn ?? "?"} (${c.old_netname || "—"}) → AS${c.new_asn ?? "?"} (${c.new_netname || "—"})`));
  }
  const o = e.data;
  // hl_ports/hl_tags (HoneyLabs) and shodan_ports/shodan_tags (Shodan
  // InternetDB) are mutually exclusive per row (one source per
  // observation) - show whichever this row actually carries.
  //
  // Deliberately no Arkime link here: this row's ports/tags come from
  // HoneyLabs/Shodan enrichment, not from a probe this lab actually ran -
  // there's no basis for expecting a local capture to exist for it (see
  // arkimeSessionUrl, which only ever fires from a genuine probe/Zeek-
  // passive provenance string).
  const ports = (o.hl_ports && o.hl_ports.length) ? o.hl_ports : (o.shodan_ports || []);
  const tags = (o.hl_tags && o.hl_tags.length) ? o.hl_tags : (o.shodan_tags || []);
  const matches = (o.threatfox_matches || []).map((m) => m.malware || m.threat_type).filter(Boolean);
  const detail = [o.asn != null ? `AS${o.asn} ${o.netname || ""}` : null, o.country_code,
    ports.length ? `ports: ${ports.join(", ")}` : null,
    tags.length ? `tags: ${tags.join(", ")}` : null,
    matches.length ? `threatfox: ${matches.join(", ")}` : null].filter(Boolean).join(" · ");
  // Most sources' checks come back empty most days (e.g. "no ThreatFox
  // match today") - skip the row entirely rather than render a dash-only
  // timeline item; the daily pivot sweep would otherwise pile these up
  // indefinitely. hl_events is checked separately since it renders as a
  // head chip, not part of `detail`.
  if (!detail && o.hl_events == null) return null;
  return h("div", { class: "timeline-item" },
    h("div", { class: "timeline-item__head" },
      h("span", { class: "timeline-item__date" }, formatDate(e.date)),
      h("span", { class: "chip chip--neutral" }, o.source),
      o.hl_events != null ? h("span", { class: "chip chip--neutral" }, `${o.hl_events} events`) : null),
    h("div", { class: "timeline-item__body" }, detail || "—"));
}

function trackingZeekTable(zeekMatches) {
  if (!zeekMatches.length) return null;
  return h("div", { class: "table-wrap" }, h("table", { class: "data-table" },
    h("thead", {}, h("tr", {}, h("th", {}, "Day"), h("th", {}, "Direction"), h("th", {}, "Hits"), h("th", {}, "Ports"))),
    h("tbody", {}, ...[...zeekMatches].reverse().map((z) => h("tr", {},
      h("td", { class: "mono" }, z.day),
      h("td", {}, z.direction),
      h("td", { class: "mono" }, String(z.hit_count)),
      h("td", { class: "mono" }, (z.ports || []).join(", ") || "—"))))));
}

async function viewTrackingDetail(ip) {
  const data = await api(`/api/tracking/observables/${encodeURIComponent(ip)}`);
  const header = h("div", { class: "view-header" },
    h("div", { class: "view-title" }, data.ip),
    h("div", { class: "view-sub" },
      trackingStatusChip(data.status), " ",
      h("a", { href: "#/tracking", style: "color:var(--accent);margin-left:8px;" }, "← back to live tracking"),
      " ", trackingRefreshButton()));

  const events = [
    ...data.observations.map((o) => ({ date: o.observed_at, kind: "observation", data: o })),
    ...data.asn_changes.map((c) => ({ date: c.detected_at, kind: "asn_change", data: c })),
  ].sort((a, b) => b.date.localeCompare(a.date));

  const items = events.map((e) => trackingEventItem(ip, e)).filter(Boolean);
  const hiddenCount = events.length - items.length;

  const hiddenNote = items.length && hiddenCount ? h("div", { class: "view-sub" },
    `${hiddenCount} check${hiddenCount === 1 ? "" : "s"} with no findings hidden.`) : null;

  const timeline = items.length
    ? h("div", { class: "card" }, ...items)
    : events.length
      ? h("div", { class: "empty-state" },
          `${events.length} check${events.length === 1 ? "" : "s"} completed with nothing to report.`)
      : h("div", { class: "empty-state" }, "No observation history yet — this indicator is tracked but not yet enriched.");

  const zeekTable = trackingZeekTable(data.zeek_matches);
  const zeekCard = zeekTable ? h("div", { class: "card" },
    h("div", { class: "card__title" }, "Zeek matches"), zeekTable) : null;

  return h("div", {}, header, hiddenNote, timeline, zeekCard);
}

/* ---------- daily narrative ---------- */
// Stage B's narrative is Claude-authored markdown over ingested,
// sometimes adversary-influenced, report content - same "never
// innerHTML on data-derived text" rule as the rest of this file (see
// the h() comment up top). This renders a small markdown subset
// (##/### headers, -/* and N. lists, **bold** inline) directly to DOM
// nodes via h(), so there is no HTML string ever parsed from the file.
function renderInline(text) {
  return text.split(/(\*\*[^*]+\*\*)/g).map((part) => {
    const m = part.match(/^\*\*([^*]+)\*\*$/);
    return m ? h("strong", {}, m[1]) : part;
  });
}

function renderMarkdownLite(text) {
  const container = h("div", { class: "narrative-body" });
  let list = null;
  let listOrdered = false;
  for (const raw of text.split("\n")) {
    const line = raw.trimEnd();
    if (!line.trim()) { list = null; continue; }
    const heading = line.match(/^#{1,3}\s+(.*)$/);
    if (heading) { list = null; container.appendChild(h("div", { class: "card__title" }, heading[1])); continue; }
    const bullet = line.match(/^[-*]\s+(.*)$/);
    const numbered = line.match(/^\d+\.\s+(.*)$/);
    if (bullet || numbered) {
      const ordered = !!numbered;
      if (!list || listOrdered !== ordered) {
        list = h(ordered ? "ol" : "ul", { class: "narrative-list" });
        listOrdered = ordered;
        container.appendChild(list);
      }
      list.appendChild(h("li", {}, ...renderInline((bullet || numbered)[1])));
      continue;
    }
    list = null;
    container.appendChild(h("p", { class: "narrative-p" }, ...renderInline(line)));
  }
  return container;
}

async function viewNarratives() {
  const res = await api("/api/tracking/narratives");
  const header = h("div", { class: "view-header" },
    h("div", { class: "view-title" }, "Daily narrative"),
    h("div", { class: "view-sub" }, "Stage B's analyst writeup over each day's tracking digest — skipped on quiet days."));
  if (!res.dates.length) return h("div", {}, header, h("div", { class: "empty-state" }, "No narratives written yet."));
  return h("div", {}, header, h("div", { class: "card" },
    ...res.dates.map((d) => h("div", { class: "timeline-item" },
      h("div", { class: "timeline-item__head" },
        h("a", { href: `#/narratives/${d}`, style: "color:var(--accent);font-weight:600;text-decoration:none;" }, d))))));
}

async function viewNarrativeDetail(day) {
  const header = h("div", { class: "view-header" },
    h("div", { class: "view-title" }, `Narrative — ${day}`),
    h("div", { class: "view-sub" }, h("a", { href: "#/narratives", style: "color:var(--accent);" }, "← back to daily narrative")));
  let res;
  try {
    res = await api(`/api/tracking/narratives/${encodeURIComponent(day)}`);
  } catch (err) {
    return h("div", {}, header, h("div", { class: "empty-state" }, `No narrative found for ${day}.`));
  }
  return h("div", {}, header, h("div", { class: "card" }, renderMarkdownLite(res.content)));
}

/* ---------- observable search ---------- */
function observableGroup(title, items) {
  return h("div", { class: "search-group" },
    h("div", { class: "search-group__title" }, title),
    h("div", { class: "table-wrap" }, h("table", { class: "data-table" },
      h("thead", {}, h("tr", {}, h("th", {}, "Value"), h("th", {}, "Category"), h("th", {}, "Cluster"), h("th", {}, "First seen"), h("th", {}, "Last seen"))),
      h("tbody", {}, ...items.map((o) => h("tr", {},
        h("td", { class: "mono" }, o.value),
        h("td", {}, CATEGORY_LABELS[o.category] || o.category),
        h("td", {}, clusterChip(o.cluster)),
        h("td", { class: "mono" }, formatDateOnly(o.first_seen) || "—"),
        h("td", { class: "mono" }, formatDateOnly(o.last_seen) || "—")))))));
}

async function viewSearch(query) {
  const header = h("div", { class: "view-header" },
    h("div", { class: "view-title" }, "Observable search"),
    h("div", { class: "view-sub" }, query ? `Results for "${query}"` : "Enter a hash, domain, IP, or fingerprint above."));
  if (!query) return h("div", {}, header);
  const res = await api(`/api/observables/search?q=${encodeURIComponent(query)}`);
  if (!res.exact.length && !res.partial.length) return h("div", {}, header, h("div", { class: "empty-state" }, "No matches found."));
  const groups = [];
  if (res.exact.length) groups.push(observableGroup(`Exact matches (${res.exact.length})`, res.exact));
  if (res.partial.length) groups.push(observableGroup(`Partial matches (${res.partial.length})`, res.partial));
  return h("div", {}, header, ...groups);
}

/* ---------- router ---------- */
function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const parts = raw.split("/").filter(Boolean).map(decodeURIComponent);
  if (!parts.length) return { name: "overview" };
  if (parts[0] === "cluster") return { name: "cluster", slug: parts[1], tab: parts[2] || "diamond" };
  if (parts[0] === "techniques") return { name: "techniques", id: parts[1] };
  if (parts[0] === "queue") return { name: "queue" };
  if (parts[0] === "tracking") return { name: "tracking", ip: parts[1] };
  if (parts[0] === "narratives") return { name: "narratives", date: parts[1] };
  if (parts[0] === "search") return { name: "search", query: parts.slice(1).join("/") };
  return { name: "overview" };
}

async function render() {
  const route = parseHash();
  updateActiveStates(route);
  const view = document.getElementById("view");
  view.textContent = "";
  view.appendChild(h("div", { class: "loading" }, "Loading…"));
  try {
    let node;
    if (route.name === "overview") node = await viewOverview();
    else if (route.name === "cluster") node = await viewCluster(route.slug, route.tab);
    else if (route.name === "techniques") node = route.id ? await viewTechniqueDetail(route.id) : await viewTechniques();
    else if (route.name === "queue") node = await viewQueue();
    else if (route.name === "tracking") node = route.ip ? await viewTrackingDetail(route.ip) : await viewTracking();
    else if (route.name === "narratives") node = route.date ? await viewNarrativeDetail(route.date) : await viewNarratives();
    else if (route.name === "search") node = await viewSearch(route.query);
    else node = h("div", { class: "empty-state" }, "Not found.");
    view.textContent = "";
    view.appendChild(node);
    view.focus();
  } catch (err) {
    view.textContent = "";
    view.appendChild(h("div", { class: "empty-state" }, `Failed to load: ${err.message}`));
  }
}

/* ---------- theme ---------- */
function initTheme() {
  const saved = localStorage.getItem("cti-theme");
  if (saved) document.documentElement.setAttribute("data-theme", saved);
  document.getElementById("theme-toggle").addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme")
      || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("cti-theme", next);
  });
}

/* ---------- init ---------- */
document.getElementById("global-search-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const q = document.getElementById("global-search-input").value.trim();
  if (q) location.hash = `#/search/${encodeURIComponent(q)}`;
});
document.getElementById("cluster-filter").addEventListener("input", (e) => renderClusterList(state.clusters, e.target.value));
window.addEventListener("hashchange", render);

initTheme();
initSidebar().then(render);
