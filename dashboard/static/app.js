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
const COVERAGE_LABELS = ["no coverage", "idea only", "built, unvalidated", "validated, in production", "validated + tuned"];
const DETECTION_STATUS = { draft: ["det-draft", "Draft"], unvalidated: ["det-unvalidated", "Unvalidated"], published: ["det-published", "Published"] };

const state = { clusters: [] };

/* ---------- shared formatting / small components ---------- */
function formatDate(iso) {
  if (!iso) return "—";
  const m = String(iso).match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/);
  return m ? `${m[1]} ${m[2]}` : String(iso);
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

function clusterChip(name) {
  const match = state.clusters.find((c) => c.name === name);
  return h("a", { class: "chip chip--neutral", style: "text-decoration:none;", href: match ? `#/cluster/${match.slug}` : "#" }, name);
}

function sourceLink(url) {
  let host = url;
  try { host = new URL(url).hostname.replace(/^www\./, ""); } catch (_) { /* not a URL, show raw text */ }
  return h("a", { class: "source-link", href: url, target: "_blank", rel: "noopener noreferrer" }, host);
}

/* ---------- sidebar ---------- */
async function initSidebar() {
  const [clusters, pending] = await Promise.all([api("/api/clusters"), api("/api/pending-fingerprints")]);
  state.clusters = clusters;
  document.getElementById("cluster-count").textContent = clusters.length;
  renderClusterList(clusters);
  const badge = document.getElementById("queue-badge");
  if (pending.length) { badge.textContent = String(pending.length); badge.hidden = false; }
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
    list.appendChild(h("a", { class: "cluster-row", href: `#/cluster/${c.slug}`, "data-slug": c.slug },
      h("div", { class: "cluster-row__top" },
        h("span", { class: "cluster-row__dot", style: `background:${confidenceColor(c.confidence)}` }),
        h("span", { class: "cluster-row__name" }, c.name)),
      h("div", { class: "cluster-row__meta" }, c.last_seen ? `last seen ${c.last_seen}` : "no activity logged")));
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

function renderObservables(data) {
  const cats = Object.entries(data.observables).filter(([, v]) => v.length > 0);
  if (!cats.length) return h("div", { class: "empty-state" }, "No observables tracked yet.");
  let active = cats[0][0];
  const pillsRow = h("div", { class: "filter-row" });
  const searchInput = h("input", { type: "search", placeholder: "Filter values…", oninput: () => draw() });
  const tableWrap = h("div", { class: "table-wrap" });

  function draw() {
    pillsRow.textContent = "";
    pillsRow.appendChild(h("div", { class: "category-pills" }, ...cats.map(([cat, items]) =>
      h("button", { class: "category-pill" + (cat === active ? " is-active" : ""), onclick: () => { active = cat; draw(); } },
        CATEGORY_LABELS[cat] || cat, h("span", { class: "num" }, items.length)))));
    const f = searchInput.value.trim().toLowerCase();
    const items = cats.find(([c]) => c === active)[1].filter((o) => !f || o.value.toLowerCase().includes(f));
    tableWrap.textContent = "";
    if (!items.length) { tableWrap.appendChild(h("div", { class: "empty-state" }, "No matching values.")); return; }
    tableWrap.appendChild(h("table", { class: "data-table" },
      h("thead", {}, h("tr", {}, h("th", {}, "Value"), h("th", {}, "First seen"), h("th", {}, "Last seen"), h("th", {}, "Sources"))),
      h("tbody", {}, ...items.map((o) => h("tr", {},
        h("td", { class: "mono" }, o.value),
        h("td", { class: "mono" }, formatDate(o.first_seen)),
        h("td", { class: "mono" }, formatDate(o.last_seen)),
        h("td", {}, h("div", { class: "link-list" }, ...(o.sources || []).slice(0, 3).map(sourceLink))))))));
  }
  const container = h("div", {}, pillsRow, h("div", { class: "filter-row" }, searchInput), tableWrap);
  draw();
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
      h("span", {}, "First seen ", h("b", {}, data.first_seen || "—")),
      h("span", {}, "Last seen ", h("b", {}, data.last_seen || "—")),
      h("span", {}, "STIX ID ", h("b", { style: "font-family:var(--font-mono);font-size:11.5px;font-weight:500;" }, data.stix_id))));

  const tabStrip = h("div", { class: "tabs" }, ...tabs.map(([key, label, count]) =>
    h("button", { class: "tab" + (key === activeTab ? " is-active" : ""), onclick: () => { location.hash = `#/cluster/${slug}/${key}`; } },
      label, count != null ? h("span", { class: "tab__count" }, count) : null)));

  const renderers = {
    diamond: renderDiamond, ttps: renderTtps, observables: renderObservables,
    detections: renderDetections, gaps: renderGaps, hunt_log: renderHuntLog, relationships: renderRelationships,
  };
  return h("div", {}, header, tabStrip, renderers[activeTab](data));
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
        h("td", { class: "mono" }, formatDate(o.first_seen)),
        h("td", { class: "mono" }, formatDate(o.last_seen))))))));
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
