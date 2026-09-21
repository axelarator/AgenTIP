// Ported from the old app.js rather than rewritten - each of these encodes
// a behaviour that a fresh reading would get subtly wrong.

// The API's timestamps are naive (no zone), so they are shown as written.
// The first cut of this ran them through `new Date()`, which reinterprets
// them in the browser's zone and moves every time by the UTC offset.
export function formatDate(iso) {
  if (!iso) return "—";
  const m = String(iso).match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})/);
  return m ? `${m[1]} ${m[2]}` : String(iso);
}

// Date-only, for first_seen/last_seen, which read side by side and must
// always look like YYYY-MM-DD. Cluster-level values come from free-text
// update_profile params, and real data includes "2025-09" and
// "2022-12-01T00:00:00Z" next to plain dates. Mirrors
// cti/clusters_render.py:_date_only: a day-less YYYY-MM is padded to the
// 1st, the conventional stand-in for "day unknown". Blank gives null, not
// a dash, so the caller picks its own fallback; anything without at least
// YYYY-MM passes through unmangled.
export function formatDateOnly(iso) {
  if (!iso) return null;
  const m = String(iso).match(/^(\d{4})-(\d{2})(?:-(\d{2}))?/);
  return m ? `${m[1]}-${m[2]}-${m[3] || "01"}` : String(iso);
}

export function dayOf(value) {
  return value ? String(value).slice(0, 10) : "—";
}

// Prose only. NEVER an indicator value - see IndicatorChip.
export function truncate(text, n) {
  if (!text) return "";
  return text.length > n ? text.slice(0, n).trimEnd() + "…" : text;
}

export function humanBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return value ?? "—";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v < 10 && i ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

export function confidenceColor(c) {
  if (c == null) return "var(--ink-3)";
  if (c >= 75) return "var(--cov-4-ink)";
  if (c >= 50) return "var(--cov-3-ink)";
  if (c >= 25) return "var(--cov-2-ink)";
  return "var(--cov-1-ink)";
}

// A value worth linking to a selector page.
const HASHLIKE = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i;
export const looksLikeHash = (v) =>
  HASHLIKE.test(String(v).replace(/^(?:cert-)?sha\d*:/i, ""));

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
// Hostname-shaped: labels of letters/digits/hyphens joined by dots. Underscores
// are excluded on purpose so selector type names (http.body_sha256,
// tls.cert_sha256) are never mistaken for domains.
const HOSTNAME = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
export const looksLikeIndicator = (v) => IPV4.test(v) || HOSTNAME.test(v);
