// Ported from the old app.js rather than rewritten. The padding rule in
// formatDateOnly mirrors cti/clusters_render.py:_date_only - a year-month
// with no day is completed to the first, which a fresh reading does not
// suggest and which a rewrite would silently drop.
export function formatDate(value) {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
         `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

export function formatDateOnly(value) {
  if (!value) return null;
  const m = /^(\d{4})-(\d{2})(?:-(\d{2}))?/.exec(String(value));
  if (!m) return null;
  return `${m[1]}-${m[2]}-${m[3] || "01"}`;
}

export function dayOf(value) {
  return value ? String(value).slice(0, 10) : "—";
}

// Prose only. NEVER an indicator value - see IndicatorChip.
export function truncate(text, n) {
  const s = String(text ?? "");
  return s.length <= n ? s : s.slice(0, n) + "…";
}

export function humanBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return value ?? "—";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v < 10 && i ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

// A value that is worth linking to a selector page.
const HASHLIKE = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i;
export const looksLikeHash = (v) =>
  HASHLIKE.test(String(v).replace(/^(?:cert-)?sha\d*:/i, ""));
