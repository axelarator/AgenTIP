// report_sources is one entry per ingest_report call against a cluster
// (core.py appends, never overwrites). Re-running ingest_report on a source
// that is already fully merged files another entry with all-zero counts, so
// showing them raw means N near-identical rows for what is operationally one
// report. Grouped by source: the repeat history survives in the "x N" badge's
// tooltip instead of in the table.
export function groupReportSources(reports) {
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

export const isCertHash = (o) =>
  o.hash_kind === "certificate" || String(o.value).startsWith("cert-sha256:");

const PRIORITY_ORDER = { high: 0, medium: 1, low: 2 };
export const byPriority = (a, b) =>
  (PRIORITY_ORDER[a.priority] ?? 3) - (PRIORITY_ORDER[b.priority] ?? 3);
