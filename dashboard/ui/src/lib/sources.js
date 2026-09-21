// Provenance -> link. Ported from the old app.js, including the rule that
// matters most: an Arkime link is built ONLY from a genuine probe or
// Zeek-passive provenance string, never from HoneyLabs enrichment. Those
// have no relationship to this lab's own captured traffic, and an earlier
// version that linked them produced a link that (correctly) usually showed
// nothing.
import { truncate } from "./format.js";

const JARM_SOURCE_RE = /^JARM against (.+):(\d+) via .+, (\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?)$/;
const ZEEK_SOURCE_RE = /^Zeek passive \(tap107, via OpenSearch\) handshake against (.+):(\d+) \(([\d.]+)\), (\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?)$/;
const ARKIME_BASE = "http://10.20.0.18:8005/sessions";
// Wide enough for a little clock/ingestion lag, tight enough that the link
// points at "when probing took place" rather than a whole-day guess.
const ARKIME_PROBE_WINDOW_SECS = 5 * 60;

export function parseProbeSource(source) {
  const zeek = source.match(ZEEK_SOURCE_RE);
  if (zeek) return { target: zeek[1], port: zeek[2], ip: zeek[3], when: zeek[4] };
  const jarm = source.match(JARM_SOURCE_RE);
  if (jarm) {
    // A JARM probe fires at the tracked name before any Zeek-side DNS
    // resolution is recorded, so the target is only Arkime-queryable when
    // it already looks like an IP.
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(jarm[1]);
    return { target: jarm[1], port: jarm[2], ip: isIp ? jarm[1] : null, when: jarm[3] };
  }
  return null;
}

export function arkimeSessionUrl(source) {
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

function pivotSourceUrl(source, category, value) {
  if (/VirusTotal/i.test(source)) {
    const bare = category === "hashes" && value.includes(":") ? value.split(":", 2)[1] : value;
    return { url: `https://www.virustotal.com/gui/search/${encodeURIComponent(bare)}`, label: "VirusTotal" };
  }
  return arkimeSessionUrl(source);
}

// -> {kind: "link", url, label, title?} | {kind: "note", text, title}
export function describeSource(source, category, value) {
  let parsed = null;
  try { parsed = new URL(source); } catch { /* a provenance note, not a URL */ }
  if (parsed && (parsed.protocol === "http:" || parsed.protocol === "https:")) {
    return { kind: "link", url: source, label: parsed.hostname.replace(/^www\./, "") };
  }
  const pivot = pivotSourceUrl(source, category, value);
  if (pivot) return { kind: "link", url: pivot.url, label: pivot.label, title: source };
  return { kind: "note", text: truncate(source, 42), title: source };
}
