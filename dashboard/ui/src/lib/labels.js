export const CATEGORY_LABELS = {
  hashes: "Hashes", domains: "Domains", ips: "IPs", urls: "URLs", emails: "Emails",
  cves: "CVEs", wallets: "Wallets", ja4: "JA4", ja4s: "JA4S", ja4h: "JA4H",
  ja4l: "JA4L", ja4x: "JA4X", ja4t: "JA4T", ja4ts: "JA4TS", ja4ssh: "JA4SSH", jarm: "JARM",
};
export const FINGERPRINT_CATEGORIES = new Set(
  ["ja4", "ja4s", "ja4h", "ja4l", "ja4x", "ja4t", "ja4ts", "ja4ssh", "jarm"]);
export const PROFILE_CATEGORIES = new Set(["ips", "domains"]);
export const COVERAGE_LABELS = [
  "no coverage", "idea only", "built, unvalidated",
  "validated, in production", "validated + tuned"];
export const DETECTION_STATUS = {
  draft: ["det-draft", "Draft"],
  unvalidated: ["det-unvalidated", "Unvalidated"],
  published: ["det-published", "Published"],
};

// Indicator status, for both kinds. The IP ladder and the domain ladder
// both end up here; `resolving`/`unresolved`/`silent` are the domain and
// probe-failure states that had no colour because nothing could show them.
// [css var stem, label]
export const STATUS = {
  "in-network": ["track-in-network", "In network"],
  active: ["track-active", "Active"],
  resolving: ["track-active", "Resolving"],
  moved: ["track-moved", "Moved"],
  quiet: ["track-quiet", "Quiet"],
  absent: ["track-absent", "Absent"],
  unresolved: ["pri-high", "Unresolved"],
  silent: ["pri-medium", "Silent"],
  "never-enriched": ["track-absent", "Never enriched"],
};
export const STATUS_ORDER = {
  "in-network": 0, active: 1, resolving: 1, moved: 2, unresolved: 3,
  silent: 3, quiet: 4, absent: 5, "never-enriched": 6,
};

export const LIFECYCLE = {
  active: "track-active", routed: "track-active",
  dead: "track-absent", sinkholed: "track-absent",
  expired: "track-absent", unrouted: "track-absent",
};
