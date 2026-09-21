import { writable } from "svelte/store";
import { api } from "./api.js";

// Sidebar data, loaded once. The tracking call is allowed to fail on its
// own: the daily job holds DuckDB's write lock and answers 503 for minutes,
// and a badge failing to load must not take the cluster nav down with it.
export const clusters = writable([]);
export const pendingCount = writable(0);
export const inNetworkCount = writable(0);

export async function loadSidebar() {
  const [cs, pending, tracking] = await Promise.all([
    api("/api/clusters"),
    api("/api/pending-fingerprints").catch(() => []),
    api("/api/tracking/observables").catch(() => ({ observables: [] })),
  ]);
  clusters.set(Array.isArray(cs) ? cs : []);
  pendingCount.set(Array.isArray(pending) ? pending.length : 0);
  inNetworkCount.set(
    (tracking.observables || []).filter((o) => o.status === "in-network").length);
}
