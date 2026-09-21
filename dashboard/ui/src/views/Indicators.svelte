<script>
  import { api } from "../lib/api.js";
  import { resource } from "../lib/resource.svelte.js";
  import { href } from "../lib/router.js";
  import { dayOf } from "../lib/format.js";
  import { STATUS, STATUS_ORDER } from "../lib/labels.js";
  import Async from "../components/Async.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import Select from "../components/Select.svelte";
  import StatusChip from "../components/StatusChip.svelte";

  const res = resource(() => "/api/indicators");

  // Status is JOINED from the tracked-observables read, not computed here.
  // Two ladders already exist (IP and domain) and a test pins that they
  // agree; a third derived from this table's aggregate could disagree with
  // both. That read is scoped to tracked actors, so an indicator outside it
  // simply shows no status. A failure is quiet - the daily job holds the
  // database for minutes and the index is still useful without the column.
  let status = $state({});
  $effect(() => {
    api("/api/tracking/observables")
      .then((d) => {
        status = Object.fromEntries(
          (d.observables || []).map((o) => [o.indicator_value, o.status]));
      })
      .catch(() => {});
  });

  let filter = $state("");
  let kind = $state("all");
  let statusFilter = $state("all");

  const rows = $derived.by(() => {
    const list = (res.data?.indicators ?? []).map((r) => ({ ...r, status: status[r.indicator_value] ?? null }));
    const q = filter.trim().toLowerCase();
    return list
      .filter((r) => {
        if (kind === "domain" && !String(r.indicator_type).startsWith("domain")) return false;
        if (kind === "ip" && !String(r.indicator_type).startsWith("ip")) return false;
        if (statusFilter !== "all" && r.status !== statusFilter) return false;
        return !q || r.indicator_value.toLowerCase().includes(q)
                  || String(r.actor || "").toLowerCase().includes(q);
      })
      // Most attention-worthy first, as the old Live tracking page did.
      .sort((a, b) =>
        (STATUS_ORDER[a.status] ?? 9) - (STATUS_ORDER[b.status] ?? 9)
        || String(b.last_seen).localeCompare(String(a.last_seen))
        || a.indicator_value.localeCompare(b.indicator_value));
  });

  const statusOptions = $derived([
    { value: "all", label: "any status" },
    ...Object.keys(STATUS).filter((s) => Object.values(status).includes(s))
      .map((s) => ({ value: s, label: STATUS[s][1] })),
  ]);
</script>

<PageHeader title="Indicators"
  sub="Every domain and address that has been observed. Status comes from the daily enrichment pipeline." />

<Async {res}>
  {#snippet children(d)}
    <div class="controls">
      <input type="search" placeholder="Filter by value or actor…" bind:value={filter} />
      <Select label="type" bind:value={kind}
        options={[{ value: "all", label: "all types" },
                  { value: "domain", label: "domains" },
                  { value: "ip", label: "addresses" }]} />
      <Select label="status" bind:value={statusFilter} options={statusOptions} />
      <span class="count">{rows.length} of {d.count}</span>
    </div>

    <div class="table-wrap">
      <table class="data-table">
        <thead>
          <tr>
            <th>Indicator</th><th>Status</th><th>Type</th><th>Actor</th>
            <th class="num">Obs</th><th class="num">Sources</th>
            <th class="num">Selectors</th><th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {#each rows as r (r.indicator_value)}
            <tr>
              <td class="mono"><a href={href.indicator(r.indicator_value)}>{r.indicator_value}</a></td>
              <td>{#if r.status}<StatusChip status={r.status} />{:else}—{/if}</td>
              <td>{r.indicator_type ?? "—"}</td>
              <td>{r.actor ?? "—"}</td>
              <td class="num">{r.observations}</td>
              <td class="num">{r.sources}</td>
              <td class="num">{r.selectors}</td>
              <td>{dayOf(r.last_seen)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/snippet}
</Async>

<style>
  .controls { display: flex; gap: 12px; align-items: center; margin-bottom: 14px; flex-wrap: wrap; }
  .controls input { flex: 1; min-width: 14rem; max-width: 26rem; }
  .count { color: var(--ink-3); font-size: 13px; }
</style>
