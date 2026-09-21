<script>
  import { api } from "../lib/api.js";
  import { href } from "../lib/router.js";
  import { dayOf } from "../lib/format.js";
  import Busy from "../components/Busy.svelte";

  let loading = $state(true);
  let data = $state(null);
  let filter = $state("");
  let kind = $state("all");

  $effect(() => {
    api("/api/indicators")
      .then((d) => (data = d))
      .finally(() => (loading = false));
  });

  const rows = $derived(
    !data?.indicators ? [] : data.indicators.filter((r) => {
      if (kind === "domain" && !String(r.indicator_type).startsWith("domain")) return false;
      if (kind === "ip" && !String(r.indicator_type).startsWith("ip")) return false;
      const q = filter.trim().toLowerCase();
      return !q || r.indicator_value.toLowerCase().includes(q)
              || String(r.actor || "").toLowerCase().includes(q);
    }),
  );
</script>

<h1>Indicators</h1>

{#if loading}
  <p class="muted">Loading…</p>
{:else if data?.busy}
  <Busy error={data.error} />
{:else}
  <div class="controls">
    <input placeholder="Filter by value or actor…" bind:value={filter} />
    <select bind:value={kind}>
      <option value="all">all types</option>
      <option value="domain">domains</option>
      <option value="ip">addresses</option>
    </select>
    <span class="muted">{rows.length} of {data.count}</span>
  </div>

  <div class="table-wrap">
    <table class="data-table">
      <thead>
        <tr>
          <th>Indicator</th><th>Type</th><th>Actor</th>
          <th class="num">Obs</th><th class="num">Sources</th>
          <th class="num">Selectors</th><th>Last seen</th>
        </tr>
      </thead>
      <tbody>
        {#each rows as r (r.indicator_value)}
          <tr>
            <td class="mono"><a href={href.indicator(r.indicator_value)}>{r.indicator_value}</a></td>
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
{/if}

<style>
  .controls { display: flex; gap: .75rem; align-items: center; margin-bottom: 1rem; }
  .controls input { flex: 1; max-width: 26rem; padding: .4rem .6rem; }
  .muted { color: var(--muted, #6b6b76); font-size: .85rem; }
</style>
