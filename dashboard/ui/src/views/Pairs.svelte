<script>
  import { resource } from "../lib/resource.svelte.js";
  import { href } from "../lib/router.js";
  import Async from "../components/Async.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import IndicatorChip from "../components/IndicatorChip.svelte";
  import Memberships from "../components/Memberships.svelte";
  import BandChip from "../components/BandChip.svelte";

  let { a, b = null } = $props();
  const res = resource(() =>
    `/api/pairs?a=${encodeURIComponent(a)}${b ? `&b=${encodeURIComponent(b)}` : ""}&limit=50`);

  const gap = (g) => g == null ? "undated" : g === 0 ? "overlapping" : `${Math.round(g)} days apart`;
</script>

{#snippet evidence(rows)}
  <div class="table-wrap">
    <table class="data-table">
      <thead><tr><th>Weight</th><th>Class</th><th>Shared</th><th>When</th><th>Note</th></tr></thead>
      <tbody>
        {#each rows as e}
          <tr>
            <td class="mono num">{e.weight.toFixed(3)}</td>
            <td>{e.class}</td>
            <td class="mono"><span class="t">{e.type}</span>={String(e.value).slice(0, 80)}
              {#if e.member && e.member !== b && e.member !== a}<span class="hint"> · via {e.member}</span>{/if}</td>
            <td>{gap(e.gap_days)}</td>
            <td class="hint">{e.note || ""}{#if e.global_count != null} {e.global_count.toLocaleString()} hits index-wide{/if}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/snippet}

<Async {res}>
  {#snippet children(d)}
    {#if b}
      <PageHeader title="Pairs" sub="What two indicators share, when each held it, and what that is worth." />
      <div class="card pair-head">
        <IndicatorChip value={d.indicator} /> <span class="arrow">⇄</span> <IndicatorChip value={d.other} />
        <BandChip band={d.band} score={d.score} />
      </div>
      {#if d.evidence.length}{@render evidence(d.evidence)}{:else}<div class="empty-state">They share nothing the store has observed.</div>{/if}
    {:else}
      <PageHeader title="Pairs" sub={`What ${d.indicator} is most like — scored pairwise against everything that shares a value with it.`} />
      <div class="hint shared">{d.shared_values} shared value{d.shared_values === 1 ? "" : "s"}</div>
      {#if d.related.length}
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>Related</th><th>Relatedness</th><th>Through</th><th>Clusters</th></tr></thead>
            <tbody>
              {#each d.related as r}
                <tr>
                  <td><IndicatorChip value={r.other} /> <a class="hint" href={href.pairs(d.indicator, r.other)}>why</a></td>
                  <td><BandChip band={r.band} score={r.score} /></td>
                  <td class="mono">{Object.keys(r.artefacts).slice(0, 4).join(", ")}</td>
                  <td><Memberships rows={r.memberships} /></td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <div class="empty-state">Nothing else in the store shares a value with it.</div>
      {/if}
    {/if}
  {/snippet}
</Async>

<style>
  .pair-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; }
  .arrow { color: var(--ink-3); }
  .hint { color: var(--ink-3); font-size: 12.5px; }
  .shared { margin-bottom: 10px; }
  .t { color: var(--accent); }
</style>
