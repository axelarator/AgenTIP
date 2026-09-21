<script>
  import { formatDate, truncate } from "../../lib/format.js";
  import CoverageChip from "../../components/CoverageChip.svelte";
  import TechniqueChip from "../../components/TechniqueChip.svelte";

  let { data } = $props();
  let filter = $state("");
  const rows = $derived.by(() => {
    const f = filter.trim().toLowerCase();
    return data.ttps.filter((t) => !f
      || t.id.toLowerCase().includes(f) || t.name.toLowerCase().includes(f));
  });
</script>

<div class="filter-row">
  <input type="search" placeholder="Filter techniques…" bind:value={filter} />
</div>
<div class="table-wrap">
  {#if !rows.length}
    <div class="empty-state">No matching techniques.</div>
  {:else}
    <table class="data-table">
      <thead><tr><th>Technique</th><th>Name</th><th>Coverage</th><th>Notes</th><th>Updated</th></tr></thead>
      <tbody>
        {#each rows as t (t.id)}
          <tr>
            <td><TechniqueChip id={t.id} /></td>
            <td>{t.name}</td>
            <td><CoverageChip status={t.status} /></td>
            <td>{truncate(t.notes, 140)}</td>
            <td class="mono">{formatDate(t.updated)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
