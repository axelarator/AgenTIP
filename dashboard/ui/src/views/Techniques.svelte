<script>
  import { resource } from "../lib/resource.svelte.js";
  import Async from "../components/Async.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import ClusterChip from "../components/ClusterChip.svelte";
  import Chip from "../components/Chip.svelte";

  const res = resource(() => "/api/techniques");
  let filter = $state("");

  const sorted = $derived(
    [...(res.data?.techniques ?? [])].sort((a, b) => b.used_by.length - a.used_by.length));
  const rows = $derived.by(() => {
    const f = filter.trim().toLowerCase();
    return sorted.filter((t) => !f
      || t.technique_id.toLowerCase().includes(f) || t.name.toLowerCase().includes(f));
  });
</script>

<PageHeader title="Technique matrix"
  sub={res.data?.techniques
    ? `${sorted.length} distinct ATT&CK techniques logged across every tracked cluster.` : ""} />

<Async {res}>
  {#snippet children()}
    <div class="filter-row">
      <input type="search" placeholder="Filter by technique ID or name…" bind:value={filter} />
    </div>
    <div class="table-wrap">
      {#if !rows.length}
        <div class="empty-state">No matching techniques.</div>
      {:else}
        <table class="data-table">
          <thead><tr><th>Technique</th><th>Name</th><th>Used by</th><th>Detections</th></tr></thead>
          <tbody>
            {#each rows as t (t.technique_id)}
              <tr>
                <td class="mono">
                  <a class="tech-id" href="#/techniques/{encodeURIComponent(t.technique_id)}">{t.technique_id}</a>
                </td>
                <td>{t.name}</td>
                <td>
                  <div class="link-list">
                    <span class="num used-n">{t.used_by.length}</span>
                    {#each t.used_by.slice(0, 4) as u}<ClusterChip name={u.cluster} />{/each}
                    {#if t.used_by.length > 4}<Chip>+{t.used_by.length - 4}</Chip>{/if}
                  </div>
                </td>
                <td class="num">{t.detections.length}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  {/snippet}
</Async>

<style>
  .tech-id { color: var(--accent); text-decoration: none; font-weight: 600; }
  .used-n { font-family: var(--font-mono); margin-right: 4px; }
</style>
