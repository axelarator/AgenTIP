<script>
  import { resource } from "../lib/resource.svelte.js";
  import Async from "../components/Async.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import ClusterChip from "../components/ClusterChip.svelte";
  import CoverageChip from "../components/CoverageChip.svelte";
  import DetStatusChip from "../components/DetStatusChip.svelte";
  import Chip from "../components/Chip.svelte";

  let { id } = $props();
  const res = resource(() => `/api/techniques/${encodeURIComponent(id)}`);
</script>

<Async {res}>
  {#snippet children(t)}
    <PageHeader title="{t.technique_id} — {t.name}">
      <a class="back" href="#/techniques">← back to technique matrix</a>
    </PageHeader>

    <div class="card">
      <div class="card__title">Used by ({t.used_by.length})</div>
      {#if t.used_by.length}
        <div class="table-wrap">
          <table class="data-table">
            <thead><tr><th>Cluster</th><th>Coverage</th><th>Notes</th></tr></thead>
            <tbody>
              {#each t.used_by as u}
                <tr>
                  <td><ClusterChip name={u.cluster} /></td>
                  <td><CoverageChip status={u.status} /></td>
                  <td>{u.notes}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <div class="empty-state">No tracked cluster currently logs this technique.</div>
      {/if}
    </div>

    {#if t.detections.length}
      <div class="card">
        <div class="card__title">Detections ({t.detections.length})</div>
        {#each t.detections as d}
          <div class="gap-item">
            <div class="gap-item__head"><Chip mono>{d.id}</Chip><DetStatusChip status={d.status} /></div>
            <div class="gap-item__body">{d.description}</div>
          </div>
        {/each}
      </div>
    {/if}
  {/snippet}
</Async>

<style>
  .back { color: var(--accent); }
</style>
