<script>
  import DetStatusChip from "../../components/DetStatusChip.svelte";
  import TechniqueChip from "../../components/TechniqueChip.svelte";

  let { data } = $props();
</script>

{#if !data.detections.length}
  <div class="empty-state">No detections filed against this cluster yet.</div>
{:else}
  <div class="table-wrap">
    <table class="data-table">
      <thead><tr><th>ID</th><th>Description</th><th>Status</th><th>Covers</th></tr></thead>
      <tbody>
        {#each data.detections as d}
          <tr>
            <td class="mono">{d.id}</td>
            <td>{d.description}</td>
            <td><DetStatusChip status={d.status} /></td>
            <td>
              <div class="link-list">
                {#each d.covers_ttps || d.technique_ids || [] as t}<TechniqueChip id={t} />{/each}
              </div>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}
