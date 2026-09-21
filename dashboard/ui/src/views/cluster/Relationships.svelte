<script>
  import { formatDate } from "../../lib/format.js";
  import Chip from "../../components/Chip.svelte";
  import ClusterChip from "../../components/ClusterChip.svelte";

  let { data } = $props();
  const rels = $derived(data.relationships || []);
</script>

{#if !rels.length}
  <div class="empty-state">No relationships recorded.</div>
{:else}
  <div class="card">
    {#each rels as r}
      <div class="rel-item">
        <div class="rel-item__head">
          <Chip>{r.relationship_type}</Chip>
          <ClusterChip name={r.target_cluster} />
          <span class="rel-item__date">{formatDate(r.created)}</span>
        </div>
        {#if r.description}<div class="gap-item__body">{r.description}</div>{/if}
      </div>
    {/each}
  </div>
{/if}
