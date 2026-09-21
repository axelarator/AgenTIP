<script>
  import { byPriority } from "../../lib/reports.js";
  import GapItem from "../../components/GapItem.svelte";

  let { data } = $props();
  const sorted = $derived([...data.gaps].sort(byPriority));
</script>

{#if !data.gaps.length}
  <div class="empty-state">No open gaps.</div>
{:else}
  <div class="card">{#each sorted as g}<GapItem gap={g} />{/each}</div>
{/if}
