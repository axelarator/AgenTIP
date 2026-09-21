<script>
  import { formatDate } from "../../lib/format.js";

  let { data } = $props();
  const sorted = $derived([...data.hunt_log].sort((a, b) => b.date.localeCompare(a.date)));
</script>

{#if !data.hunt_log.length}
  <div class="empty-state">No hunt log entries yet.</div>
{:else}
  <div class="card">
    {#each sorted as e}
      <div class="timeline-item">
        <div class="timeline-item__head">
          <span class="timeline-item__date">{formatDate(e.date)}</span>
        </div>
        <div class="timeline-item__body">{e.entry}</div>
      </div>
    {/each}
  </div>
{/if}
