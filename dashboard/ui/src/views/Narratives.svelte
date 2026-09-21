<script>
  import { resource } from "../lib/resource.svelte.js";
  import { href } from "../lib/router.js";
  import Async from "../components/Async.svelte";
  import PageHeader from "../components/PageHeader.svelte";

  const res = resource(() => "/api/tracking/narratives");
</script>

<PageHeader title="Daily narrative"
  sub="Stage B's analyst writeup over each day's tracking digest — skipped on quiet days." />

<Async {res}>
  {#snippet children(d)}
    {#if !d.dates.length}
      <div class="empty-state">No narratives written yet.</div>
    {:else}
      <div class="card">
        {#each d.dates as day}
          <div class="timeline-item">
            <div class="timeline-item__head">
              <a class="day" href={href.narrative(day)}>{day}</a>
              <a class="alt" href={href.findings(day)}>structured findings</a>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  {/snippet}
</Async>

<style>
  .day { color: var(--accent); font-weight: 600; text-decoration: none; }
  .alt { color: var(--ink-3); font-size: 12.5px; margin-left: 12px; }
</style>
