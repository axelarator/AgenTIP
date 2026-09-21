<script>
  import { resource } from "../lib/resource.svelte.js";
  import { href } from "../lib/router.js";
  import Async from "../components/Async.svelte";
  import PageHeader from "../components/PageHeader.svelte";

  const res = resource(() => "/api/runs");
</script>

<PageHeader title="Pipeline runs"
  sub="What actually ran each day: which nodes fired, how long each took, and what the ranker dropped before any of them saw it." />

<Async {res}>
  {#snippet children(d)}
    {#if !d.dates.length}
      <div class="empty-state">No runs recorded yet.</div>
    {:else}
      <div class="card">
        {#each d.dates as day}
          <div class="timeline-item">
            <div class="timeline-item__head"><a class="day" href={href.run(day)}>{day}</a></div>
          </div>
        {/each}
      </div>
    {/if}
  {/snippet}
</Async>

<style>
  .day { color: var(--accent); font-weight: 600; text-decoration: none; }
</style>
