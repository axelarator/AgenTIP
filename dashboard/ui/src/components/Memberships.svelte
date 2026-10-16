<script>
  import { href } from "../lib/router.js";
  import BandChip from "./BandChip.svelte";

  // Every cluster that has a say on an indicator, and what it says.
  let { rows = [] } = $props();
</script>

{#each rows as m}
  <span class="membership">
    <a href={href.cluster(m.cluster, m.role === "candidate" || m.role === "rejected" ? "candidates" : "observables")}
       class="chip chip--neutral">{m.cluster}:{m.role}</a>
    {#if m.role === "candidate"}<BandChip band={m.band} score={m.score} />{/if}
  </span>
{:else}
  <span class="muted">not in any cluster</span>
{/each}

<style>
  .membership { display: inline-flex; gap: 4px; margin-right: 6px; }
  .muted { color: var(--ink-3); font-size: 12.5px; }
</style>
