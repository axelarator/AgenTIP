<script>
  import { byPriority } from "../../lib/reports.js";
  import GapItem from "../../components/GapItem.svelte";

  let { data } = $props();
  const d = $derived(data.diamond || {});
  const gaps = $derived(data.gaps || []);
  const top = $derived([...gaps].sort(byPriority).slice(0, 3));
  const quads = $derived([
    ["Adversary", d.adversary], ["Capability", d.capability],
    ["Infrastructure", d.infrastructure], ["Victim", d.victim],
  ]);
</script>

<div class="diamond-grid">
  {#each quads as [label, text]}
    <div class="card"><div class="card__title">{label}</div><p>{text || "—"}</p></div>
  {/each}
</div>

{#if gaps.length}
  <div class="card">
    <div class="card__title">Open gaps ({gaps.length})</div>
    {#each top as g}<GapItem gap={g} />{/each}
  </div>
{/if}
