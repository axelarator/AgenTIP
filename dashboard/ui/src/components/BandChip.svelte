<script>
  // How strongly a candidate relates to a cluster. Colours ride the
  // coverage ramp so strong reads as the fullest and noise as empty.
  let { band = null, score = null } = $props();
  const STEM = { strong: "cov-4", probable: "cov-3", weak: "cov-2", noise: "cov-0" };
</script>

{#if band}
  <span class="chip" style="background:var(--{STEM[band] || 'cov-0'}-bg);color:var(--{STEM[band] || 'cov-0'}-ink)"
        title={score != null ? `relatedness ${Number(score).toFixed(2)}` : null}>
    {band}{#if score != null}<span class="mono">{Number(score).toFixed(2)}</span>{/if}
  </span>
{:else}
  <span class="chip chip--neutral">unscored</span>
{/if}
