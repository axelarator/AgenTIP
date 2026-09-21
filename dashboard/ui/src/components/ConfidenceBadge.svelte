<script>
  import { confidenceColor } from "../lib/format.js";
  import Chip from "./Chip.svelte";

  let { value } = $props();
</script>

{#if value == null}
  <Chip>confidence unknown</Chip>
{:else}
  <span class="confidence-bar">
    <span class="confidence-bar__track">
      <span class="confidence-bar__fill"
            style="width:{value}%;background:{confidenceColor(value)}"></span>
    </span>
    <span class="conf__num">{value}%</span>
  </span>
{/if}

<style>
  .conf__num { font-family: var(--font-mono); font-size: 12px; color: var(--ink-2); }
</style>
