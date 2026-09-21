<script>
  import { describeSource } from "../lib/sources.js";

  let { source, category = null, value = "" } = $props();
  const d = $derived(describeSource(String(source), category, String(value)));
</script>

{#if d.kind === "link"}
  <a class="source-link" href={d.url} target="_blank" rel="noopener noreferrer" title={d.title}>{d.label}</a>
{:else}
  <span class="source-note" title={d.title}>{d.text}</span>
{/if}
