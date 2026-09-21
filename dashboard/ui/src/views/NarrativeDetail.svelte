<script>
  import { resource } from "../lib/resource.svelte.js";
  import { href } from "../lib/router.js";
  import Async from "../components/Async.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import Markdown from "../components/Markdown.svelte";

  let { date } = $props();
  const res = resource(() => `/api/tracking/narratives/${encodeURIComponent(date)}`);
  const missing = $derived(res.error && /404/.test(res.error));
</script>

<PageHeader title="Narrative — {date}">
  <a class="back" href="#/narratives">← back to daily narrative</a>
  · <a class="back" href={href.findings(date)}>structured findings for this day →</a>
</PageHeader>

{#if missing}
  <div class="empty-state">No narrative found for {date}.</div>
{:else}
  <Async {res}>
    {#snippet children(n)}
      <p class="hint">
        The prose is the editor's summary. The findings page carries every
        indicator at full length as copyable chips.
      </p>
      <div class="card"><Markdown text={n.content} /></div>
    {/snippet}
  </Async>
{/if}

<style>
  .back { color: var(--accent); }
  .hint { color: var(--ink-3); font-size: 12.5px; margin: 0 0 12px; }
</style>
