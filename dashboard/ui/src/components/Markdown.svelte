<script>
  import { href } from "../lib/router.js";
  import { parse } from "../lib/markdown.js";
  import IndicatorChip from "./IndicatorChip.svelte";

  // The narrative is Claude-authored markdown over ingested, sometimes
  // adversary-influenced, report content, so this NEVER builds an HTML
  // string: the text is parsed into blocks and tokens and rendered as
  // ordinary Svelte elements, which escape their content. Svelte's raw-HTML
  // tag is deliberately not used anywhere in this app, and a test keeps it
  // that way.
  //
  // Subset: #/##/### headings, -/* and N. lists, **bold**, and `code`.
  // Inline code is new. The old renderer showed the backticks literally, and
  // now that full hashes are written in backticks that matters: a hash
  // renders as a copyable chip linking to its selector page, an IP or
  // hostname links to its profile, and anything else is plain code.
  let { text } = $props();

  const blocks = $derived(parse(text));
</script>

{#snippet parts(list)}
  {#each list as p}
    {#if p.t === "hash"}<IndicatorChip value={p.v} />
    {:else if p.t === "indicator"}<a class="md-ind" href={href.indicator(p.v)}><code>{p.v}</code></a>
    {:else if p.t === "code"}<code class="md-code">{p.v}</code>
    {:else if p.strong}<strong>{p.v}</strong>
    {:else}{p.v}{/if}
  {/each}
{/snippet}

<div class="narrative-body">
  {#each blocks as b}
    {#if b.type === "heading"}
      <div class="card__title">{b.text}</div>
    {:else if b.type === "list"}
      {#if b.ordered}
        <ol class="narrative-list">{#each b.items as item}<li>{@render parts(item)}</li>{/each}</ol>
      {:else}
        <ul class="narrative-list">{#each b.items as item}<li>{@render parts(item)}</li>{/each}</ul>
      {/if}
    {:else}
      <p class="narrative-p">{@render parts(b.parts)}</p>
    {/if}
  {/each}
</div>

<style>
  .md-code, .md-ind code {
    font-family: var(--font-mono);
    font-size: .86em;
    background: var(--surface-2);
    padding: .05em .35em;
    border-radius: 4px;
    overflow-wrap: anywhere;
  }
  .md-ind { text-decoration: none; color: var(--accent); }
  .md-ind:hover code { text-decoration: underline; }
</style>
