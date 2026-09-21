<script>
  import CopyValue from "./CopyValue.svelte";
  import IndicatorChip from "./IndicatorChip.svelte";

  // "corroborating selectors only - nothing that can promote" is accurate
  // and answers nothing. The question it leaves is which selectors, and why
  // those cannot carry a link - and the evidence for both is already on the
  // candidate, just never shown.
  let { link, classes } = $props();

  const shared = $derived([
    ...link.identity.map(([t, v]) => [t, v, "identity"]),
    ...link.structural.map(([t, v]) => [t, v, "structural"]),
    ...link.corroborating.map(([t, v]) => [t, v, classes[t] ?? "contextual"]),
  ]);

  const WHY = {
    behavioural: "behavioural — describes how the service behaves, which every host running the same stack shares",
    contextual: "contextual — describes the hosting, not the operator",
  };
</script>

<article class="held">
  <div class="held__top">
    <IndicatorChip value={link.indicator} />
    {#if link.actor}<span class="muted">{link.actor}</span>{/if}
  </div>

  <p class="held__verdict">{link.reason}</p>

  {#if shared.length}
    <p class="held__lead">
      These two share {shared.length} selector{shared.length === 1 ? "" : "s"}:
    </p>
    <ul class="held__list">
      {#each shared as [type, value, cls]}
        <li>
          <span class="held__type">{type}</span>
          <CopyValue {value} />
          <span class="held__why">
            {WHY[cls] ?? `${cls} — counts toward a link`}
          </span>
        </li>
      {/each}
    </ul>
    <p class="held__rule">
      A link needs one identity selector, or two structural selectors read
      off different things. Nothing above clears that bar.
    </p>
  {/if}
</article>

<style>
  .held { border: 1px solid var(--border, #d0d0d8); border-radius: 8px;
          padding: .75rem .9rem; margin-bottom: .6rem; }
  .held__top { display: flex; gap: .7rem; align-items: baseline; flex-wrap: wrap; }
  .held__verdict { margin: .45rem 0 .5rem; font-size: .86rem; }
  .held__lead { margin: 0 0 .3rem; font-size: .82rem; color: var(--muted, #6b6b76); }
  .held__list { list-style: none; margin: 0 0 .5rem; padding: 0; }
  .held__list li { display: flex; flex-wrap: wrap; gap: .5rem;
                   align-items: baseline; padding: .2rem 0; font-size: .8rem; }
  .held__type { font-family: var(--font-mono, monospace); }
  .held__why { color: var(--muted, #6b6b76); }
  .held__rule { margin: 0; font-size: .78rem; color: var(--muted, #6b6b76);
                font-style: italic; }
  .muted { color: var(--muted, #6b6b76); font-size: .85rem; }
</style>
