<script>
  // The taxonomy's `means` prose is written for one frame - "two indicators
  // share this value, and here is what that proves". Shown beside a single
  // host's attribute it reads as a non-sequitur: a cert hash on one page
  // saying "the same leaf certificate is installed on both hosts" invites
  // the obvious question, which two?
  //
  // So the prose is labelled with the condition it applies under, and what
  // is actually true right now is stated first.
  let { meaning, never, carriers, selfName = null } = $props();

  const others = $derived(
    selfName ? carriers.filter((c) => c !== selfName) : carriers,
  );
</script>

<div class="meaning">
  {#if others.length === 0}
    <p class="meaning__state">
      Nothing else recorded carries this value{selfName ? " yet" : ""}.
      It links nothing on its own.
    </p>
  {:else}
    <p class="meaning__state">
      Shared with {others.length} other indicator{others.length === 1 ? "" : "s"}:
      {#each others.slice(0, 4) as o, i}<code>{o}</code>{#if i < Math.min(others.length, 4) - 1}, {/if}{/each}{#if others.length > 4}, and {others.length - 4} more{/if}.
    </p>
  {/if}

  <p class="meaning__if">
    <span class="meaning__tag">{others.length ? "Which means" : "If shared, it would mean"}</span>
    {meaning}
  </p>
  {#if never}
    <p class="meaning__never">
      <span class="meaning__tag meaning__tag--warn">It never proves</span>
      {never}
    </p>
  {/if}
</div>

<style>
  .meaning__state { margin: 0 0 .5rem; font-size: .88rem; }
  .meaning__state code { font-size: .8rem; overflow-wrap: anywhere; }
  .meaning__if, .meaning__never { margin: 0 0 .35rem; font-size: .86rem; }
  .meaning__never { color: var(--ink-3); }
  .meaning__tag {
    display: inline-block;
    font-size: .68rem; text-transform: uppercase; letter-spacing: .05em;
    color: var(--ink-3);
    margin-right: .4rem;
  }
  .meaning__tag--warn { color: var(--pri-high-ink); }
</style>
