<script>
  import { api } from "../lib/api.js";
  import { href } from "../lib/router.js";
  import { dayOf } from "../lib/format.js";
  import Busy from "../components/Busy.svelte";
  import IndicatorChip from "../components/IndicatorChip.svelte";

  let { date = null } = $props();
  let loading = $state(true);
  let data = $state(null);

  $effect(() => {
    loading = true;
    data = null;
    api(date ? `/api/findings/${encodeURIComponent(date)}` : "/api/findings")
      .then((d) => (data = d))
      .finally(() => (loading = false));
  });
</script>

{#if loading}
  <p class="muted">Loading…</p>
{:else if data?.busy}
  <Busy error={data.error} />
{:else if !date}
  <h1>Findings</h1>
  {#if !data?.days?.length}
    <p class="muted">No findings recorded yet.</p>
  {:else}
    <ul class="days">
      {#each data.days as d}
        <li>
          <a href={href.findings(d.day)}>{d.day}</a>
          <span class="muted">{d.findings} finding{d.findings === 1 ? "" : "s"}
            · {d.saved} saved as correlation{d.saved === 1 ? "" : "s"}</span>
        </li>
      {/each}
    </ul>
  {/if}
{:else}
  <header class="fhead">
    <h1>Findings · {date}</h1>
    <nav class="fhead__links">
      <a href="#/findings">all days</a>
      <a href={href.narrative(date)}>narrative</a>
      <a href={href.run(date)}>run trace</a>
    </nav>
  </header>

  {#if !data?.findings?.length}
    <p class="muted">Nothing recorded for this day.</p>
  {:else}
    {#each data.findings as f}
      <article class="finding" class:finding--saved={f.saved}>
        <div class="finding__top">
          <span class="tag">{f.family}</span>
          {#if f.actor}<span class="tag tag--actor">{f.actor}</span>{/if}
          <span class="tag tag--{f.confidence}">{f.confidence}</span>
          {#if f.saved}
            <span class="tag tag--saved">saved · {f.correlation_type}</span>
          {:else}
            <span class="muted">noted only</span>
          {/if}
        </div>
        <h2>{f.headline}</h2>
        {#if f.detail}<p class="finding__detail">{f.detail}</p>{/if}
        {#if f.indicators?.length}
          <!--
            The whole point of this view. These values are complete in the
            store even on a day the prose abbreviated them, so the chips are
            correct regardless of what the narrative says.
          -->
          <div class="finding__inds">
            {#each f.indicators as i}<IndicatorChip value={i} />{/each}
          </div>
        {/if}
      </article>
    {/each}
  {/if}
{/if}

<style>
  .fhead { display: flex; justify-content: space-between; align-items: baseline;
           flex-wrap: wrap; gap: 1rem; }
  .fhead__links { display: flex; gap: 1rem; font-size: .85rem; }
  .days { list-style: none; padding: 0; }
  .days li { padding: .5rem 0; border-bottom: 1px solid var(--border, #d0d0d8);
             display: flex; gap: 1rem; align-items: baseline; }
  .finding { border: 1px solid var(--border, #d0d0d8); border-radius: 8px;
             padding: .9rem 1rem; margin-bottom: .8rem; }
  .finding--saved { border-color: rgba(45,160,90,.5); }
  .finding__top { display: flex; gap: .5rem; align-items: center;
                  flex-wrap: wrap; margin-bottom: .4rem; }
  .finding h2 { font-size: .98rem; margin: .1rem 0 .4rem; }
  .finding__detail { font-size: .88rem; margin: 0 0 .7rem; }
  .finding__inds { display: flex; flex-wrap: wrap; gap: .4rem; }
  .tag { font-size: .7rem; text-transform: uppercase; letter-spacing: .04em;
         padding: .12rem .45rem; border-radius: 4px;
         background: var(--chip-bg, rgba(127,127,140,.12)); }
  .tag--saved { background: rgba(45,160,90,.18); }
  .tag--high { background: rgba(200,80,60,.16); }
  .muted { color: var(--muted, #6b6b76); font-size: .85rem; }
</style>
