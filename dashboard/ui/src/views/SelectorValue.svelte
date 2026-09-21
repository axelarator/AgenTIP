<script>
  import { api, selectorUrl } from "../lib/api.js";
  import { href } from "../lib/router.js";
  import { dayOf } from "../lib/format.js";
  import Busy from "../components/Busy.svelte";
  import CopyValue from "../components/CopyValue.svelte";

  let { type, value } = $props();
  let loading = $state(true);
  let d = $state(null);

  $effect(() => {
    loading = true;
    d = null;
    api(selectorUrl(type, value)).then((r) => (d = r)).finally(() => (loading = false));
  });
</script>

{#if loading}
  <p class="muted">Loading…</p>
{:else if d?.busy}
  <Busy error={d.error} />
{:else if !d}
  <p class="muted">Nothing found.</p>
{:else}
  <header class="shead">
    <h1>{d.selector_type}</h1>
    <CopyValue value={d.selector_value} />
  </header>

  <section class="verdict">
    <p class="verdict__means">{d.means}</p>
    {#if d.never}<p class="verdict__never"><em>Never:</em> {d.never}</p>{/if}
    <p class="muted">
      class <strong>{d.selector_class}</strong> · artefact <strong>{d.artefact}</strong>
      · held by {d.local_count ?? "?"} of our indicators
      {#if d.global_count !== null && d.global_count !== undefined}
        · {d.global_count.toLocaleString()} on {d.global_source ?? "the index"}
      {/if}
      · spread across {d.apex_spread} registered domain{d.apex_spread === 1 ? "" : "s"}
    </p>
    <p class:can={d.can_promote} class:cannot={!d.can_promote}>
      {#if d.can_promote}
        This value can promote a link.
      {:else}
        This value cannot promote a link{#if d.why_not}: {d.why_not}{/if}.
      {/if}
    </p>
  </section>

  <h2 class="cls">Carried by {d.indicators.length} indicator{d.indicators.length === 1 ? "" : "s"}</h2>
  <div class="table-wrap">
    <table class="data-table">
      <thead><tr><th>Indicator</th><th>Type</th><th>Actor</th><th>Source</th><th>Last seen</th></tr></thead>
      <tbody>
        {#each d.indicators as i}
          <tr>
            <td class="mono"><a href={href.indicator(i.indicator_value)}>{i.indicator_value}</a></td>
            <td>{i.indicator_type ?? "—"}</td>
            <td>{i.actor ?? "—"}</td>
            <td>{i.source ?? "—"}</td>
            <td>{dayOf(i.last_seen)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

<style>
  .shead h1 { font-size: 1rem; margin: 0 0 .4rem; font-family: var(--font-mono, monospace); }
  .verdict { border: 1px solid var(--border, #d0d0d8); border-radius: 8px;
             padding: .9rem 1rem; margin: 1.2rem 0; }
  .verdict__means { margin: 0 0 .4rem; font-size: .92rem; }
  .verdict__never { margin: 0 0 .5rem; font-size: .85rem; color: var(--muted, #6b6b76); }
  .can { color: rgb(30,130,70); font-size: .88rem; margin: .5rem 0 0; }
  .cannot { color: var(--muted, #6b6b76); font-size: .88rem; margin: .5rem 0 0; }
  .cls { font-size: .78rem; text-transform: uppercase; letter-spacing: .06em;
         color: var(--muted, #6b6b76); margin: 1.4rem 0 .6rem; }
  .muted { color: var(--muted, #6b6b76); font-size: .85rem; }
</style>
