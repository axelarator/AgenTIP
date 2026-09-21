<script>
  import { api, selectorUrl } from "../lib/api.js";
  import { href } from "../lib/router.js";
  import { dayOf } from "../lib/format.js";
  import Busy from "../components/Busy.svelte";
  import CopyValue from "../components/CopyValue.svelte";
  import SelectorMeaning from "../components/SelectorMeaning.svelte";

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
{:else if d?.not_a_selector}
  <div class="empty">
    <p><strong>Not a recorded selector.</strong></p>
    <p class="muted">
      Nothing in the store carries <code>{d.selector_value}</code>. It may
      have come from a report rather than an observation, or predate the
      selector index.
    </p>
  </div>
{:else if !d}
  <p class="muted">Nothing found.</p>
{:else}
  <header class="shead">
    <p class="shead__kind">{d.selector_type} · {d.selector_class}</p>
    <h1><CopyValue value={d.selector_value} /></h1>
    {#if d.other_types?.length}
      <p class="muted">
        This value is also recorded as
        {#each d.other_types as t, i}<a href={href.selector(t, d.selector_value)}>{t}</a>{#if i < d.other_types.length - 1}, {/if}{/each}.
      </p>
    {/if}
  </header>

  <section class="verdict">
    <SelectorMeaning
      meaning={d.means}
      never={d.never}
      carriers={d.indicators.map((i) => i.indicator_value)} />
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
  <p class="muted">
    First and last seen are when this value was recorded on each indicator.
    A match that stopped weeks ago is still a match — it dates the
    deployment even when the value has since rotated away.
  </p>
  <div class="table-wrap">
    <table class="data-table">
      <thead><tr><th>Indicator</th><th>Type</th><th>Actor</th><th>Source</th><th>First seen</th><th>Last seen</th></tr></thead>
      <tbody>
        {#each d.indicators as i}
          <tr>
            <td class="mono"><a href={href.indicator(i.indicator_value)}>{i.indicator_value}</a></td>
            <td>{i.indicator_type ?? "—"}</td>
            <td>{i.actor ?? "—"}</td>
            <td>{i.source ?? "—"}</td>
            <td>{dayOf(i.first_seen)}</td>
            <td>{dayOf(i.last_seen)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

<style>
  .shead h1 { font-size: 1rem; margin: 0 0 .4rem; }
  .shead__kind { margin: 0 0 .3rem; font-size: .74rem; text-transform: uppercase;
                 letter-spacing: .06em; color: var(--muted, #6b6b76);
                 font-family: var(--font-mono, monospace); }
  .empty { border: 1px dashed var(--border, #d0d0d8); border-radius: 8px; padding: 1.25rem; }
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
