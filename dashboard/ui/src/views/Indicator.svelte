<script>
  import { api, indicatorUrl } from "../lib/api.js";
  import { href } from "../lib/router.js";
  import { dayOf, formatDate, humanBytes } from "../lib/format.js";
  import Busy from "../components/Busy.svelte";
  import CopyValue from "../components/CopyValue.svelte";
  import IndicatorChip from "../components/IndicatorChip.svelte";
  import Select from "../components/Select.svelte";
  import SelectorMeaning from "../components/SelectorMeaning.svelte";
  import HeldBack from "../components/HeldBack.svelte";

  let { value } = $props();
  let loading = $state(true);
  let p = $state(null);
  let tab = $state("current");
  let sourceFilter = $state("all");
  // 172 observations over 27 days is a lot of scrolling to reach last week.
  let windowDays = $state(7);
  let jumpDate = $state("");

  $effect(() => {
    loading = true;
    p = null;
    tab = "current";
    sourceFilter = "all";
    windowDays = 7;
    jumpDate = "";
    api(indicatorUrl(value))
      .then((d) => (p = d))
      .finally(() => (loading = false));
  });

  const CLASS_ORDER = ["identity", "structural", "behavioural", "contextual"];
  const byClass = $derived(
    !p?.selectors ? [] :
      CLASS_ORDER.map((c) => [c, p.selectors.filter((s) => s.selector_class === c)])
                 .filter(([, list]) => list.length),
  );
  const promoted = $derived((p?.links ?? []).filter((l) => l.promoted));
  const held = $derived((p?.links ?? []).filter((l) => !l.promoted));
  const days = $derived(
    !p?.observations ? [] :
      [...new Set(p.observations.map((o) => String(o.observed_at).slice(0, 10)))]
        .sort().reverse(),
  );

  // A specific day wins over the rolling window: picking one is an explicit
  // request for that day, not a wider net.
  const cutoff = $derived(
    jumpDate ? null
    : windowDays === 0 ? null
    : new Date(Date.now() - windowDays * 86400000).toISOString().slice(0, 10),
  );

  const timeline = $derived(
    !p?.observations ? [] :
      [...p.observations].reverse().filter((o) => {
        if (sourceFilter !== "all" && o.source !== sourceFilter) return false;
        const day = String(o.observed_at).slice(0, 10);
        if (jumpDate) return day === jumpDate;
        return !cutoff || day >= cutoff;
      }),
  );

  const hiddenCount = $derived(
    (p?.observations?.length ?? 0) - timeline.length,
  );

  // type -> class, so a held-back link can say why each shared selector
  // cannot carry it. Both ends of a shared selector carry it, so the
  // indicator's own bag is a complete source for this.
  const selectorClasses = $derived(
    Object.fromEntries((p?.selectors ?? []).map((s) => [s.selector_type, s.selector_class])),
  );


  const TABS = $derived([
    ["current", `Current (${Object.keys(p?.current ?? {}).length})`],
    ["timeline", `Timeline (${p?.observation_count ?? 0})`],
    ["selectors", `Selectors (${p?.selectors?.length ?? 0})`],
    ["links", `Links (${p?.links?.length ?? 0})`],
    ["changes", `Changes (${p?.changes?.length ?? 0})`],
  ]);

  const fmt = (v) => (Array.isArray(v) || (v && typeof v === "object"))
    ? JSON.stringify(v) : String(v);
  const isLong = (v) => typeof v === "string" && /^[0-9a-f]{32,}$/i.test(v);
</script>

{#if loading}
  <p class="muted">Loading…</p>
{:else if p?.busy}
  <Busy error={p.error} />
{:else if !p}
  <p class="muted">Nothing found.</p>
{:else}
  <header class="ihead">
    <h1><CopyValue value={p.indicator} /></h1>
    <div class="ihead__meta">
      <span class="pill pill--{p.status}">{p.status}</span>
      <span>{p.indicator_type ?? "unknown type"}</span>
      {#each p.actors as a}
        <a href={href.cluster(a.toLowerCase().replace(/\s+/g, "-"))}>{a}</a>
      {/each}
      <span>{p.observation_count} observations · {p.sources.length} sources</span>
      <span>{dayOf(p.first_seen)} → {dayOf(p.last_seen)}</span>
    </div>
  </header>

  <nav class="tabs">
    {#each TABS as [key, label]}
      <button class:is-active={tab === key} onclick={() => (tab = key)}>{label}</button>
    {/each}
  </nav>

  {#if tab === "current"}
    {#if !Object.keys(p.current).length}
      <p class="muted">No values recorded yet.</p>
    {:else}
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Field</th><th>Value</th><th>Source</th><th>Seen</th></tr></thead>
          <tbody>
            {#each Object.entries(p.current).sort(([a], [b]) => a.localeCompare(b)) as [field, cell]}
              <tr>
                <td class="mono">{field}</td>
                <td class="mono wrap">
                  {#if isLong(cell.value)}
                    <CopyValue value={cell.value} />
                  {:else}
                    {fmt(cell.value)}
                  {/if}
                </td>
                <td>{cell.source}</td>
                <td>{dayOf(cell.observed_at)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}

  {:else if tab === "timeline"}
    <div class="controls">
      <Select
        label="source"
        bind:value={sourceFilter}
        options={[{ value: "all", label: "all sources" },
                  ...p.sources.map((s) => ({ value: s, label: s }))]} />
      <Select
        label="window"
        bind:value={windowDays}
        options={[{ value: 7, label: "last 7 days" },
                  { value: 14, label: "last 14 days" },
                  { value: 30, label: "last 30 days" },
                  { value: 0, label: "everything" }]} />
      <Select
        label="day"
        bind:value={jumpDate}
        options={[{ value: "", label: "any day" },
                  ...days.map((d) => ({ value: d, label: d }))]} />
      <span class="muted">
        {timeline.length} row{timeline.length === 1 ? "" : "s"}{#if hiddenCount > 0}, {hiddenCount} outside the window{/if}
      </span>
    </div>
    {#if !timeline.length}
      <p class="muted">Nothing in this window. Widen it or pick another day.</p>
    {/if}
    {#each timeline as o}
      <article class="obs">
        <div class="obs__head">
          <strong>{o.source}</strong>
          <span class="muted">{formatDate(o.observed_at)}</span>
        </div>
        {#if Object.keys(o.payload ?? {}).length}
          <dl class="obs__body">
            {#each Object.entries(o.payload) as [k, v]}
              {#if v !== null && v !== "" && !(Array.isArray(v) && !v.length)}
                <dt>{k}</dt>
                <dd class="mono wrap">
                  {#if isLong(v)}<CopyValue value={v} />{:else}{fmt(v)}{/if}
                </dd>
              {/if}
            {/each}
          </dl>
        {:else}
          <p class="muted">Checked, nothing recorded.</p>
        {/if}
      </article>
    {/each}

  {:else if tab === "selectors"}
    {#each byClass as [cls, list]}
      <h2 class="cls">{cls}</h2>
      {#each list as s}
        <article class="sel">
          <div class="sel__top">
            <a class="sel__type" href={href.selector(s.selector_type, s.selector_value)}>
              {s.selector_type}
            </a>
            <CopyValue value={s.selector_value} />
          </div>
          <SelectorMeaning
            meaning={s.means}
            never={s.never}
            carriers={s.carriers ?? []} />
          <p class="muted">
            recorded {dayOf(s.first_seen)} → {dayOf(s.last_seen)}
            {#if s.global_count !== null && s.global_count !== undefined}
              · {s.global_count.toLocaleString()} on the index
            {/if}
            {#if !s.can_promote}· <strong>cannot promote a link</strong>{#if s.why_not}: {s.why_not}{/if}{/if}
          </p>
        </article>
      {/each}
    {/each}

  {:else if tab === "links"}
    {#if promoted.length}
      <h2 class="cls">Promoted</h2>
      {#each promoted as l}
        <article class="link link--promoted">
          <div class="link__top">
            <IndicatorChip value={l.indicator} />
            {#if l.actor}<span class="muted">{l.actor}</span>{/if}
          </div>
          <p class="link__reason">{l.reason}</p>
          {#each [...l.identity, ...l.structural] as [t, v]}
            <div class="link__ev"><span class="mono">{t}</span> <CopyValue value={v} /></div>
          {/each}
        </article>
      {/each}
    {/if}
    {#if held.length}
      <h2 class="cls">Held back ({held.length})</h2>
      <p class="muted">
        The corroboration rule declined these. That is the filter working, not a gap.
      </p>
      {#each held.slice(0, 25) as l}
        <HeldBack link={l} classes={selectorClasses} />
      {/each}
      {#if held.length > 25}
        <p class="muted">{held.length - 25} more not shown.</p>
      {/if}
    {/if}
    {#if !p.links.length}<p class="muted">Nothing shares a selector with this indicator.</p>{/if}

  {:else if tab === "changes"}
    {#if !p.changes.length}
      <p class="muted">No recorded changes.</p>
    {:else}
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Detected</th><th>Attribute</th><th>Change</th><th>New value</th><th>Confidence</th></tr></thead>
          <tbody>
            {#each p.changes as c}
              <tr>
                <td>{dayOf(c.detected_at)}</td>
                <td class="mono">{c.attribute}</td>
                <td>{c.change_type}</td>
                <td class="mono wrap">{fmt(c.new_value)}</td>
                <td>{c.confidence}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
{/if}

<style>
  .ihead h1 { margin: 0 0 .5rem; font-size: 1.15rem; }
  .ihead__meta { display: flex; flex-wrap: wrap; gap: .9rem; font-size: .85rem;
                 color: var(--muted, #6b6b76); margin-bottom: 1.25rem; }
  .pill { padding: .1rem .5rem; border-radius: 999px; font-size: .75rem;
          background: var(--chip-bg, rgba(127,127,140,.12)); }
  .pill--resolving { background: rgba(45,160,90,.16); }
  .pill--unresolved { background: rgba(200,80,60,.16); }
  .pill--in-network { background: rgba(200,140,40,.18); }
  .tabs { display: flex; gap: .4rem; margin-bottom: 1.25rem; flex-wrap: wrap; }
  .tabs button { border: 1px solid var(--border, #d0d0d8); background: transparent;
                 padding: .3rem .7rem; border-radius: 6px; cursor: pointer;
                 color: var(--muted, #6b6b76); font-size: .85rem; }
  .tabs button.is-active { color: var(--ink, #16161a); border-color: var(--muted, #6b6b76); }
  .cls { font-size: .78rem; text-transform: uppercase; letter-spacing: .06em;
         color: var(--muted, #6b6b76); margin: 1.4rem 0 .6rem; }
  .obs, .sel, .link { border: 1px solid var(--border, #d0d0d8); border-radius: 8px;
                      padding: .75rem .9rem; margin-bottom: .6rem; }
  .obs__head { display: flex; justify-content: space-between; font-size: .85rem; }
  .obs__body { display: grid; grid-template-columns: minmax(9rem, auto) 1fr;
               gap: .25rem .9rem; margin: .6rem 0 0; font-size: .82rem; }
  .obs__body dt { color: var(--muted, #6b6b76); }
  .obs__body dd { margin: 0; overflow-wrap: anywhere; }
  .sel__top, .link__top { display: flex; gap: .7rem; align-items: baseline; flex-wrap: wrap; }
  .sel__type { font-family: var(--font-mono, monospace); font-size: .82rem; }
  .sel__means { margin: .45rem 0 .2rem; font-size: .86rem; }
  .sel__never { margin: 0 0 .3rem; font-size: .82rem; color: var(--muted, #6b6b76); }
  .link--promoted { border-color: rgba(45,160,90,.5); }
  .link__reason { margin: .4rem 0; font-size: .86rem; }
  .link__ev { display: flex; gap: .6rem; font-size: .8rem; margin-top: .2rem; flex-wrap: wrap; }
  .controls { display: flex; gap: .75rem; align-items: center; margin-bottom: 1rem; }
  .muted { color: var(--muted, #6b6b76); font-size: .85rem; }
  .wrap { overflow-wrap: anywhere; }
</style>
