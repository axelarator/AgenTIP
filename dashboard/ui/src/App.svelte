<script>
  import { route } from "./lib/router.js";
  import { clusters, pendingCount, inNetworkCount, loadSidebar } from "./lib/store.js";
  import { formatDateOnly, confidenceColor } from "./lib/format.js";
  import { initTheme, toggleTheme } from "./lib/theme.js";

  import Overview from "./views/Overview.svelte";
  import Cluster from "./views/Cluster.svelte";
  import Techniques from "./views/Techniques.svelte";
  import TechniqueDetail from "./views/TechniqueDetail.svelte";
  import Queue from "./views/Queue.svelte";
  import Indicators from "./views/Indicators.svelte";
  import Indicator from "./views/Indicator.svelte";
  import Findings from "./views/Findings.svelte";
  import SelectorValue from "./views/SelectorValue.svelte";
  import Narratives from "./views/Narratives.svelte";
  import NarrativeDetail from "./views/NarrativeDetail.svelte";
  import Runs from "./views/Runs.svelte";
  import RunDetail from "./views/RunDetail.svelte";
  import Search from "./views/Search.svelte";

  initTheme();
  loadSidebar().catch(() => { /* the views report their own failures */ });

  // Which sidebar entry a route belongs to.
  const SECTION = {
    overview: "overview", technique: "techniques", techniques: "techniques",
    queue: "queue", indicators: "indicators", indicator: "indicators",
    selector: "indicators", findings: "findings", narrative: "narratives",
    narratives: "narratives", run: "runs", runs: "runs",
  };
  const section = $derived(SECTION[$route.name] ?? null);

  let clusterFilter = $state("");
  const shownClusters = $derived.by(() => {
    const f = clusterFilter.trim().toLowerCase();
    return $clusters.filter((c) => !f
      || c.name.toLowerCase().includes(f)
      || c.slug.includes(f)
      || (c.aliases || []).some((a) => a.toLowerCase().includes(f)));
  });

  let query = $state("");
  $effect(() => { if ($route.name === "search") query = $route.query ?? ""; });
  function search(e) {
    e.preventDefault();
    const q = query.trim();
    if (q) location.hash = `#/search/${encodeURIComponent(q)}`;
  }

  let main;
  // New page: back to the top, and focus the pane so keyboard scrolling works.
  $effect(() => { $route; if (main) { main.scrollTop = 0; main.focus({ preventScroll: true }); } });

  const NAV = [
    ["overview", "#/overview", "Overview"],
    ["techniques", "#/techniques", "Technique matrix"],
    ["queue", "#/queue", "Fingerprint queue"],
    ["indicators", "#/indicators", "Indicators"],
    ["findings", "#/findings", "Findings"],
    ["narratives", "#/narratives", "Daily narrative"],
    ["runs", "#/runs", "Pipeline runs"],
  ];
</script>

<div class="app">
  <header class="topbar">
    <div class="topbar__brand">CTI<span class="topbar__brand-accent">//console</span></div>
    <form class="topbar__search" role="search" onsubmit={search}>
      <svg class="topbar__search-icon" viewBox="0 0 16 16" width="15" height="15" aria-hidden="true">
        <circle cx="7" cy="7" r="5" fill="none" stroke="currentColor" stroke-width="1.6"/>
        <line x1="11" y1="11" x2="14.5" y2="14.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
      </svg>
      <input type="search" bind:value={query} autocomplete="off"
             placeholder="Search observables — hash, domain, IP, JARM…" />
    </form>
    <button class="theme-toggle" type="button" aria-label="Toggle color theme"
            title="Toggle color theme" onclick={toggleTheme}></button>
  </header>

  <div class="app__body">
    <nav class="sidebar" aria-label="Primary">
      <div class="sidebar__section">
        {#each NAV as [key, to, label]}
          <a class="nav-link" class:is-active={section === key} href={to}>
            <span>{label}</span>
            {#if key === "queue" && $pendingCount}<span class="nav-badge">{$pendingCount}</span>{/if}
            {#if key === "indicators" && $inNetworkCount}<span class="nav-badge">{$inNetworkCount}</span>{/if}
          </a>
        {/each}
      </div>

      <div class="sidebar__section sidebar__section--clusters">
        <div class="sidebar__heading">
          <span>Clusters</span>
          <span class="sidebar__count">{$clusters.length || ""}</span>
        </div>
        <input class="sidebar__filter" type="search" bind:value={clusterFilter}
               placeholder="Filter clusters…" autocomplete="off" />
        <div class="cluster-list">
          {#each shownClusters as c (c.slug)}
            <a class="cluster-row" href="#/cluster/{encodeURIComponent(c.slug)}"
               class:is-active={$route.name === "cluster" && $route.slug === c.slug}>
              <div class="cluster-row__top">
                <span class="cluster-row__dot" style="background:{confidenceColor(c.confidence)}"></span>
                <span class="cluster-row__name">{c.name}</span>
              </div>
              <div class="cluster-row__meta">
                {formatDateOnly(c.last_seen) ? `last seen ${formatDateOnly(c.last_seen)}` : "no activity logged"}
              </div>
            </a>
          {:else}
            <div class="empty-state">No clusters match.</div>
          {/each}
        </div>
      </div>
    </nav>

    <main class="view" tabindex="-1" bind:this={main}>
      {#if $route.name === "cluster"}
        <Cluster slug={$route.slug} tab={$route.tab} />
      {:else if $route.name === "techniques"}
        <Techniques />
      {:else if $route.name === "technique"}
        <TechniqueDetail id={$route.id} />
      {:else if $route.name === "queue"}
        <Queue />
      {:else if $route.name === "indicators"}
        <Indicators />
      {:else if $route.name === "indicator"}
        <Indicator value={$route.value} />
      {:else if $route.name === "findings"}
        <Findings date={$route.date} />
      {:else if $route.name === "selector"}
        <SelectorValue type={$route.type} value={$route.value} />
      {:else if $route.name === "narratives"}
        <Narratives />
      {:else if $route.name === "narrative"}
        <NarrativeDetail date={$route.date} />
      {:else if $route.name === "runs"}
        <Runs />
      {:else if $route.name === "run"}
        <RunDetail date={$route.date} />
      {:else if $route.name === "search"}
        <Search query={$route.query} />
      {:else}
        <Overview />
      {/if}
    </main>
  </div>
</div>
