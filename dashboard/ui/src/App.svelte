<script>
  import { route } from "./lib/router.js";
  import Indicators from "./views/Indicators.svelte";
  import Indicator from "./views/Indicator.svelte";
  import Findings from "./views/Findings.svelte";
  import SelectorValue from "./views/SelectorValue.svelte";

  const NAV = [
    ["#/indicators", "Indicators"],
    ["#/findings", "Findings"],
  ];
</script>

<div class="shell">
  <header class="topbar">
    <a class="topbar__brand" href="#/indicators">CTI portal</a>
    <nav class="topbar__nav">
      {#each NAV as [to, label]}
        <a href={to} class:is-active={$route.name.startsWith(label.toLowerCase().slice(0, 6))}>{label}</a>
      {/each}
      <a href="/" title="The current dashboard">legacy ↗</a>
    </nav>
  </header>

  <main class="view">
    {#if $route.name === "indicator"}
      <Indicator value={$route.value} />
    {:else if $route.name === "findings"}
      <Findings date={$route.date} />
    {:else if $route.name === "selector"}
      <SelectorValue type={$route.type} value={$route.value} />
    {:else}
      <Indicators />
    {/if}
  </main>
</div>

<style>
  /* Use the monitor. This is a data-dense internal tool on a wide screen,
     not prose - a 1180px column left most of the display empty while
     timelines and selector tables scrolled sideways inside it. The cap is
     generous rather than absent so text lines do not become unreadable on
     an ultrawide. */
  .shell { max-width: min(2100px, 96vw); margin: 0 auto; padding: 0 1.5rem 3rem; }
  .topbar {
    display: flex; align-items: center; gap: 1.5rem;
    padding: 1rem 0; margin-bottom: 1.25rem;
    border-bottom: 1px solid var(--border, #d0d0d8);
  }
  .topbar__brand { font-weight: 600; text-decoration: none; color: var(--ink, #16161a); }
  .topbar__nav { display: flex; gap: 1rem; font-size: .9rem; }
  .topbar__nav a { text-decoration: none; color: var(--muted, #6b6b76); }
  .topbar__nav a:hover, .topbar__nav a.is-active { color: var(--ink, #16161a); }
</style>
