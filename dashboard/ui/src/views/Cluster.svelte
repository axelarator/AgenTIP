<script>
  import { resource } from "../lib/resource.svelte.js";
  import { href } from "../lib/router.js";
  import { formatDateOnly } from "../lib/format.js";
  import { groupReportSources } from "../lib/reports.js";
  import Async from "../components/Async.svelte";
  import Chip from "../components/Chip.svelte";
  import ConfidenceBadge from "../components/ConfidenceBadge.svelte";

  import Diamond from "./cluster/Diamond.svelte";
  import Reports from "./cluster/Reports.svelte";
  import Ttps from "./cluster/Ttps.svelte";
  import Observables from "./cluster/Observables.svelte";
  import Detections from "./cluster/Detections.svelte";
  import Gaps from "./cluster/Gaps.svelte";
  import HuntLog from "./cluster/HuntLog.svelte";
  import Relationships from "./cluster/Relationships.svelte";

  let { slug, tab } = $props();
  const res = resource(() => `/api/clusters/${encodeURIComponent(slug)}`);

  const BODY = {
    diamond: Diamond, reports: Reports, ttps: Ttps, observables: Observables,
    detections: Detections, gaps: Gaps, hunt_log: HuntLog, relationships: Relationships,
  };

  function tabsFor(data) {
    const tabs = [
      ["diamond", "Diamond", null],
      ["reports", "Reports", groupReportSources(data.report_sources || []).length],
      ["ttps", "TTPs", data.ttps.length],
      ["observables", "Observables",
        Object.values(data.observables).reduce((a, v) => a + v.length, 0)],
      ["detections", "Detections", data.detections.length],
      ["gaps", "Gaps", data.gaps.length],
      ["hunt_log", "Hunt log", data.hunt_log.length],
    ];
    // Only shown when there is something in it.
    if ((data.relationships || []).length) {
      tabs.push(["relationships", "Relationships", data.relationships.length]);
    }
    return tabs;
  }
</script>

<Async {res}>
  {#snippet children(data)}
    {@const tabs = tabsFor(data)}
    {@const active = tabs.some((t) => t[0] === tab) ? tab : "diamond"}
    {@const Body = BODY[active]}

    <div class="cluster-header">
      <div class="cluster-header__title-row">
        <div class="cluster-header__name">{data.name}</div>
        <ConfidenceBadge value={data.confidence} />
      </div>
      {#if data.aliases.length}
        <div class="cluster-header__aliases">{#each data.aliases as a}<Chip>{a}</Chip>{/each}</div>
      {/if}
      <div class="cluster-header__desc">{data.description}</div>
      <div class="cluster-header__meta">
        <span>First seen <b>{formatDateOnly(data.first_seen) || "—"}</b></span>
        <span>Last seen <b>{formatDateOnly(data.last_seen) || "—"}</b></span>
        <span>STIX ID <b class="stix">{data.stix_id}</b></span>
      </div>
    </div>

    <div class="tabs">
      {#each tabs as [key, label, count]}
        <button class="tab" class:is-active={key === active}
                onclick={() => (location.hash = href.cluster(slug, key))}>
          {label}{#if count != null}<span class="tab__count">{count}</span>{/if}
        </button>
      {/each}
    </div>

    <Body {data} />
  {/snippet}
</Async>

<style>
  .stix { font-family: var(--font-mono); font-size: 11.5px; font-weight: 500; }
</style>
