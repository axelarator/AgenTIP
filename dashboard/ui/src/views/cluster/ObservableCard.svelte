<script>
  import { href } from "../../lib/router.js";
  import { formatDateOnly } from "../../lib/format.js";
  import { LIFECYCLE } from "../../lib/labels.js";
  import Chip from "../../components/Chip.svelte";
  import CopyValue from "../../components/CopyValue.svelte";

  // An ip or domain observable. The old card fetched a full tracking history
  // for every one of them (N requests to draw one tab) to offer an
  // expandable timeline. That history now lives on the indicator's own
  // profile page, which is one click away, so this is a summary built from
  // what the cluster record already carries - no per-row fetch - plus the
  // link.
  let { o, category } = $props();
  const d = $derived(o.status_detail || {});
  const asn = $derived((d.asn || [])[0]);
  const malware = $derived(
    (o.tags || []).filter((t) => t.startsWith("threatfox:malware:"))
      .map((t) => t.slice("threatfox:malware:".length)).slice(0, 3));
  const stem = $derived(LIFECYCLE[o.status] || "track-quiet");
</script>

<div class="card">
  <div class="view-header">
    <div class="view-title mono">
      <a class="prof" href={href.indicator(o.value)} title="Open the full profile">{o.value}</a>
      <CopyValue value={o.value} label="copy" />
    </div>
    <div class="view-sub">
      <Chip {stem}>{o.status || "unchecked"}</Chip>
      first seen {formatDateOnly(o.first_seen) || "—"} · last seen {formatDateOnly(o.last_seen) || "—"}
    </div>
  </div>

  <div class="link-list">
    {#if category === "ips"}
      {#if asn != null}<Chip>AS{asn}{d.as_holder ? ` ${d.as_holder}` : ""}</Chip>{/if}
      {#if d.prefix}<Chip mono>{d.prefix}</Chip>{/if}
      <!-- Stated by a report, not scanned: the two are kept apart everywhere
           else, and a bare "ports:" here would blur that. -->
      {#if (o.ports || []).length}<Chip mono>reported ports: {o.ports.join(", ")}</Chip>{/if}
    {:else}
      {#if (d.nameservers || []).length}<Chip mono>{d.nameservers[0]}</Chip>{/if}
      {#each d.resolved || [] as ip}<Chip mono href={href.indicator(ip)}>{ip}</Chip>{/each}
    {/if}
    {#each malware as m}<Chip stem="track-in-network">{m}</Chip>{/each}
  </div>

  <div class="filter-row">
    <a class="category-pill" href={href.indicator(o.value)}>Open full profile →</a>
  </div>
</div>

<style>
  .prof { color: var(--accent); text-decoration: none; }
  .prof:hover { text-decoration: underline; }
</style>
