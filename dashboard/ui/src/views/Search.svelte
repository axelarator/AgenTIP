<script>
  import { resource } from "../lib/resource.svelte.js";
  import { formatDateOnly } from "../lib/format.js";
  import { CATEGORY_LABELS } from "../lib/labels.js";
  import Async from "../components/Async.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import ClusterChip from "../components/ClusterChip.svelte";
  import IndicatorChip from "../components/IndicatorChip.svelte";

  let { query } = $props();
  const res = resource(() => query
    ? `/api/observables/search?q=${encodeURIComponent(query)}`
    : "/api/observables/search?q=");
</script>

{#snippet group(title, items)}
  <div class="search-group">
    <div class="search-group__title">{title}</div>
    <div class="table-wrap">
      <table class="data-table">
        <thead><tr><th>Value</th><th>Category</th><th>Cluster</th><th>First seen</th><th>Last seen</th></tr></thead>
        <tbody>
          {#each items as o}
            <tr>
              <td><IndicatorChip value={o.value} /></td>
              <td>{CATEGORY_LABELS[o.category] || o.category}</td>
              <td><ClusterChip name={o.cluster} /></td>
              <td class="mono">{formatDateOnly(o.first_seen) || "—"}</td>
              <td class="mono">{formatDateOnly(o.last_seen) || "—"}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>
{/snippet}

<PageHeader title="Observable search"
  sub={query ? `Results for "${query}"` : "Enter a hash, domain, IP, or fingerprint above."} />

{#if query}
  <Async {res}>
    {#snippet children(r)}
      {#if !r.exact.length && !r.partial.length}
        <div class="empty-state">No matches found.</div>
      {/if}
      {#if r.exact.length}{@render group(`Exact matches (${r.exact.length})`, r.exact)}{/if}
      {#if r.partial.length}{@render group(`Partial matches (${r.partial.length})`, r.partial)}{/if}
    {/snippet}
  </Async>
{/if}
