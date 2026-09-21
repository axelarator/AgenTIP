<script>
  import { resource } from "../lib/resource.svelte.js";
  import { formatDate } from "../lib/format.js";
  import { CATEGORY_LABELS } from "../lib/labels.js";
  import Async from "../components/Async.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import ClusterChip from "../components/ClusterChip.svelte";
  import CopyValue from "../components/CopyValue.svelte";

  const res = resource(() => "/api/pending-fingerprints");
</script>

<PageHeader title="Fingerprint queue"
  sub="Domains/IPs tracked since the last JA4+/JARM probe pass — not yet actively fingerprinted." />

<Async {res}>
  {#snippet children(items)}
    {#if !items.length}
      <div class="empty-state">Queue is empty — everything tracked has been probed.</div>
    {:else}
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Cluster</th><th>Category</th><th>Value</th><th>Queued</th></tr></thead>
          <tbody>
            {#each items as i}
              <tr>
                <td><ClusterChip name={i.cluster} /></td>
                <td>{CATEGORY_LABELS[i.category] || i.category}</td>
                <td class="mono"><CopyValue value={i.value} /></td>
                <td class="mono">{formatDate(i.queued_at)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/snippet}
</Async>
