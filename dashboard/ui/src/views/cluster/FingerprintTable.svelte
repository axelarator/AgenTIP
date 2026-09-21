<script>
  import { formatDate, truncate } from "../../lib/format.js";
  import { parseProbeSource, arkimeSessionUrl } from "../../lib/sources.js";
  import CopyValue from "../../components/CopyValue.svelte";

  // JA4+/JARM values are opaque; what an analyst wants at a glance is which
  // IP:port they were captured against and when. One row per (value, source)
  // pair, since a probe can reproduce the same fingerprint against a
  // different target on a later date.
  let { items } = $props();
  const rows = $derived(items.flatMap((o) =>
    (o.sources && o.sources.length ? o.sources : [null]).map((s) => {
      const p = s ? parseProbeSource(s) : null;
      return {
        value: o.value, raw: s, date: p ? p.when : null,
        target: p ? `${p.target}:${p.port}` : null,
        arkime: s ? arkimeSessionUrl(s) : null,
      };
    })));
</script>

<table class="data-table">
  <thead><tr><th>Value</th><th>Target</th><th>Checked</th><th>Session</th></tr></thead>
  <tbody>
    {#each rows as r}
      <tr>
        <td class="mono"><CopyValue value={r.value} /></td>
        <td class="mono">{r.target || (r.raw ? truncate(r.raw, 40) : "—")}</td>
        <td class="mono">{r.date ? formatDate(r.date) : "—"}</td>
        <td>
          {#if r.arkime}
            <a class="source-link" href={r.arkime.url} target="_blank" rel="noopener noreferrer">View in Arkime →</a>
          {:else}—{/if}
        </td>
      </tr>
    {/each}
  </tbody>
</table>
