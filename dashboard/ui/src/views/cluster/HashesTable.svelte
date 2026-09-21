<script>
  import { formatDateOnly } from "../../lib/format.js";
  import { isCertHash } from "../../lib/reports.js";
  import Chip from "../../components/Chip.svelte";
  import IndicatorChip from "../../components/IndicatorChip.svelte";
  import SourceLink from "../../components/SourceLink.svelte";

  // Hashes are the one category with two genuinely different kinds of value
  // under one bucket: a certificate's own SHA256 (auto-filed by pivot_cluster
  // for a tracked domain) and an actual malware file hash. The
  // `cert-sha256:` prefix makes it unambiguous in the raw value; the type
  // column makes it visible without reading the string - the standing ask:
  // never let a certificate hash be mistaken for a file hash.
  let { items } = $props();
</script>

<table class="data-table">
  <thead>
    <tr><th>Value</th><th>Type</th><th>Detail</th><th>First seen</th><th>Last seen</th><th>Sources</th></tr>
  </thead>
  <tbody>
    {#each items as o (o.value)}
      {@const cert = isCertHash(o)}
      <tr>
        <!-- Full value, linked to the selector page that says who else has it. -->
        <td><IndicatorChip value={o.value} /></td>
        <td>
          {#if cert}<Chip stem="track-in-network">Certificate hash</Chip>
          {:else if (o.filenames || []).length}<Chip>File hash</Chip>
          {:else}<Chip>Hash</Chip>{/if}
        </td>
        <td>
          {#if cert}
            {#if o.cert_for}<Chip mono>{o.cert_for}</Chip>{:else}—{/if}
            {#if o.cert_revoked}<Chip stem="track-absent">revoked</Chip>{/if}
          {:else if (o.filenames || []).length}
            <div class="mono">{o.filenames.join(", ")}</div>
          {:else}—{/if}
        </td>
        <td class="mono">{formatDateOnly(o.first_seen) || "—"}</td>
        <td class="mono">{formatDateOnly(o.last_seen) || "—"}</td>
        <td>
          <div class="link-list">
            {#each (o.sources || []).slice(0, 3) as s}
              <SourceLink source={s} category="hashes" value={o.value} />
            {/each}
          </div>
        </td>
      </tr>
    {/each}
  </tbody>
</table>
