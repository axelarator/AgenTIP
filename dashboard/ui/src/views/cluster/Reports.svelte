<script>
  import { formatDate } from "../../lib/format.js";
  import { CATEGORY_LABELS } from "../../lib/labels.js";
  import { groupReportSources } from "../../lib/reports.js";
  import Chip from "../../components/Chip.svelte";
  import TechniqueChip from "../../components/TechniqueChip.svelte";

  let { data } = $props();
  const grouped = $derived(
    groupReportSources(data.report_sources || [])
      .sort((a, b) => (b.lastIngested || "").localeCompare(a.lastIngested || "")));

  const isUrl = (s) => { try { return /^https?:$/.test(new URL(s).protocol); } catch { return false; } };
  const sum = (o) => Object.values(o).reduce((a, v) => a + v, 0);
  const breakdown = (g) => Object.entries(g.observableCounts).filter(([, v]) => v > 0)
    .map(([c, v]) => `${CATEGORY_LABELS[c] || c} ${v}`).join(", ");
  const attemptsTitle = (g) => g.attempts.map((a) =>
    `${formatDate(a.ingested)} — ${sum(a.observables_found || {})} observables, ${(a.ttps_found || []).length} ttps`).join("\n");
</script>

{#if !grouped.length}
  <div class="empty-state">No reports ingested into this cluster yet.</div>
{:else}
  <div class="table-wrap">
    <table class="data-table">
      <thead>
        <tr><th>Ingested</th><th>Source</th><th>Times</th><th>Observables found</th><th>TTPs found</th><th>Skipped</th></tr>
      </thead>
      <tbody>
        {#each grouped as g}
          <tr>
            <td class="mono">{formatDate(g.attempts[0].ingested)}</td>
            <td>
              {#if isUrl(g.source)}
                <a class="source-link" href={g.source} target="_blank" rel="noopener noreferrer">{g.source}</a>
              {:else}
                <span class="source-note">{g.source}</span>
              {/if}
            </td>
            <td>
              {#if g.attempts.length > 1}
                <Chip title={attemptsTitle(g)}>×{g.attempts.length}</Chip>
              {:else}—{/if}
            </td>
            <td title={breakdown(g) || undefined}>{sum(g.observableCounts)}</td>
            <td>
              {#if g.ttps.length}
                <div class="link-list">
                  {#each g.ttps.slice(0, 6) as t}<TechniqueChip id={t} />{/each}
                  {#if g.ttps.length > 6}<Chip>+{g.ttps.length - 6}</Chip>{/if}
                </div>
              {:else}<span class="source-note">none</span>{/if}
            </td>
            <td>
              {#if g.skipped.length}
                <Chip title={g.skipped.map((s) => `${s.value}: ${s.reason}`).join("\n")}>{g.skipped.length}</Chip>
              {:else}—{/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}
