<script>
  import { resource } from "../../lib/resource.svelte.js";
  import { href } from "../../lib/router.js";
  import { formatDateOnly } from "../../lib/format.js";
  import Async from "../../components/Async.svelte";
  import IndicatorChip from "../../components/IndicatorChip.svelte";
  import BandChip from "../../components/BandChip.svelte";

  let { data } = $props();
  const res = resource(() => `/api/clusters/${encodeURIComponent(data.name)}/candidates`);

  // One candidate's evidence at a time, fetched on demand.
  let open = $state(null);
  const evidence = resource(() => open
    ? `/api/clusters/${encodeURIComponent(data.name)}/candidates?value=${encodeURIComponent(open)}`
    : `/api/clusters/${encodeURIComponent(data.name)}/candidates`);
  const gap = (g) => g == null ? "undated" : g === 0 ? "overlapping" : `${Math.round(g)}d apart`;
</script>

<p class="hint">Proposed by pivots, scans and hunt rules, scored against this cluster's members.
  None of these export until accepted (<code>accept_candidate</code> / <code>reject_candidate</code>).</p>

<Async {res}>
  {#snippet children(d)}
    {#if d.candidates.length}
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>Indicator</th><th>Relatedness</th><th>Role</th><th>Found via</th><th>Filed</th></tr></thead>
          <tbody>
            {#each d.candidates as c}
              <tr class:rejected={c.role === "rejected"}>
                <td>
                  <IndicatorChip value={c.entity} />
                  {#if c.role === "candidate"}
                    <button class="linkish" onclick={() => (open = open === c.entity ? null : c.entity)}>
                      {open === c.entity ? "hide" : "evidence"}</button>
                  {/if}
                  <a class="hint" href={href.pairs(c.entity)}>pairs</a>
                </td>
                <td>{#if c.role === "candidate"}<BandChip band={c.band} score={c.score} />{/if}</td>
                <td>{c.role}{#if c.role === "rejected" && c.reason}<div class="hint">{c.reason}</div>{/if}</td>
                <td class="hint">{(c.origin || "").slice(0, 90)}</td>
                <td class="mono">{formatDateOnly(c.created_at) || "—"}</td>
              </tr>
              {#if open === c.entity}
                <tr><td colspan="5">
                  {#if evidence.loading}<div class="loading">Scoring…</div>
                  {:else if evidence.data?.evidence}
                    {#each evidence.data.evidence as e}
                      <div class="ev mono">
                        <span class="w">{e.weight.toFixed(3)}</span> {e.class.padEnd(11)}
                        <span class="t">{e.type}</span>={String(e.value).slice(0, 70)}
                        <span class="hint"> ↔ {e.member} · {gap(e.gap_days)}{e.note ? ` · ${e.note}` : ""}</span>
                      </div>
                    {:else}<div class="hint">No shared value with any member.</div>{/each}
                  {/if}
                </td></tr>
              {/if}
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <div class="empty-state">No candidates for this cluster.</div>
    {/if}
  {/snippet}
</Async>

<style>
  .hint { color: var(--ink-3); font-size: 12.5px; }
  .hint code { font-size: 12px; }
  .linkish { background: none; border: none; color: var(--accent); cursor: pointer; font-size: 12px; padding: 0 4px; }
  .rejected td { opacity: .6; }
  .ev { font-size: 12px; line-height: 1.8; white-space: pre-wrap; word-break: break-all; }
  .w { color: var(--ink); font-weight: 600; }
  .t { color: var(--accent); }
</style>
