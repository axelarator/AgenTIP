<script>
  import { resource } from "../lib/resource.svelte.js";
  import { href } from "../lib/router.js";
  import Async from "../components/Async.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import Chip from "../components/Chip.svelte";
  import IndicatorChip from "../components/IndicatorChip.svelte";

  let { date } = $props();
  const res = resource(() => `/api/runs/${encodeURIComponent(date)}`);
  const missing = $derived(res.error && /404/.test(res.error));

  // Bar width is proportional to the slowest node in the run, so the shape
  // of the bar answers "what was slow" without reading any numbers.
  const pct = (n, max) => (max > 0 ? Math.max(2, Math.round((n.elapsed_s / max) * 100)) : 2);
  const maxOf = (nodes) => Math.max(...nodes.map((n) => n.elapsed_s), 0);
  const label = (n) => (n.stage && n.stage !== "legacy" ? `${n.stage} · ${n.node}` : n.node);
  const rankNode = (nodes) => nodes.find((n) => n.node.split(":").pop() === "rank");
</script>

<PageHeader title="Run — {date}">
  <a class="back" href="#/runs">← back to pipeline runs</a>
  · <a class="back" href={href.findings(date)}>findings →</a>
</PageHeader>

{#if missing}
  <div class="empty-state">No run recorded for {date}.</div>
{:else}
  <Async {res}>
    {#snippet children(r)}
      {@const max = maxOf(r.nodes)}
      <div class="card">
        <div class="card__title">
          Timeline — {r.summary.total_s}s total
          ({(r.summary.stages || []).map((s) => `${s.stage} ${s.total_s}s`).join(", ")}),
          slowest: {r.summary.slowest || "n/a"}
        </div>
        {#each r.nodes as n}
          <div class="run-node">
            <div class="run-node__head">
              <span class="mono strong">{label(n)}</span>
              <span class="mono dim">{n.elapsed_s.toFixed(2)}s</span>
            </div>
            <div class="run-bar"><div class="run-bar__fill" style="width:{pct(n, max)}%"></div></div>
          </div>
        {/each}
      </div>

      {#if rankNode(r.nodes)}
        {@const rank = rankNode(r.nodes)}
        <div class="card">
          <div class="card__title">
            Triage — {rank.items_seen} rows seen, {(rank.suppressed || []).length}
            suppressed before any model ran
          </div>
          {#each Object.entries(rank.selected || {}) as [family, picked]}
            <div class="timeline-item">
              <div class="timeline-item__head"><span class="mono strong">{family}</span></div>
              <div>
                {#if picked.length}
                  {#each picked as i}<Chip mono>{i.indicator} · {i.attribute}</Chip>{/each}
                {:else}
                  <span class="dim">nothing to weigh</span>
                {/if}
              </div>
            </div>
          {/each}
          {#if (rank.suppressed || []).length}
            <div class="table-wrap">
              <table class="data-table">
                <thead><tr><th>Indicator</th><th>Attribute</th><th>Suppressed because</th></tr></thead>
                <tbody>
                  {#each rank.suppressed as s}
                    <tr><td class="mono">{s.indicator}</td><td class="mono">{s.attribute}</td><td>{s.reason}</td></tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {:else}
            <div class="dim">Nothing was suppressed.</div>
          {/if}
        </div>
      {/if}

      {#each r.nodes as node}
        {#if node.findings || node.errors}
          <div class="card">
            <div class="card__title">{node.node}</div>
            {#each node.findings || [] as f}
              <div class="timeline-item">
                <div class="timeline-item__head"><strong>{f.headline}</strong></div>
                <div class="narrative-p">{f.detail || ""}</div>
                <div class="chips">
                  <Chip>confidence: {f.confidence}</Chip>
                  <Chip>{f.correlation_type ? `saved as ${f.correlation_type}` : "noted only"}</Chip>
                </div>
                <!--
                  Full values, as copyable chips. The trace caps lists at 40
                  and strings at 2000 chars, which a 64-character hash is far
                  under; the findings page reads the same values from a table.
                -->
                <div class="chips">
                  {#each f.indicators || [] as i}<IndicatorChip value={i} />{/each}
                </div>
              </div>
            {/each}
            {#each node.errors || [] as e}<div class="narrative-p">error: {e}</div>{/each}
          </div>
        {/if}
      {/each}
    {/snippet}
  </Async>
{/if}

<style>
  .back { color: var(--accent); }
  .strong { font-weight: 600; }
  .dim { opacity: .65; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
</style>
