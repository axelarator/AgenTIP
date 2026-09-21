<script>
  import { api } from "../lib/api.js";
  import { resource } from "../lib/resource.svelte.js";
  import { href } from "../lib/router.js";
  import { formatDate, truncate } from "../lib/format.js";
  import Async from "../components/Async.svelte";
  import PageHeader from "../components/PageHeader.svelte";
  import StatTile from "../components/StatTile.svelte";
  import Chip from "../components/Chip.svelte";

  const stats = resource(() => "/api/stats");

  // The latest day's findings. Two dependent fetches, so done by hand: the
  // second URL is only known once the first answers. Failure here is quiet -
  // the daily job can hold the database for minutes, and the overview should
  // still show its stats.
  let latest = $state({ day: null, findings: [] });
  $effect(() => {
    api("/api/findings")
      .then((d) => (d.days?.length ? api(`/api/findings/${d.days[0].day}`) : null))
      .then((d) => { if (d?.findings) latest = { day: d.day, findings: d.findings }; })
      .catch(() => {});
  });
</script>

<PageHeader title="Overview" sub="Snapshot across every tracked cluster." />

<Async res={stats}>
  {#snippet children(s)}
    <div class="stat-grid">
      <StatTile label="Clusters" value={s.cluster_count} />
      <StatTile label="Observables tracked" value={s.observable_count} />
      <StatTile label="TTPs logged" value={s.ttp_count} />
      <StatTile label="Detections" value={s.detection_count} />
      <StatTile label="Open gaps" value={s.gap_count} />
      <StatTile label="Pending fingerprints" value={s.pending_fingerprint_count}
                accent={s.pending_fingerprint_count > 0} />
    </div>

    {#if latest.findings.length}
      <div class="card">
        <div class="card__title">
          Latest findings — <a href={href.findings(latest.day)}>{latest.day}</a>
        </div>
        {#each latest.findings as f}
          <div class="timeline-item">
            <div class="timeline-item__head">
              <Chip>{f.family}</Chip>
              {#if f.actor}<Chip>{f.actor}</Chip>{/if}
              {#if f.saved}<Chip stem="track-active">saved</Chip>{/if}
            </div>
            <div class="timeline-item__body">{f.headline}</div>
          </div>
        {/each}
      </div>
    {/if}

    <div class="card">
      <div class="card__title">Recent hunt activity</div>
      {#each s.recent_activity as e}
        <div class="timeline-item">
          <div class="timeline-item__head">
            <span class="timeline-item__date">{formatDate(e.date)}</span>
            <a class="timeline-item__cluster-link" href={href.cluster(e.slug, "hunt_log")}>{e.cluster}</a>
          </div>
          <div class="timeline-item__body">{truncate(e.entry, 320)}</div>
        </div>
      {:else}
        <div class="empty-state">No hunt log entries yet.</div>
      {/each}
    </div>
  {/snippet}
</Async>
