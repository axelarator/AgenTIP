<script>
  import { formatDateOnly } from "../../lib/format.js";
  import { CATEGORY_LABELS, FINGERPRINT_CATEGORIES, PROFILE_CATEGORIES } from "../../lib/labels.js";
  import IndicatorChip from "../../components/IndicatorChip.svelte";
  import SourceLink from "../../components/SourceLink.svelte";
  import FingerprintTable from "./FingerprintTable.svelte";
  import HashesTable from "./HashesTable.svelte";
  import ObservableCard from "./ObservableCard.svelte";

  let { data } = $props();
  const cats = $derived(Object.entries(data.observables).filter(([, v]) => v.length > 0));
  let picked = $state(null);
  let filter = $state("");
  const active = $derived(picked && cats.some(([c]) => c === picked) ? picked : cats[0]?.[0]);
  const items = $derived.by(() => {
    const f = filter.trim().toLowerCase();
    const all = cats.find(([c]) => c === active)?.[1] ?? [];
    return all.filter((o) => !f || o.value.toLowerCase().includes(f));
  });
</script>

{#if !cats.length}
  <div class="empty-state">No observables tracked yet.</div>
{:else}
  <div class="filter-row">
    <div class="category-pills">
      {#each cats as [cat, list]}
        <button class="category-pill" class:is-active={cat === active}
                onclick={() => (picked = cat)}>
          {CATEGORY_LABELS[cat] || cat}<span class="num">{list.length}</span>
        </button>
      {/each}
    </div>
  </div>
  <div class="filter-row">
    <input type="search" placeholder="Filter values…" bind:value={filter} />
  </div>

  <div class="table-wrap">
    {#if !items.length}
      <div class="empty-state">No matching values.</div>
    {:else if FINGERPRINT_CATEGORIES.has(active)}
      <FingerprintTable {items} />
    {:else if active === "hashes"}
      <HashesTable {items} />
    {:else if PROFILE_CATEGORIES.has(active)}
      <div>{#each items as o (o.value)}<ObservableCard {o} category={active} />{/each}</div>
    {:else}
      <table class="data-table">
        <thead><tr><th>Value</th><th>First seen</th><th>Last seen</th><th>Sources</th></tr></thead>
        <tbody>
          {#each items as o (o.value)}
            <tr>
              <td><IndicatorChip value={o.value} /></td>
              <td class="mono">{formatDateOnly(o.first_seen) || "—"}</td>
              <td class="mono">{formatDateOnly(o.last_seen) || "—"}</td>
              <td>
                <div class="link-list">
                  {#each (o.sources || []).slice(0, 3) as s}
                    <SourceLink source={s} category={active} value={o.value} />
                  {/each}
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
{/if}
