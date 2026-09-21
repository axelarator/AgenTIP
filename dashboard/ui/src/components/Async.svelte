<script>
  import Busy from "./Busy.svelte";

  // The loading / busy / failed states every view needs, once. `busy` is not
  // an error: the daily job holds DuckDB's write lock and every read answers
  // 503 while it does.
  let { res, children } = $props();
</script>

{#if res.loading}
  <div class="loading">Loading…</div>
{:else if res.error}
  <div class="empty-state">Failed to load: {res.error}</div>
{:else if res.data?.busy}
  <Busy error={res.data.error} />
{:else if res.data}
  {@render children(res.data)}
{/if}
