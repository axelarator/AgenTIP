<script>
  // The daily job holds DuckDB's write lock for minutes and every read
  // answers 503 while it does. Saying so beats a blank page or a red error:
  // nothing is broken and the answer arrives on a refresh.
  let { error } = $props();
</script>

<div class="busy">
  <strong>The tracking database is busy.</strong>
  <p>{error}</p>
  <p class="busy__hint">The daily sweep holds the write lock while it runs. Refresh shortly.</p>
</div>

<style>
  .busy { padding: 1.5rem; border: 1px dashed var(--border, #d0d0d8); border-radius: 8px; }
  .busy p { margin: .4rem 0 0; color: var(--muted, #6b6b76); font-size: .9rem; }
  .busy__hint { font-size: .82rem; }
</style>
