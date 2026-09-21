<script>
  let { label, value, accent = false } = $props();
</script>

<div class="stat-tile">
  <div class="stat-tile__label">{label}</div>
  <div class="stat-tile__value" class:stat-tile__value--accent={accent}>{value}</div>
</div>
