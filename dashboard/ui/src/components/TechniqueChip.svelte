<script>
  import Chip from "./Chip.svelte";

  let { id } = $props();
</script>

<Chip mono href={`#/techniques/${encodeURIComponent(id)}`}>{id}</Chip>
