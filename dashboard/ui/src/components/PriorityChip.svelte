<script>
  import Chip from "./Chip.svelte";

  let { priority } = $props();
  const key = $derived(["low", "medium", "high"].includes(priority) ? priority : "low");
</script>

<Chip stem={`pri-${key}`}>{key}</Chip>
