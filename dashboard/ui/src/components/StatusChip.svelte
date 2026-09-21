<script>
  import { STATUS } from "../lib/labels.js";
  import Chip from "./Chip.svelte";

  let { status } = $props();
  const entry = $derived(STATUS[status] ?? ["track-quiet", status || "never enriched"]);
</script>

<Chip stem={entry[0]}>{entry[1]}</Chip>
