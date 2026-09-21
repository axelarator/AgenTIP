<script>
  import { DETECTION_STATUS } from "../lib/labels.js";
  import Chip from "./Chip.svelte";

  let { status } = $props();
  const entry = $derived(DETECTION_STATUS[status] ?? ["det-draft", status || "unknown"]);
</script>

<Chip stem={entry[0]}>{entry[1]}</Chip>
