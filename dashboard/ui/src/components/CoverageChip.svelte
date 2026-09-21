<script>
  import { COVERAGE_LABELS } from "../lib/labels.js";
  import Chip from "./Chip.svelte";

  let { status } = $props();
</script>

<Chip stem={`cov-${status}`}>{COVERAGE_LABELS[status] ?? `status ${status}`}</Chip>
