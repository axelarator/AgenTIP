<script>
  import { formatDate } from "../lib/format.js";
  import PriorityChip from "./PriorityChip.svelte";

  let { gap } = $props();
</script>

<div class="gap-item">
  <div class="gap-item__head">
    <PriorityChip priority={gap.priority} />
    <span class="gap-item__date">{formatDate(gap.created)}</span>
  </div>
  <div class="gap-item__body">{gap.description}</div>
</div>
