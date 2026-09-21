<script>
  import { clusters } from "../lib/store.js";
  import { href } from "../lib/router.js";
  import Chip from "./Chip.svelte";

  let { name } = $props();
  const match = $derived($clusters.find((c) => c.name === name));
</script>

<Chip href={match ? href.cluster(match.slug) : "#"}>{name}</Chip>
