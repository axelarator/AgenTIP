<script>
  import { href } from "../lib/router.js";
  import { looksLikeHash } from "../lib/format.js";
  import CopyValue from "./CopyValue.svelte";

  // `value` may be a bare indicator, or a prefixed hash the pipeline files
  // onto a cluster ("cert-sha256:<64 hex>"). The prefix is how the store
  // distinguishes a certificate hash from a file hash, so it is kept in the
  // displayed and copied text and only stripped to decide where to link.
  let { value, selectorType = null } = $props();

  const bare = $derived(String(value).replace(/^(?:cert-)?sha\d*:/i, ""));
  const target = $derived(
    selectorType
      ? href.selector(selectorType, bare)
      : looksLikeHash(value)
        ? href.selector(String(value).startsWith("cert-sha256:")
            ? "tls.cert_sha256" : "http.body_sha256", bare)
        : href.indicator(bare),
  );
</script>

<span class="ichip">
  <a class="ichip__link" href={target} title="Open profile">↗</a>
  <CopyValue {value} />
</span>

<style>
  .ichip {
    display: inline-flex;
    align-items: baseline;
    gap: .3rem;
    max-width: 100%;
    padding: .12rem .4rem;
    border-radius: 5px;
    background: var(--chip-bg, rgba(127,127,140,.10));
  }
  .ichip__link { text-decoration: none; flex: none; opacity: .75; }
  .ichip__link:hover { opacity: 1; }
</style>
