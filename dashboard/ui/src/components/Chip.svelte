<script>
  // One chip for every badge in the app. `stem` names a colour pair in the
  // theme ("track-active" -> --track-active-bg / --track-active-ink), so a
  // chip follows light and dark mode without carrying colours of its own.
  let { stem = null, mono = false, href = null, title = null, children } = $props();
  const cls = $derived(
    "chip" + (stem ? "" : " chip--neutral") + (mono ? " chip--mono" : ""));
  const style = $derived(
    stem ? `background:var(--${stem}-bg);color:var(--${stem}-ink)` : null);
</script>

{#if href}
  <a class={cls} {style} {href} {title} style:text-decoration="none">{@render children?.()}</a>
{:else}
  <span class={cls} {style} {title}>{@render children?.()}</span>
{/if}
