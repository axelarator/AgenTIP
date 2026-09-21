<script>
  let { title, mono = false, sub = null, children } = $props();
</script>

<div class="view-header">
  <div class="view-title" class:mono>{title}</div>
  {#if sub || children}
    <div class="view-sub">{#if sub}{sub}{/if}{@render children?.()}</div>
  {/if}
</div>
