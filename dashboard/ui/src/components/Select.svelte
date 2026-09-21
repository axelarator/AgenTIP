<script>
  // A themed replacement for a bare <select>, which reads as browser
  // chrome dropped into the page. Native element underneath - it keeps
  // keyboard behaviour and the OS picker on mobile - with the platform
  // styling stripped and the site's own border, radius and colours put
  // back, plus a chevron drawn in CSS.
  let { value = $bindable(), options, label = null } = $props();
</script>

<label class="sel">
  {#if label}<span class="sel__label">{label}</span>{/if}
  <span class="sel__wrap">
    <select bind:value>
      {#each options as o}
        <option value={o.value}>{o.label}</option>
      {/each}
    </select>
    <span class="sel__chev" aria-hidden="true"></span>
  </span>
</label>

<style>
  .sel { display: inline-flex; align-items: center; gap: .5rem; }
  .sel__label {
    font-size: .72rem; text-transform: uppercase; letter-spacing: .06em;
    color: var(--ink-3);
  }
  .sel__wrap { position: relative; display: inline-block; }
  .sel__wrap select {
    appearance: none; -webkit-appearance: none;
    font: inherit;
    font-size: .84rem;
    color: var(--ink);
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: .34rem 1.9rem .34rem .6rem;
    cursor: pointer;
    outline: none;
  }
  .sel__wrap select:hover { border-color: var(--ink-3); }
  .sel__wrap select:focus-visible {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 25%, transparent);
  }
  .sel__chev {
    position: absolute; right: .6rem; top: 50%;
    width: .42rem; height: .42rem;
    border-right: 1.5px solid var(--ink-3);
    border-bottom: 1.5px solid var(--ink-3);
    transform: translateY(-65%) rotate(45deg);
    pointer-events: none;
  }
</style>
