<script>
  import { copyText } from "../lib/copy.js";

  let { value, label = null } = $props();
  let state = $state("idle");

  async function copy() {
    state = (await copyText(String(value))) ? "ok" : "fail";
    setTimeout(() => (state = "idle"), 1200);
  }
</script>

<!--
  A value in full, always. There is no truncation here and there must not
  be: the reason this portal exists is that "the cert changed from
  0ca9769a… to 8ed8767a…" cannot be pasted into anything.
  `user-select: all` makes one click select the whole value even when the
  copy button is not used.
-->
<span class="copyvalue">
  <code class="copyvalue__text">{label ?? value}</code>
  <button
    class="copyvalue__btn"
    type="button"
    title="Copy to clipboard"
    aria-label="Copy {value} to clipboard"
    onclick={copy}
  >{state === "ok" ? "copied" : state === "fail" ? "failed" : "copy"}</button>
</span>

<style>
  .copyvalue { display: inline-flex; align-items: baseline; gap: .4rem; max-width: 100%; }
  .copyvalue__text {
    font-family: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace);
    font-size: .82rem;
    user-select: all;
    word-break: break-all;
  }
  .copyvalue__btn {
    flex: none;
    font-size: .68rem;
    text-transform: uppercase;
    letter-spacing: .04em;
    padding: .1rem .35rem;
    border-radius: 4px;
    border: 1px solid var(--border, #d0d0d8);
    background: transparent;
    color: var(--muted, #6b6b76);
    cursor: pointer;
  }
  .copyvalue__btn:hover { color: var(--ink, #16161a); border-color: var(--muted, #6b6b76); }
</style>
