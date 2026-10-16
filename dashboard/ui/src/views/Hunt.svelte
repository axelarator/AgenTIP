<script>
  import { href } from "../lib/router.js";
  import PageHeader from "../components/PageHeader.svelte";
  import IndicatorChip from "../components/IndicatorChip.svelte";
  import Memberships from "../components/Memberships.svelte";

  let { query = "" } = $props();

  let text = $state("");
  $effect(() => { text = query || ""; });

  // Not `resource`: a query that does not parse comes back 400 with the
  // reason, and that reason is the most useful thing on the page.
  let res = $state({ loading: false, data: null, error: null, busy: false });
  let latest = 0;
  $effect(() => {
    const q = (query || "").trim();
    if (!q) { res = { loading: false, data: null, error: null, busy: false }; return; }
    const mine = ++latest;
    res = { loading: true, data: null, error: null, busy: false };
    fetch(`/api/hunt?q=${encodeURIComponent(q)}&limit=200`, { headers: { accept: "application/json" } })
      .then(async (r) => {
        const body = await r.json().catch(() => ({}));
        if (mine !== latest) return;
        if (r.ok) res = { loading: false, data: body, error: null, busy: false };
        else res = { loading: false, data: null, error: body.error || `${r.status} ${r.statusText}`,
                     busy: r.status === 503 };
      })
      .catch((e) => { if (mine === latest) res = { loading: false, data: null, error: e.message, busy: false }; });
  });

  function run(e) {
    e?.preventDefault();
    const q = text.trim();
    if (q) location.hash = href.hunt(q);
  }
  function onKey(e) {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) run(e);
  }

  const EXAMPLES = [
    ["Stock self-signed certs on a C2 port", "tls.default_subject:* AND net.port:8443"],
    ["A JARM, minus Cloudflare", "tls.jarm:27d40d40d00040d1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c AND NOT net.asn:13335"],
    ["Who sat on an address, and when", "net.resolved_ip:192.252.186.62 OR net.historical_ip:192.252.186.62"],
    ["…only in 2026", "(net.resolved_ip:192.252.186.62 OR net.historical_ip:192.252.186.62) during:[2026-01-01,2026-12-31]"],
    ["Candidates worth a look", "role:candidate band:probable"],
    ["Certificates rotated this week", "changed:tls.cert_sha256 since:7d"],
  ];
</script>

<PageHeader title="Hunt"
  sub="Query everything the store has observed by key:value — selectors, memberships, vantages and time." />

<form class="hunt-form card" onsubmit={run}>
  <textarea bind:value={text} onkeydown={onKey} rows="2" spellcheck="false"
            placeholder='tls.jarm:<hash> AND NOT net.asn:13335   ·   cluster:jadeprox role:candidate   ·   net.port:8443 seen:>2026-09-01'></textarea>
  <div class="hunt-form__row">
    <button class="btn" type="submit">Run</button>
    <span class="hint">Ctrl/⌘ + Enter · AND (implicit) · OR · NOT · ( ) · <code>*</code> any · <code>~"regex"</code> ·
      <code>during:[A,B]</code> · <code>seen:&gt;DATE</code> · <code>changed:TYPE since:7d</code></span>
  </div>
</form>

{#if !query}
  <div class="card">
    <div class="card__title">Examples</div>
    <ul class="examples">
      {#each EXAMPLES as [label, q]}
        <li><a href={href.hunt(q)}>{label}</a> <code>{q}</code></li>
      {/each}
    </ul>
    <p class="hint">Keys: any selector type (<code>tls.*</code>, <code>http.*</code>, <code>net.*</code>,
      <code>dns.*</code>, <code>whois.*</code>, <code>ssh.*</code>, <code>webamon.*</code>),
      <code>net.port</code>, <code>indicator</code>, <code>type</code>, <code>cluster</code>, <code>role</code>,
      <code>band</code>, <code>vantage</code>, <code>changed</code>. A match says an indicator carried a
      value; open <b>pairs</b> on a row to see what that link is worth.</p>
  </div>
{:else if res.loading}
  <div class="loading">Running…</div>
{:else if res.error}
  <div class="card hunt-error" class:is-busy={res.busy}>{res.error}</div>
{:else if res.data}
  {@const d = res.data}
  <div class="hunt-summary">
    {d.total} match{d.total === 1 ? "" : "es"}{#if d.window.from || d.window.to}
      in [{d.window.from?.slice(0, 10) || "…"}, {d.window.to?.slice(0, 10) || "…"}]{/if}{#if d.returned < d.total}, showing {d.returned}{/if}
  </div>
  {#if d.results.length}
    <div class="table-wrap">
      <table class="data-table">
        <thead><tr><th>Indicator</th><th>Clusters</th><th>Matched on</th></tr></thead>
        <tbody>
          {#each d.results as r}
            <tr>
              <td>
                <IndicatorChip value={r.indicator} />
                <a class="pairs-link" href={href.pairs(r.indicator)}>pairs</a>
              </td>
              <td><Memberships rows={r.memberships} /></td>
              <td>
                {#each r.matched as m}
                  <div class="span-row mono">
                    <span class="span-type">{m.type}</span>={String(m.value).slice(0, 72)}
                    <span class="span-when">{m.from.slice(0, 10)} → {m.to.slice(0, 10)}</span>
                    <span class="span-src">{m.source}{m.vantage ? ` · ${m.vantage}` : ""}</span>
                  </div>
                {:else}
                  <span class="hint">membership / indicator terms only</span>
                {/each}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <div class="empty-state">Nothing in the store matches.</div>
  {/if}
{/if}

<style>
  .hunt-form { display: flex; flex-direction: column; gap: 8px; margin-bottom: 16px; }
  .hunt-form textarea {
    width: 100%; font-family: var(--font-mono); font-size: 13px; padding: 10px 12px;
    border: 1px solid var(--border); border-radius: 8px; background: var(--surface-2);
    color: var(--ink); resize: vertical; box-sizing: border-box;
  }
  .hunt-form__row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .btn {
    padding: 6px 16px; border-radius: 8px; border: 1px solid var(--accent);
    background: var(--accent); color: var(--surface); font-weight: 600; cursor: pointer;
  }
  .hint { color: var(--ink-3); font-size: 12.5px; }
  .examples { margin: 0; padding-left: 18px; display: grid; gap: 6px; font-size: 13px; }
  .examples code, .hint code { font-size: 12px; color: var(--ink-2); }
  .hunt-summary { font-size: 13px; color: var(--ink-2); margin-bottom: 10px; }
  .hunt-error { color: var(--pri-high-ink); background: var(--pri-high-bg); }
  .hunt-error.is-busy { color: var(--ink-2); background: var(--surface-2); }
  .pairs-link { font-size: 12px; margin-left: 6px; }
  .span-row { font-size: 12px; line-height: 1.7; word-break: break-all; }
  .span-type { color: var(--accent); }
  .span-when { color: var(--ink-2); margin-left: 8px; }
  .span-src { color: var(--ink-3); margin-left: 8px; }
</style>
