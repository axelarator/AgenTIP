import { api } from "./api.js";

// A reactive fetch. Re-runs when the URL changes, and a slow response for a
// route the user has already left cannot overwrite the page they are on -
// each request checks it is still the latest before it writes.
export function resource(getUrl) {
  const s = $state({ loading: true, data: null, error: null });
  let latest = 0;
  $effect(() => {
    const url = getUrl();
    const mine = ++latest;
    // No URL means nothing to fetch yet (a panel that is closed). Counting
    // it as a request still retires any answer on its way for the last one.
    if (!url) { s.loading = false; s.data = null; s.error = null; return; }
    s.loading = true;
    s.error = null;
    api(url)
      .then((d) => { if (mine === latest) { s.data = d; s.loading = false; } })
      .catch((e) => { if (mine === latest) { s.data = null; s.error = e.message; s.loading = false; } });
  });
  return s;
}
