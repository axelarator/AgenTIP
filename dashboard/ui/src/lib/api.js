// One fetch wrapper for the whole app.
//
// 503 is not an error here, it is a state. The daily job holds DuckDB's
// write lock for minutes at a time and every read endpoint answers 503
// while it does; the old app handled this by catching per-call and
// substituting an empty list, which is why the sidebar survived a sweep.
// Surfacing it as `busy` lets a view say so instead of blanking.
export async function api(path) {
  const res = await fetch(path, { headers: { accept: "application/json" } });
  if (res.status === 503) {
    let detail = "tracking database busy";
    try {
      detail = (await res.json()).error || detail;
    } catch {
      /* body may not be JSON */
    }
    return { busy: true, error: detail };
  }
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export const indicatorUrl = (v) => `/api/indicators/${encodeURIComponent(v)}`;
export const selectorUrl = (t, v) =>
  `/api/selectors?type=${encodeURIComponent(t)}&value=${encodeURIComponent(v)}`;
