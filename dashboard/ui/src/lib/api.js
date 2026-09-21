// One fetch wrapper for the whole app.
//
// 503 is not an error here, it is a state. The daily job holds DuckDB's
// write lock for minutes at a time and every read endpoint answers 503
// while it does; surfacing it as `busy` lets a view say so instead of
// blanking or showing a red failure for something that is working.
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

// `type` is optional and usually absent. A hash chip knows the value and
// not what kind of selector it is; the server resolves that. Guessing from
// the value's shape sent a certificate digest and an SPKI digest to a
// body-hash page that found nothing.
export const selectorUrl = (t, v) =>
  `/api/selectors?value=${encodeURIComponent(v)}` +
  (t ? `&type=${encodeURIComponent(t)}` : "");
