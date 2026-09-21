import { readable } from "svelte/store";

// Hash routing, matching the old app's shapes exactly so existing bookmarks
// keep working. The split happens BEFORE decoding, which is load-bearing:
// a selector value can contain an encoded '/' (nginx/1.29.3) and must not
// be torn in half by the segmenter.
export function parseHash(raw) {
  const parts = String(raw || "")
    .replace(/^#\/?/, "")
    .split("/")
    .filter(Boolean)
    .map(decodeURIComponent);
  const [head, ...rest] = parts;
  switch (head) {
    case undefined:
      return { name: "overview" };
    case "cluster":
      return { name: "cluster", slug: rest[0], tab: rest[1] || "diamond" };
    case "techniques":
      return rest[0]
        ? { name: "technique", id: rest[0] }
        : { name: "techniques" };
    case "queue":
      return { name: "queue" };
    case "indicators":
      return { name: "indicators" };
    case "indicator":
      return { name: "indicator", value: rest.join("/") };
    // Old bookmarks land on the better page rather than breaking.
    case "tracking":
      return rest[0]
        ? { name: "indicator", value: rest.join("/") }
        : { name: "indicators" };
    case "findings":
      return rest[0] ? { name: "findings", date: rest[0] } : { name: "findings" };
    case "selector":
      return { name: "selector", type: rest[0], value: rest.slice(1).join("/") };
    case "narratives":
      return rest[0]
        ? { name: "narrative", date: rest[0] }
        : { name: "narratives" };
    case "runs":
      return rest[0] ? { name: "run", date: rest[0] } : { name: "runs" };
    case "search":
      return { name: "search", query: rest.join("/") };
    default:
      return { name: "overview" };
  }
}

export const route = readable(parseHash(location.hash), (set) => {
  const update = () => set(parseHash(location.hash));
  window.addEventListener("hashchange", update);
  return () => window.removeEventListener("hashchange", update);
});

export const href = {
  indicator: (v) => `#/indicator/${encodeURIComponent(v)}`,
  selector: (t, v) => `#/selector/${encodeURIComponent(t)}/${encodeURIComponent(v)}`,
  cluster: (slug, tab) => `#/cluster/${encodeURIComponent(slug)}${tab ? "/" + tab : ""}`,
  findings: (d) => `#/findings/${encodeURIComponent(d)}`,
  narrative: (d) => `#/narratives/${encodeURIComponent(d)}`,
  run: (d) => `#/runs/${encodeURIComponent(d)}`,
};
