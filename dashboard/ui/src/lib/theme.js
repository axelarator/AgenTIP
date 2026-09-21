// data-theme on <html>, persisted. Wrapped in try/catch: localStorage can
// throw in a private window, and a theme toggle is not worth a broken page.
export function initTheme() {
  try {
    const saved = localStorage.getItem("cti-theme");
    if (saved) document.documentElement.setAttribute("data-theme", saved);
  } catch { /* fall back to the OS preference */ }
}

export function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme")
    || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try { localStorage.setItem("cti-theme", next); } catch { /* not persisted */ }
}
