import { mount } from "svelte";

import App from "./App.svelte";
import { setArkimeBase } from "./lib/sources.js";
import "./app.css";

// Lab-specific settings come from the server before the first render, so a
// link built from them (Arkime) is right on the first page, not after a race.
// A failure only means those links are not offered.
async function start() {
  try {
    const res = await fetch("/api/config", { headers: { accept: "application/json" } });
    if (res.ok) setArkimeBase((await res.json()).arkime_sessions_url);
  } catch {
    /* no config: no Arkime links */
  }
  return mount(App, { target: document.getElementById("app") });
}

export default start();
