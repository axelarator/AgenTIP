import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Builds into ../static-next, NOT ../static, and that is deliberate for the
// whole of this rewrite. `emptyOutDir` deletes what it finds, so pointing it
// at the live directory means one stray `npm run build` silently replaces the
// working dashboard with a half-finished one. server.py mounts static-next at
// /next; the flip to ../static happens once, at cutover.
export default defineConfig({
  plugins: [svelte()],
  base: "/next/",
  build: {
    outDir: "../static-next",
    emptyOutDir: true,
    assetsDir: "assets",
    // Off because the output is committed - a sourcemap would triple the
    // diff of every build for no benefit on a LAN-only tool.
    sourcemap: false,
  },
  server: {
    // `npm run dev` serves the UI on :5173 and proxies the API to the real
    // Starlette server. Safe: that server is read-only by construction.
    proxy: { "/api": "http://127.0.0.1:8420" },
  },
});
