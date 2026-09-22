import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Builds into ../static, which server.py serves at /. The output is
// committed: the lab VM serves it directly and nothing on that path has
// node, so a change to src/ is not deployed until the rebuilt bundle is
// committed with it (a test fails if the bundle is older than its sources).
//
// `emptyOutDir` deletes what it finds. During the rewrite this pointed at a
// staging directory so one stray build could not replace the working
// dashboard; now that this IS the dashboard, that protection has done its
// job. The previous UI is in git history if it is ever needed.
export default defineConfig({
  plugins: [svelte()],
  base: "/",
  build: {
    outDir: "../static",
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
