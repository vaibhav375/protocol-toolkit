import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// `npm run build` writes into the Python package, so `python -m protocol_toolkit`
// serves the UI without Node. `npm run dev` proxies the API to a backend started with
// PT_TOKEN=dev PT_DEV_ORIGIN=http://localhost:5173 python -m protocol_toolkit web --port 8765
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: "../protocol_toolkit/webapp/static", emptyOutDir: true, chunkSizeWarningLimit: 900 },
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:8765", ws: true, changeOrigin: true, headers: { "X-Token": "dev" } },
    },
  },
});
