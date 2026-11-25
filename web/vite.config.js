import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
// The backend runs on :8080 by default; the dev server proxies API + WS.
export default defineConfig({
    plugins: [react()],
    server: {
        port: 5173,
        proxy: {
            "/api": { target: "http://127.0.0.1:8080", changeOrigin: true },
            "/ws": { target: "ws://127.0.0.1:8080", ws: true },
        },
    },
    build: { outDir: "dist", sourcemap: false },
});
