import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In development, Vite proxies /api to FastAPI so the browser sees ONE origin.
// Same-origin means no CORS configuration at all, and SameSite=Strict cookies just work.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { "/api": { target: "http://localhost:8000", changeOrigin: false } },
  },
  build: { outDir: "dist", sourcemap: false },
});
