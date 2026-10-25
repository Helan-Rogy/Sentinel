import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const target = process.env.VITE_API_TARGET || "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    allowedHosts: true,
    proxy: {
      "/api": { target, changeOrigin: true },
      "/ws": { target: target.replace("http", "ws"), ws: true },
    },
  },
});
