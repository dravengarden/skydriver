import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
    plugins: [react()],
    build: {
        outDir: "dist/client",
        sourcemap: true,
        target: "es2022",
    },
    server: {
        host: "0.0.0.0",
        port: 5173,
        strictPort: true,
        proxy: {
            "/api": "http://127.0.0.1:8787",
        },
    },
});
