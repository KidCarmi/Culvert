import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// FE-1A production contract (docs/design/FRONTEND-MIGRATION-PLAN.md §1, §7 of
// the FE-1A directive): deterministic output, no sourcemaps, manifest at
// dist/manifest.json, hashed assets, no timestamps / machine paths / git SHAs.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    // Emit the manifest at dist/manifest.json (not .vite/manifest.json):
    // FE-1B embeds and validates it; it is never publicly served.
    manifest: "manifest.json",
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
