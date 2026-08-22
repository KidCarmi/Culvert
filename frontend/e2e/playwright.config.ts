import { defineConfig } from "@playwright/test";

// FE-1B real-binary smoke configuration. The CULVERT binary is started by
// scripts/e2e-smoke.sh (never a dev server, never a mock); its admin-UI base
// URL arrives via CULVERT_E2E_BASE_URL.
export default defineConfig({
  testDir: ".",
  timeout: 60_000,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env["CULVERT_E2E_BASE_URL"] ?? "http://127.0.0.1:19090",
    headless: true,
    // Environments with a system-provisioned Chromium (no playwright
    // download) point this at the browser binary; CI installs the pinned
    // revision via `npx playwright install chromium` and leaves it unset.
    launchOptions: process.env["CULVERT_PW_CHROMIUM"]
      ? { executablePath: process.env["CULVERT_PW_CHROMIUM"] }
      : {},
  },
});
