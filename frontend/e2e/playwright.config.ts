import { defineConfig } from "@playwright/test";

// FE-1B/FE-3 real-binary configuration. scripts/e2e-smoke.sh starts THREE
// CULVERT instances (never a dev server, never a mock):
//   CULVERT_E2E_BASE_URL      — configured appliance (seeded admin roster)
//   CULVERT_E2E_FRESH_URL     — fresh appliance (needsSetup)
//   CULVERT_E2E_SETUPFAIL_URL — appliance whose credential persistence fails
// The auth-setup project signs in once against the configured appliance and
// saves the session cookie as storageState; ordinary specs (the FE-1B/FE-2
// suites) run authenticated with it, while FE-3 auth specs override
// storageState to start unauthenticated.
export default defineConfig({
  testDir: ".",
  timeout: 60_000,
  retries: 0,
  // One worker: the three appliance instances carry real server-side state
  // (setup completion, lockout counters, TOTP replay protection) — spec
  // files must not interleave against them.
  workers: 1,
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
  projects: [
    {
      name: "auth-setup",
      testMatch: /auth\.setup\.ts/,
    },
    {
      name: "chromium",
      testMatch: /.*\.spec\.ts/,
      dependencies: ["auth-setup"],
      use: {
        storageState: "e2e/.state/admin.json",
      },
    },
  ],
});
