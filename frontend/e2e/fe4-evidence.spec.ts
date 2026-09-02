// FE-4 visual-evidence captures (§25). Runs only when CULVERT_EVIDENCE_DIR
// is set; screenshots are evidence artifacts, never committed. All captures
// run against the real AUTH appliance with the admin storageState (the
// default chromium project state), over the seeded default-deny history.
// The diagnostics fail-with-action shot uses a network-layer fixture over
// the REAL /api/diagnostics response (the FE-3 TLS-fallback precedent) —
// nothing server-side is mutated.
import { expect } from "@playwright/test";
import { test } from "./test";

const dir = process.env["CULVERT_EVIDENCE_DIR"];

test.skip(dir === undefined, "evidence captures run only in qualification");

const out = (name: string): string => `${dir ?? "."}/${name}`;

test("capture FE-4 monitor evidence", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.emulateMedia({ colorScheme: "dark" });

  // Overview — dark + light.
  await page.goto("/app/");
  await expect(page.getByText("Management health")).toBeVisible();
  await expect(page.getByText(/^Updated \d\d:\d\d:\d\d$/)).toBeVisible();
  await page.screenshot({ path: out("overview-1440-dark.png") });
  await page.emulateMedia({ colorScheme: "light" });
  await page.screenshot({ path: out("overview-1440-light.png") });
  await page.emulateMedia({ colorScheme: "dark" });

  // Traffic — default bounded query over seeded history.
  await page.goto("/app/monitor/traffic");
  await expect(page.getByText("fe4-seed-149.test")).toBeVisible();
  await page.screenshot({ path: out("traffic-1440-dark.png") });

  // Traffic — server-side filtered query (host + status).
  await page.getByLabel("Host / IP contains").fill("fe4-seed-1.");
  await page.getByLabel("Status").selectOption("POLICY_DEFAULT_DENY");
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(page.getByText("1 results")).toBeVisible();
  await page.screenshot({ path: out("traffic-filtered-dark.png") });

  // Traffic — expanded row detail (full URI lives only here).
  await page
    .getByRole("button", { name: /Details for fe4-seed-1\.test/ })
    .click();
  await expect(page.getByText("Full URI")).toBeVisible();
  await page.screenshot({ path: out("traffic-row-detail-dark.png") });

  // Traffic — truthful empty result.
  await page.getByLabel("Host / IP contains").fill("no-such-host-zzz");
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(page.getByText("No matching requests")).toBeVisible();
  await page.screenshot({ path: out("traffic-empty.png") });

  // Audit.
  await page.goto("/app/monitor/audit");
  await expect(
    page.getByText(/Page 1 of \d+ · \d+ matching entries/),
  ).toBeVisible();
  await page.screenshot({ path: out("audit-1440-dark.png") });

  // Diagnostics — the deterministic default_auth_open WARN row with its
  // operator_action (AUTH runs default-auth Exempt).
  await page.goto("/app/diagnostics");
  await expect(page.getByText("default_auth_open")).toBeVisible();
  await expect(
    page.getByText(/Set default authentication to Require under Settings/),
  ).toBeVisible();
  await page.screenshot({ path: out("diagnostics-warn-dark.png") });

  // Diagnostics — FAIL check with first-class operator_action (network-layer
  // fixture over the real snapshot response; no server mutation).
  await page.route(
    (u) => u.pathname === "/api/diagnostics",
    async (route) => {
      const resp = await route.fetch();
      const body: unknown = await resp.json();
      const isRecord = (v: unknown): v is Record<string, unknown> =>
        typeof v === "object" && v !== null && !Array.isArray(v);
      const isArr = (v: unknown): v is readonly unknown[] => Array.isArray(v);
      const o = isRecord(body) ? body : {};
      const prior = isArr(o["checks"]) ? o["checks"] : [];
      await route.fulfill({
        response: resp,
        json: {
          ...o,
          verdict: "fail",
          checks: [
            {
              code: "storage_writable",
              status: "fail",
              message:
                "data directory writes are failing (evidence fixture over the live snapshot)",
              operator_action:
                "Fix mount/permissions on the data directory (chown to the proxy UID, ensure the volume is mounted read-write), then restart the proxy.",
            },
            ...prior,
          ],
        },
      });
    },
  );
  await page.goto("/app/diagnostics");
  await expect(page.getByText("storage_writable")).toBeVisible();
  await expect(page.getByText(/Fix mount\/permissions/)).toBeVisible();
  await page.screenshot({ path: out("diagnostics-fail-action.png") });
  await page.unrouteAll();

  // Governance — admin posture snapshot.
  await page.goto("/app/governance");
  await expect(page.getByText("Enforcement posture")).toBeVisible();
  await expect(page.getByText("would_deny").first()).toBeVisible();
  await page.screenshot({ path: out("governance-admin.png") });

  // Monitor at 1024×768.
  await page.setViewportSize({ width: 1024, height: 768 });
  await page.goto("/app/monitor/traffic");
  await expect(page.getByText("fe4-seed-149.test")).toBeVisible();
  await page.screenshot({ path: out("monitor-1024.png") });

  // Traffic at 640×800 (≈200% zoom), full page.
  await page.setViewportSize({ width: 640, height: 800 });
  await page.reload();
  await expect(page.getByRole("heading", { name: "Traffic" })).toBeVisible();
  await page.screenshot({ path: out("traffic-200pct.png"), fullPage: true });
});
