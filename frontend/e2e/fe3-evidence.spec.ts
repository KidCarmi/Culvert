// FE-3 visual-evidence captures (§27). Runs only when CULVERT_EVIDENCE_DIR
// is set; screenshots are evidence artifacts, never committed. Setup-screen
// shots use the SETUPFAIL appliance (permanently needsSetup — visually
// identical to any fresh appliance and immune to spec ordering).
import { expect } from "@playwright/test";
import { test } from "./test";
import { AUTH_URL, EMPTY_STATE, SETUPFAIL_URL, USERS } from "./fixtures";

const dir = process.env["CULVERT_EVIDENCE_DIR"];

test.skip(dir === undefined, "evidence captures run only in qualification");
test.use({ storageState: EMPTY_STATE });

const out = (name: string): string => `${dir ?? "."}/${name}`;

test("capture FE-3 auth evidence", async ({ page, context }) => {
  await page.setViewportSize({ width: 1440, height: 900 });

  // Setup screen — dark + light.
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto(`${SETUPFAIL_URL}/app/`);
  await page.waitForSelector("text=First-time setup");
  await page.screenshot({ path: out("setup-1440-dark.png") });
  await page.emulateMedia({ colorScheme: "light" });
  await page.screenshot({ path: out("setup-1440-light.png") });
  await page.emulateMedia({ colorScheme: "dark" });

  // Login screen.
  await page.goto(`${AUTH_URL}/app/`);
  await page.waitForSelector("text=Sign in");
  await page.screenshot({ path: out("login-1440-dark.png") });

  // TOTP second step (no code submitted — replay counter untouched).
  await page.getByLabel("Username").fill(USERS.totp.user);
  await page.getByLabel("Password").fill(USERS.totp.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForSelector("text=Two-factor verification");
  await page.screenshot({ path: out("login-totp-dark.png") });

  // TLS-fallback warning (network-layer fixture over the real responses).
  await page.route("**/api/auth/status", async (route) => {
    const resp = await route.fetch();
    const body: unknown = await resp.json();
    await route.fulfill({
      response: resp,
      json: {
        ...(typeof body === "object" && body !== null ? body : {}),
        ui_tls_fallback: true,
        ui_tls_fallback_reason:
          "self-signed certificate generation failed (fixture)",
      },
    });
  });
  await page.goto(`${AUTH_URL}/app/`);
  await page.waitForSelector("text=This connection is NOT encrypted");
  await page.screenshot({ path: out("login-tls-fallback-warning.png") });
  await page.unrouteAll();

  // Authenticated admin shell.
  await page.goto(`${AUTH_URL}/app/`);
  await page.getByLabel("Username").fill(USERS.admin.user);
  await page.getByLabel("Password").fill(USERS.admin.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await page.screenshot({ path: out("authenticated-admin-shell.png") });

  // Session-expired → login (route intent preserved in the address bar).
  await context.clearCookies();
  await page.getByRole("link", { name: "Design System" }).click();
  await page.waitForSelector("text=Management session ended");
  await page.screenshot({ path: out("session-expired-login.png") });

  // Authenticated viewer shell (no Administration affordances).
  await page.getByLabel("Username").fill(USERS.viewer.user);
  await page.getByLabel("Password").fill(USERS.viewer.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(
    page.getByRole("heading", { name: "Design system" }),
  ).toBeVisible();
  await page.goto(`${AUTH_URL}/app/`);
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await page.screenshot({ path: out("authenticated-viewer-shell.png") });
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.waitForSelector("text=Sign in");

  // Auth surfaces at 1024×768 and 640w (≈200% zoom).
  await page.setViewportSize({ width: 1024, height: 768 });
  await page.goto(`${AUTH_URL}/app/`);
  await page.waitForSelector("text=Sign in");
  await page.screenshot({ path: out("login-1024x768-dark.png") });
  await page.setViewportSize({ width: 640, height: 800 });
  await page.reload();
  await page.waitForSelector("text=Sign in");
  await page.screenshot({
    path: out("login-640w-200pct-zoom.png"),
    fullPage: true,
  });
});
