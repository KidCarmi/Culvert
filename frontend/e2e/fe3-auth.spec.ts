// FE-3 authentication flows (§21.4–11, §23) against the REAL configured
// appliance (seeded roster: admin, op-user, view-user, totp-user). Every
// flow starts unauthenticated (storageState override) and watches for
// console/page errors and external-origin requests.
import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import {
  AUTH_URL,
  EMPTY_STATE,
  TOTP_SECRET,
  USERS,
  totpCode,
} from "./fixtures";

test.use({ storageState: EMPTY_STATE });

const ORIGIN = new URL(AUTH_URL).origin;

function watch(page: Page): { errors: string[]; external: string[] } {
  const errors: string[] = [];
  const external: string[] = [];
  page.on("console", (m) => {
    // Chromium's network layer logs "Failed to load resource … 4xx/5xx" for
    // the very statuses these flows exercise on purpose (expected 401s,
    // lockout 429, persistence 500). Those are not application errors; every
    // OTHER console error still fails the flow.
    if (m.type() !== "error") return;
    if (/Failed to load resource: .* status of (401|429|500)/.test(m.text()))
      return;
    errors.push(m.text());
  });
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("request", (r) => {
    if (new URL(r.url()).origin !== ORIGIN) external.push(r.url());
  });
  return { errors, external };
}

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}

test("configured appliance shows Login — no shell flash", async ({ page }) => {
  const w = watch(page);
  await page.goto(`${AUTH_URL}/app/`);
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign out" })).toHaveCount(0);
  await expect(page.getByRole("navigation", { name: "Primary" })).toHaveCount(
    0,
  );
  expect(w.errors).toEqual([]);
  expect(w.external).toEqual([]);
});

test("invalid password: controlled error, no session-expiry transition", async ({
  page,
}) => {
  const w = watch(page);
  await page.goto(`${AUTH_URL}/app/`);
  await login(page, USERS.admin.user, "WrongPass9x");
  await expect(page.getByText("Invalid credentials")).toBeVisible();
  // Still the login screen, same step — not a teardown/redirect storm.
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  expect(w.errors).toEqual([]);
  expect(w.external).toEqual([]);
});

test("TOTP: second step, invalid code error, success via real code", async ({
  page,
}) => {
  const w = watch(page);
  await page.goto(`${AUTH_URL}/app/`);
  await login(page, USERS.totp.user, USERS.totp.pass);
  // In-band second step; focus enters the code input.
  await expect(
    page.getByRole("heading", { name: "Two-factor verification" }),
  ).toBeVisible();
  const code = page.getByLabel("Authenticator or backup code");
  await expect(code).toBeFocused();
  // Invalid code → controlled 401 error, still on the TOTP step.
  await code.fill("000000");
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByText("Invalid TOTP code")).toBeVisible();
  // Real RFC 6238 code (same host clock as the server) → authenticated.
  await code.fill(totpCode(TOTP_SECRET));
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.getByText(USERS.totp.user)).toBeVisible();
  expect(w.errors).toEqual([]);
  expect(w.external).toEqual([]);
});

test("logout: server revocation, teardown, storage hygiene (§23)", async ({
  page,
  context,
}) => {
  const w = watch(page);
  await page.goto(`${AUTH_URL}/app/`);
  await login(page, USERS.admin.user, USERS.admin.pass);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  // §23 while authenticated: the session cookie is HttpOnly (not
  // JS-readable), storage carries at most the theme key.
  const cookieNames = (await context.cookies()).map((c) => c.name);
  expect(cookieNames).toContain("ps_ui_session");
  // eslint-disable-next-line no-restricted-properties -- §23 proof: the HttpOnly session cookie must NOT be JS-readable
  const jsCookie = await page.evaluate(() => document.cookie);
  expect(jsCookie).not.toContain("ps_ui_session");
  const ls = await page.evaluate(() => Object.keys(localStorage));
  expect(ls.filter((k) => k !== "culvert-theme")).toEqual([]);
  expect(await page.evaluate(() => sessionStorage.length)).toBe(0);

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  // Server-side revocation: the cookie is gone from the browser…
  const after = (await context.cookies()).map((c) => c.name);
  expect(after).not.toContain("ps_ui_session");
  // …and storage stays clean after the boundary.
  const lsAfter = await page.evaluate(() => Object.keys(localStorage));
  expect(lsAfter.filter((k) => k !== "culvert-theme")).toEqual([]);
  expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
  // No password survives in mounted inputs.
  await expect(page.getByLabel("Password")).toHaveValue("");
  expect(w.errors).toEqual([]);
  expect(w.external).toEqual([]);
});

test("session expiry: boundary 401 → one teardown → login; route intent honored", async ({
  page,
  context,
}) => {
  const w = watch(page);
  await page.goto(`${AUTH_URL}/app/`);
  await login(page, USERS.admin.user, USERS.admin.pass);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  // The server-side session disappears (cookie invalidated in the browser);
  // the next protected probe — fired by the route transition — returns 401.
  await context.clearCookies();
  await page.getByRole("link", { name: "Design System" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();

  // Re-authenticate: the safe internal route intent (/design-system) is
  // honored for the confirmed role.
  await login(page, USERS.admin.user, USERS.admin.pass);
  await expect(
    page.getByRole("heading", { name: "Design system" }),
  ).toBeVisible();
  expect(w.errors).toEqual([]);
  expect(w.external).toEqual([]);
});

test("RBAC navigation: viewer, operator, admin differences", async ({
  page,
}) => {
  const w = watch(page);
  // viewer: no Administration affordances.
  await page.goto(`${AUTH_URL}/app/`);
  await login(page, USERS.viewer.user, USERS.viewer.pass);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.getByText("viewer", { exact: true })).toBeVisible();
  await expect(page.getByText("Administrators")).toHaveCount(0);
  await expect(page.getByText("Settings")).toHaveCount(0);
  await expect(page.getByText("Access Rules")).toBeVisible(); // read surface stays visible
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();

  // operator: intermediate — same read surfaces, no admin governance, and
  // the role is visible in the shell.
  await login(page, USERS.operator.user, USERS.operator.pass);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.getByText("operator", { exact: true })).toBeVisible();
  await expect(page.getByText("Administrators")).toHaveCount(0);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();

  // admin: governance affordances appear.
  await login(page, USERS.admin.user, USERS.admin.pass);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.getByText("Administrators")).toBeVisible();
  await expect(page.getByText("Settings")).toBeVisible();
  expect(w.errors).toEqual([]);
  expect(w.external).toEqual([]);
});

test("TLS fallback warning renders BEFORE credentials and inside the shell", async ({
  page,
}) => {
  // The server cannot be pushed into TLS fallback deterministically without
  // production changes (uitls.SelfSigned is in-memory crypto), so the REAL
  // responses are rewritten in the browser network layer — decode + render
  // paths are the production code.
  await page.route("**/api/setup/status", async (route) => {
    const resp = await route.fetch();
    const body: unknown = await resp.json();
    const patched = {
      ...(typeof body === "object" && body !== null ? body : {}),
      ui_tls_fallback: true,
      ui_tls_fallback_reason:
        "self-signed certificate generation failed (fixture)",
    };
    await route.fulfill({ response: resp, json: patched });
  });
  await page.route("**/api/auth/status", async (route) => {
    const resp = await route.fetch();
    const body: unknown = await resp.json();
    const patched = {
      ...(typeof body === "object" && body !== null ? body : {}),
      ui_tls_fallback: true,
      ui_tls_fallback_reason:
        "self-signed certificate generation failed (fixture)",
    };
    await route.fulfill({ response: resp, json: patched });
  });
  await page.goto(`${AUTH_URL}/app/`);
  // Prominent warning on the login screen, before any credential entry.
  await expect(
    page.getByText("This connection is NOT encrypted"),
  ).toBeVisible();
  await expect(
    page.getByText(/self-signed certificate generation failed/),
  ).toBeVisible();
  // And it carries into the authenticated shell.
  await login(page, USERS.admin.user, USERS.admin.pass);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(
    page.getByText("Management traffic is NOT encrypted"),
  ).toBeVisible();
});

test("unauthenticated /app/design-system deep link shows Login, not the gallery", async ({
  page,
}) => {
  const w = watch(page);
  await page.goto(`${AUTH_URL}/app/design-system`);
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Design system" }),
  ).toHaveCount(0);
  expect(w.errors).toEqual([]);
  expect(w.external).toEqual([]);
});
