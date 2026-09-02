// FE-3 first-run setup flows (§21.1–3) against REAL fresh appliances:
//   FRESH     — completes credential setup end-to-end (server auto-login →
//               fresh auth/status → AppShell)
//   SETUPFAIL — the appliance whose durable credential save always fails
//               (500 + server-side rollback): error shown, retry possible.
// Every flow: zero console/page errors, zero external-origin requests.
import { expect } from "@playwright/test";
import { test } from "./test";
import type { Page } from "@playwright/test";
import { EMPTY_STATE, FRESH_URL, SETUPFAIL_URL } from "./fixtures";

test.use({ storageState: EMPTY_STATE });

function watch(
  page: Page,
  origin: string,
): { errors: string[]; external: string[] } {
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
    if (new URL(r.url()).origin !== origin) external.push(r.url());
  });
  return { errors, external };
}

test("fresh appliance shows Setup — never a shell flash, gallery gated", async ({
  page,
}) => {
  const w = watch(page, new URL(FRESH_URL).origin);
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto(`${FRESH_URL}/app/`);
  await expect(
    page.getByRole("heading", { name: "First-time setup" }),
  ).toBeVisible();
  // No authenticated shell affordances anywhere pre-setup.
  await expect(page.getByRole("button", { name: "Sign out" })).toHaveCount(0);
  await expect(page.getByRole("navigation", { name: "Primary" })).toHaveCount(
    0,
  );
  // §17: pre-setup exposes ONLY the Setup UI — the gallery deep link included.
  await page.goto(`${FRESH_URL}/app/design-system`);
  await expect(
    page.getByRole("heading", { name: "First-time setup" }),
  ).toBeVisible();
  expect(w.errors).toEqual([]);
  expect(w.external).toEqual([]);
});

test("client-side validation mirrors the server and never dials", async ({
  page,
}) => {
  const posts: string[] = [];
  page.on("request", (r) => {
    if (r.method() === "POST") posts.push(r.url());
  });
  await page.goto(`${FRESH_URL}/app/`);
  await page.getByLabel("Administrator username").fill("root-admin");
  await page.getByLabel(/^Password/).fill("weak");
  await page.getByLabel("Confirm password").fill("weak");
  await page
    .getByRole("button", { name: "Create administrator account" })
    .click();
  await expect(
    page.getByText("Password must be at least 8 characters."),
  ).toBeVisible();
  await page.getByLabel(/^Password/).fill("StrongPass123");
  await page.getByLabel("Confirm password").fill("StrongPass124");
  await page
    .getByRole("button", { name: "Create administrator account" })
    .click();
  await expect(page.getByText("Passwords do not match.")).toBeVisible();
  expect(posts).toEqual([]); // invalid forms never reach the network
});

test("persistence failure: 500 keeps setup retryable, form preserved", async ({
  page,
  request,
}) => {
  const w = watch(page, new URL(SETUPFAIL_URL).origin);
  await page.goto(`${SETUPFAIL_URL}/app/`);
  await page.getByLabel("Administrator username").fill("root-admin");
  await page.getByLabel(/^Password/).fill("StrongPass123");
  await page.getByLabel("Confirm password").fill("StrongPass123");
  await page
    .getByRole("button", { name: "Create administrator account" })
    .click();
  await expect(
    page.getByText("Setup did NOT complete", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText(/retrying is safe/)).toBeVisible();
  // Form is NOT wiped on a retryable persistence error.
  await expect(page.getByLabel("Administrator username")).toHaveValue(
    "root-admin",
  );
  await expect(page.getByLabel(/^Password/)).toHaveValue("StrongPass123");
  // The server rolled its in-memory state back — setup remains available.
  const status: unknown = await (
    await request.get(`${SETUPFAIL_URL}/api/setup/status`)
  ).json();
  expect(status).toMatchObject({ needsSetup: true });
  // Retrying reaches the server again (no client-side latch).
  await page
    .getByRole("button", { name: "Create administrator account" })
    .click();
  await expect(
    page.getByText("Setup did NOT complete", { exact: true }),
  ).toBeVisible();
  expect(w.errors).toEqual([]);
  expect(w.external).toEqual([]);
});

test("credential setup completes: auto-login confirmed by fresh auth/status → AppShell", async ({
  page,
}) => {
  const w = watch(page, new URL(FRESH_URL).origin);
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto(`${FRESH_URL}/app/`);
  await page.getByLabel("Administrator username").fill("root-admin");
  await page.getByLabel(/^Password/).fill("StrongPass123");
  await page.getByLabel("Confirm password").fill("StrongPass123");
  await page
    .getByRole("button", { name: "Create administrator account" })
    .click();
  // Authenticated shell only after POST + fresh setup/status + auth/status.
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("root-admin")).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();
  expect(w.errors).toEqual([]);
  expect(w.external).toEqual([]);
});
