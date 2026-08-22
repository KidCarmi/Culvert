// FE-3 auth-setup project: signs in ONCE against the configured appliance
// through the real /api/auth/login endpoint and saves the session cookie as
// storageState for the authenticated suites (FE-1B/FE-2 + evidence).
import { expect, test as setup } from "@playwright/test";
import { mkdirSync } from "node:fs";
import { ADMIN_STATE, AUTH_URL, USERS } from "./fixtures";

setup("authenticate against the seeded appliance", async ({ request }) => {
  const resp = await request.post(`${AUTH_URL}/api/auth/login`, {
    data: { user: USERS.admin.user, pass: USERS.admin.pass },
  });
  expect(resp.ok()).toBe(true);
  const body: unknown = await resp.json();
  expect(body).toMatchObject({
    ok: true,
    user: USERS.admin.user,
    role: "admin",
  });
  mkdirSync("e2e/.state", { recursive: true });
  await request.storageState({ path: ADMIN_STATE });
});
