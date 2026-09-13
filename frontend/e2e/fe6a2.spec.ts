// FE-6A.2 — real-binary journeys for the Identity Providers and Administrators
// WRITE surfaces (RED against the frozen FE-6A.1 baseline 98d4a6c8: every
// journey fails on the absent control).
//
// Appliances (scripts/e2e-smoke.sh):
//   IDPW — boots on a CORRUPT registry (quarantined) with a legacy YAML
//          `ldap:` block: W1 repair (T2, confirm = quarantine base name) →
//          W2 legacy import (T2, created disabled) → W3 cutover ceremony
//          (T2, confirm = the legacy directory URL, operationId + revision +
//          confirm bound into the PUT) → W4 edit → W5 delete (T3, typed id),
//          with the secret-leak sweep over DOM, URL, storage and bodies.
//   AUTH — A1 create account (T2) → A2 role change (T2) → A3 lockout clear
//          (T2, bound to the generation) → A4 self-service password change by
//          the created viewer through the shell (signs out, new password
//          logs in) → A5 delete (T3, typed username).
import type { APIRequestContext, Page } from "@playwright/test";
import { expect, request, test } from "./test";
import { AUTH_URL, EMPTY_STATE, IDPW_URL, USERS } from "./fixtures";

const IDP_ROUTE = "/app/objects/identity-providers";
const ADMINS_ROUTE = "/app/administrators";
const YAML_BIND_CANARY = "YAMLBINDCANARY-legacy-ldap-never-in-browser";
const LEGACY_URL = "ldaps://legacy-dc.invalid:636";
const SUFFIX = "6a2w";
const ACCOUNT = `fe6a2-op-${SUFFIX}`;
const SELF = `fe6a2-self-${SUFFIX}`;
const PASS1 = "Fe6a2Passw0rd-one";
const PASS2 = "Fe6a2Passw0rd-two";
const LEAK_NEEDLES = [
  YAML_BIND_CANARY,
  PASS1,
  PASS2,
  "pass_hash",
  "totp_secret",
  'bindPassword":"Y',
  "$2a$10$",
];

interface Watch {
  apiCalls: Array<{ method: string; url: string }>;
  bodies: string[];
}
function watch(page: Page): Watch {
  const w: Watch = { apiCalls: [], bodies: [] };
  page.on("request", (req) => {
    const u = new URL(req.url());
    if (u.pathname.startsWith("/api/"))
      w.apiCalls.push({ method: req.method(), url: u.pathname + u.search });
  });
  page.on("response", (resp) => {
    const u = new URL(resp.url());
    if (!u.pathname.startsWith("/api/")) return;
    void resp
      .text()
      .then((t) => {
        w.bodies.push(t);
      })
      .catch(() => undefined);
  });
  return w;
}
async function storageDump(page: Page): Promise<string> {
  return page.evaluate(() => {
    const out: string[] = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      if (k !== null) out.push(`${k}=${sessionStorage.getItem(k) ?? ""}`);
    }
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k !== null) out.push(`${k}=${localStorage.getItem(k) ?? ""}`);
    }
    return out.join("\n");
  });
}
async function expectNoLeak(
  page: Page,
  w: Watch,
  extra: readonly string[] = [],
): Promise<void> {
  const dom = await page.evaluate(() => document.documentElement.outerHTML);
  const store = await storageDump(page);
  const url = page.url();
  for (const n of [...LEAK_NEEDLES, ...extra]) {
    expect(dom, `DOM leaks ${n}`).not.toContain(n);
    expect(store, `storage leaks ${n}`).not.toContain(n);
    expect(url, `URL leaks ${n}`).not.toContain(n);
    for (const c of w.apiCalls)
      expect(c.url, `request URL leaks ${n}`).not.toContain(n);
    for (const b of w.bodies)
      expect(b, `response body leaks ${n}`).not.toContain(n);
  }
}
async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}
async function newAdminClient(
  base: string,
  xff: string,
): Promise<APIRequestContext> {
  const ctx = await request.newContext({
    baseURL: base,
    extraHTTPHeaders: { "X-Forwarded-For": xff },
  });
  const login = await ctx.post("/api/auth/login", {
    data: { user: USERS.admin.user, pass: USERS.admin.pass },
  });
  expect(login.ok(), await login.text()).toBe(true);
  return ctx;
}
function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
async function typeConfirm(page: Page, word: string): Promise<void> {
  await page
    .getByRole("dialog")
    .getByLabel(`Type ${word} to confirm`)
    .fill(word);
}

// ── IDPW: the full provider write journey ─────────────────────────────────
test.describe("FE-6A.2 W — provider writes on the write appliance", () => {
  test.use({ storageState: EMPTY_STATE });

  test("W1–W5 repair → import → cutover → edit → delete, every ceremony at its tier, no secret anywhere", async ({
    page,
  }) => {
    await page.goto(`${IDPW_URL}${IDP_ROUTE}`);
    const w = watch(page);
    await login(page, USERS.admin.user, USERS.admin.pass);
    await expect(page).toHaveURL(new RegExp(`${IDP_ROUTE}$`));
    const main = page.getByRole("main");

    // W1 repair — the evidence is shown ONLY inside the ceremony.
    await expect(main.getByText("Registry degraded")).toBeVisible();
    let dom = await page.evaluate(() => document.documentElement.outerHTML);
    expect(dom).not.toContain("idp_profiles.json.corrupt.");
    await main.getByRole("button", { name: "Repair registry" }).click();
    const repairDlg = page.getByRole("dialog");
    const evidence = (await repairDlg.textContent())?.match(
      /idp_profiles\.json\.corrupt\.\d+/,
    )?.[0];
    expect(
      evidence,
      "the ceremony must show the quarantine evidence",
    ).toBeTruthy();
    await expect(
      repairDlg.getByRole("button", { name: "Repair", exact: true }),
    ).toBeDisabled();
    await typeConfirm(page, evidence ?? "");
    await repairDlg
      .getByRole("button", { name: "Repair", exact: true })
      .click();
    await expect(main.getByText("Registry degraded")).toHaveCount(0);
    await expect(main.getByText("Registry repaired")).toBeVisible();
    dom = await page.evaluate(() => document.documentElement.outerHTML);
    expect(dom).not.toContain("idp_profiles.json.corrupt.");
    expect(
      w.apiCalls.filter(
        (c) => c.method === "POST" && c.url === "/api/idp/repair",
      ),
    ).toHaveLength(1);

    // W2 legacy import — T2 states the facts; the profile lands DISABLED.
    await main
      .getByRole("button", { name: "Import legacy configuration" })
      .click();
    const importDlg = page.getByRole("dialog");
    await expect(importDlg.getByText(/created disabled/i)).toBeVisible();
    await expect(importDlg.getByText(/server-side/i)).toBeVisible();
    await importDlg
      .getByRole("button", { name: "Import", exact: true })
      .click();
    const importedRow = main.getByRole("row", { name: /Imported legacy LDAP/ });
    await expect(importedRow).toBeVisible();
    await expect(
      importedRow.getByText("Disabled", { exact: true }),
    ).toBeVisible();

    // W3 cutover — enabling the imported profile runs the ceremony with the
    // server's confirm value; the PUT binds operationId + revision + confirm.
    await importedRow.getByRole("button", { name: "Edit" }).click();
    const editor = page.getByRole("dialog");
    await editor.getByLabel("Enabled").check();
    await editor.getByRole("button", { name: "Review and save" }).click();
    const cutover = page.getByRole("dialog");
    await expect(
      cutover.getByText("Retire the legacy YAML LDAP authenticator"),
    ).toBeVisible();
    await expect(cutover.getByText(LEGACY_URL).first()).toBeVisible();
    await expect(
      cutover.getByRole("button", { name: "Retire and enable" }),
    ).toBeDisabled();
    await typeConfirm(page, LEGACY_URL);
    await cutover.getByRole("button", { name: "Retire and enable" }).click();
    await expect(main.getByText("Retired", { exact: true })).toBeVisible();
    await expect(
      importedRow.getByText("Enabled", { exact: true }),
    ).toBeVisible();
    const put = w.apiCalls.find(
      (c) => c.method === "PUT" && c.url.startsWith("/api/idp/"),
    );
    expect(put, "the cutover PUT was sent").toBeTruthy();
    const q = new URL(put?.url ?? "/", "http://x").searchParams;
    expect(q.get("revision")).toMatch(/^\d+$/);
    expect(q.get("operationId")).toMatch(/^[0-9a-f-]{36}$/);
    expect(q.get("cutoverConfirm")).toBe(LEGACY_URL);
    // The legacy card's ledger lookup (admin) resolves the update's operation.
    await expect(main.getByText("Committed", { exact: true })).toBeVisible();

    // W4 edit without credential material — no T2 review step, direct save.
    await importedRow.getByRole("button", { name: "Edit" }).click();
    await page
      .getByRole("dialog")
      .getByLabel(/^Name\s*\*?$/)
      .fill("Renamed legacy LDAP");
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Review and save" })
      .click();
    await expect(
      main.getByRole("row", { name: /Renamed legacy LDAP/ }),
    ).toBeVisible();

    // W5 delete — T3: the exact id must be typed.
    const renamed = main.getByRole("row", { name: /Renamed legacy LDAP/ });
    await renamed.getByRole("button", { name: "Delete" }).click();
    const delDlg = page.getByRole("dialog");
    const id = (await delDlg.textContent())?.match(
      /Type ([0-9a-f]{12}) to confirm/,
    )?.[1];
    expect(id, "the ceremony names the exact provider id").toBeTruthy();
    await expect(
      delDlg.getByRole("button", { name: "Delete provider" }),
    ).toBeDisabled();
    await typeConfirm(page, id ?? "");
    await delDlg.getByRole("button", { name: "Delete provider" }).click();
    await expect(
      main.getByRole("row", { name: /Renamed legacy LDAP/ }),
    ).toHaveCount(0);

    // Secret sweep — the legacy bind credential exists on this node and was
    // copied server-side; it must never have crossed to the browser.
    await expectNoLeak(page, w, ["ldap_profiles.json", "/data/"]);
    // Every non-GET went to a contracted mutation path.
    for (const c of w.apiCalls.filter((c) => c.method !== "GET")) {
      expect(
        [
          "/api/auth/login",
          "/api/idp/repair",
          "/api/idp/legacy-ldap/import",
        ].some((p) => c.url === p) || /^\/api\/idp\/[0-9a-f]{12}\?/.test(c.url),
        c.url,
      ).toBe(true);
    }
  });
});

// ── AUTH: the administrator write journey ─────────────────────────────────
test.describe("FE-6A.2 A — administrator writes", () => {
  test.use({ storageState: EMPTY_STATE });

  test.afterAll(async () => {
    // Leave the shared roster as we found it (best-effort, fenced).
    const api = await newAdminClient(AUTH_URL, "10.62.0.9");
    try {
      for (const u of [ACCOUNT, SELF]) {
        const list = await api.get("/api/auth/users");
        const v: unknown = await list.json();
        if (!isRecord(v) || !Array.isArray(v["users"])) continue;
        if (!v["users"].some((x) => isRecord(x) && x["username"] === u))
          continue;
        await api.delete(
          `/api/auth/users?username=${encodeURIComponent(u)}&revision=${String(v["revision"])}`,
        );
      }
    } finally {
      await api.dispose();
    }
  });

  test("A1–A5 create → role change → lockout clear → self password change (shell) → delete", async ({
    page,
    browser,
  }) => {
    await page.goto(`${AUTH_URL}${ADMINS_ROUTE}`);
    const w = watch(page);
    await login(page, USERS.admin.user, USERS.admin.pass);
    await expect(page).toHaveURL(new RegExp(`${ADMINS_ROUTE}$`));
    const main = page.getByRole("main");

    // A1 create (T2 review before the POST)
    await main.getByRole("button", { name: "Add account" }).click();
    let dlg = page.getByRole("dialog");
    await dlg.getByLabel(/^Username\b/).fill(ACCOUNT);
    await dlg.getByLabel("Role").selectOption("viewer");
    await dlg.getByLabel(/^Password\b/).fill(PASS1);
    await dlg.getByRole("button", { name: "Review and create" }).click();
    await expect(page.getByRole("dialog").getByText(ACCOUNT)).toBeVisible();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Create account" })
      .click();
    const row = main.getByRole("row", { name: new RegExp(ACCOUNT) });
    await expect(row).toBeVisible();
    await expect(row.getByText("viewer", { exact: true })).toBeVisible();

    // also the self-service subject
    await main.getByRole("button", { name: "Add account" }).click();
    dlg = page.getByRole("dialog");
    await dlg.getByLabel(/^Username\b/).fill(SELF);
    await dlg.getByLabel("Role").selectOption("viewer");
    await dlg.getByLabel(/^Password\b/).fill(PASS1);
    await dlg.getByRole("button", { name: "Review and create" }).click();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Create account" })
      .click();
    await expect(
      main.getByRole("row", { name: new RegExp(SELF) }),
    ).toBeVisible();

    // A2 role change (T2)
    await row.getByRole("button", { name: "Edit" }).click();
    dlg = page.getByRole("dialog");
    await dlg.getByLabel("Role").selectOption("operator");
    await dlg.getByRole("button", { name: "Review and save" }).click();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Save account" })
      .click();
    await expect(row.getByText("operator", { exact: true })).toBeVisible();
    await expect(main.getByText("Sessions revoked")).toBeVisible();

    // A3 lockout: lock the account with failed logins, then clear it (T2 bound to the generation)
    const bad = await request.newContext({
      baseURL: AUTH_URL,
      extraHTTPHeaders: { "X-Forwarded-For": "10.62.0.77" },
    });
    let locked = false;
    for (let i = 0; i < 12 && !locked; i++) {
      const r = await bad.post("/api/auth/login", {
        data: { user: ACCOUNT, pass: "wrong-password-" + String(i) },
      });
      const t = await r.text();
      locked = r.status() === 429 || t.includes("locked");
    }
    await bad.dispose();
    await page.getByRole("button", { name: "Refresh" }).first().click();
    const lockRow = main
      .getByRole("row", { name: new RegExp(ACCOUNT) })
      .filter({ hasText: /account|pair/ });
    await expect(lockRow.first()).toBeVisible();
    await lockRow.first().getByRole("button", { name: "Clear" }).click();
    dlg = page.getByRole("dialog");
    await expect(dlg.getByText(ACCOUNT)).toBeVisible();
    await dlg.getByRole("button", { name: "Clear lockouts" }).click();
    await expect(main.getByText("Lockouts cleared")).toBeVisible();
    const clearCall = w.apiCalls.find(
      (c) => c.method === "POST" && c.url.startsWith("/api/auth/lockouts"),
    );
    expect(clearCall?.url).toMatch(/generation=\d+/);

    // A4 self-service password change by the created viewer, from the shell.
    const ctx2 = await browser.newContext({ storageState: EMPTY_STATE });
    const p2 = await ctx2.newPage();
    const w2 = watch(p2);
    await p2.goto(`${AUTH_URL}/app/`);
    await login(p2, SELF, PASS1);
    await expect(p2.getByRole("button", { name: "Sign out" })).toBeVisible();
    await p2.getByRole("button", { name: "Change password" }).click();
    const pw = p2.getByRole("dialog");
    await pw.getByLabel(/^Current password\b/).fill(PASS1);
    await pw.getByLabel(/^New password\b/).fill(PASS2);
    await pw.getByRole("button", { name: "Change password" }).click();
    // selfAffected ⇒ complete teardown to the login boundary
    await expect(p2.getByRole("button", { name: "Sign in" })).toBeVisible();
    const change = w2.apiCalls.find(
      (c) =>
        c.method === "POST" && c.url.startsWith("/api/auth/change-password"),
    );
    expect(change?.url).toMatch(/generation=\d+/);
    expect(
      w2.apiCalls.some(
        (c) => c.method === "POST" && c.url === "/api/auth/logout",
      ),
    ).toBe(true);
    await login(p2, SELF, PASS2);
    await expect(p2.getByRole("button", { name: "Sign out" })).toBeVisible();
    await expectNoLeak(p2, w2);
    await ctx2.close();

    // A5 delete (T3 typed username, fenced)
    await page.getByRole("button", { name: "Refresh" }).first().click();
    const delRow = main.getByRole("row", { name: new RegExp(ACCOUNT) }).first();
    await delRow.getByRole("button", { name: "Delete" }).click();
    dlg = page.getByRole("dialog");
    await expect(
      dlg.getByRole("button", { name: "Delete account" }),
    ).toBeDisabled();
    await typeConfirm(page, ACCOUNT);
    await dlg.getByRole("button", { name: "Delete account" }).click();
    await expect(
      main.getByRole("row", { name: new RegExp(`^${ACCOUNT}`) }),
    ).toHaveCount(0);
    const del = w.apiCalls.find((c) => c.method === "DELETE");
    expect(del?.url).toMatch(
      new RegExp(`^/api/auth/users\\?username=${ACCOUNT}&revision=\\d+$`),
    );
    await expectNoLeak(page, w);
  });
});
