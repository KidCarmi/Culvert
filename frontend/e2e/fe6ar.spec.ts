// FE-6A RECOVERY FOLLOW-UP (record 6AR) — real-binary journeys for the
// Identity Providers recovery card on the AUTH appliance.
//
// The Go proof (fe6ar_resend_red_test.go) shows on the production handlers
// that the IdP operation ledger evicts DECIDED records, so a 404 lookup proves
// neither non-commit nor safe retry, and that a re-sent operation executes
// again. The page therefore no longer offers "Re-send": an absent record is
// UNKNOWN, the marker is kept, every mutation stays blocked, and the typed
// Abandon is the only exit. These journeys drive that posture through the
// real appliance:
//
//   J1 a LOST response (the appliance received and committed the create; the
//      browser never saw the answer): marker retained across a reload, every
//      mutation blocked, Recover ⇒ committed ⇒ marker cleared, ONE provider.
//   J2 a NEVER-SENT request (aborted before the appliance saw it): Recover ⇒
//      404 ⇒ UNKNOWN — "retains no record", no Re-send, marker kept across a
//      reload, Abandon typed on the operationId discards the browser marker
//      only; the next operation is a NEW one (new operationId) and lands.
//   J3 an EVICTED commit: the browser's own marker for a committed create
//      whose answer was lost; the profile is then deleted and 256 decided
//      operations evict the record through the admin API; the appliance
//      answers 404 for a write it DID execute — the page renders UNKNOWN and
//      offers no re-send (a re-send would create the provider a second time,
//      as the Go proof shows), the marker is kept, Abandon is the exit.
import type { APIRequestContext, Page } from "@playwright/test";
import { expect, request, test } from "./test";
import { AUTH_URL, EMPTY_STATE, USERS } from "./fixtures";

const IDP_ROUTE = "/app/objects/identity-providers";
const MARKER_KEY = "culvert.idp.operation-recovery.v1";
const PREFIX = "FE-6AR";
const DIR_URL = "ldap://dc-6ar.invalid:389";

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
async function login(page: Page): Promise<void> {
  await page.getByLabel("Username").fill(USERS.admin.user);
  await page.getByLabel("Password").fill(USERS.admin.pass);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(new RegExp(`${IDP_ROUTE}$`));
}
async function adminClient(xff: string): Promise<APIRequestContext> {
  const ctx = await request.newContext({
    baseURL: AUTH_URL,
    extraHTTPHeaders: { "X-Forwarded-For": xff },
  });
  const r = await ctx.post("/api/auth/login", {
    data: { user: USERS.admin.user, pass: USERS.admin.pass },
  });
  expect(r.ok(), await r.text()).toBe(true);
  return ctx;
}
async function marker(page: Page): Promise<Record<string, unknown> | null> {
  const raw = await page.evaluate((k) => sessionStorage.getItem(k), MARKER_KEY);
  if (raw === null) return null;
  const v: unknown = JSON.parse(raw);
  return isRecord(v) ? v : null;
}
async function typeConfirm(page: Page, word: string): Promise<void> {
  await page
    .getByRole("dialog")
    .getByLabel(`Type ${word} to confirm`)
    .fill(word);
}
/** Fill the disabled-LDAP editor (no credential ⇒ no T2 step) and submit. */
async function submitCreate(page: Page, name: string): Promise<void> {
  const main = page.getByRole("main");
  await main.getByRole("button", { name: "Add provider" }).click();
  const dlg = page.getByRole("dialog");
  await dlg.getByLabel("Type").selectOption("ldap");
  await dlg.getByLabel(/^Name\s*\*?$/).fill(name);
  await dlg.getByLabel(/^Directory URL/).fill(DIR_URL);
  await dlg.getByLabel(/^Base DN/).fill("dc=example");
  await dlg.getByRole("button", { name: "Review and save" }).click();
}
async function expectUnknownAbsent(page: Page): Promise<void> {
  const main = page.getByRole("main");
  await expect(main.getByText(/retains no record/)).toBeVisible();
  await expect(main.getByText(/never recorded/)).toHaveCount(0);
  await expect(main.getByText(/may be re-sent/)).toHaveCount(0);
  await expect(main.getByRole("button", { name: "Re-send" })).toHaveCount(0);
  await expect(main.getByRole("button", { name: "Abandon" })).toBeVisible();
  await expect(
    main.getByRole("button", { name: "Add provider" }),
  ).toBeDisabled();
  expect(await marker(page)).not.toBeNull();
}
async function abandon(page: Page, op: string): Promise<void> {
  const main = page.getByRole("main");
  await main.getByRole("button", { name: "Abandon" }).click();
  const dlg = page.getByRole("dialog");
  await expect(
    dlg.getByRole("button", { name: "Abandon", exact: true }),
  ).toBeDisabled();
  await typeConfirm(page, op);
  await dlg.getByRole("button", { name: "Abandon", exact: true }).click();
  await expect(main.getByText("Unresolved provider operation")).toHaveCount(0);
  expect(await marker(page)).toBeNull();
  await expect(
    main.getByRole("button", { name: "Add provider" }),
  ).toBeEnabled();
}

interface Profile {
  id: string;
  name: string;
  revision: number;
}
async function profiles(
  api: APIRequestContext,
): Promise<{ revision: string; profiles: Profile[] }> {
  const r = await api.get("/api/idp");
  expect(r.ok(), await r.text()).toBe(true);
  const v: unknown = await r.json();
  if (!isRecord(v) || !Array.isArray(v["profiles"]))
    throw new Error("bad list");
  const out: Profile[] = [];
  for (const p of v["profiles"]) {
    if (!isRecord(p)) continue;
    out.push({
      id: String(p["id"]),
      name: String(p["name"]),
      revision: Number(p["revision"]),
    });
  }
  return { revision: String(v["revision"]), profiles: out };
}
async function deleteProfile(
  api: APIRequestContext,
  p: Profile,
): Promise<void> {
  const r = await api.delete(`/api/idp/${p.id}?revision=${String(p.revision)}`);
  expect(r.ok(), await r.text()).toBe(true);
}
async function cleanup(api: APIRequestContext): Promise<void> {
  const { profiles: list } = await profiles(api);
  for (const p of list)
    if (p.name.startsWith(PREFIX)) await deleteProfile(api, p);
}

test.describe("FE-6AR — IdP recovery: an absent ledger record is UNKNOWN", () => {
  test.use({ storageState: EMPTY_STATE });
  test.describe.configure({ mode: "serial" });

  test.afterAll(async () => {
    const api = await adminClient("10.66.0.9");
    try {
      await cleanup(api);
    } finally {
      await api.dispose();
    }
  });

  test("J1 lost response: marker retained across a reload, mutations blocked, Recover ⇒ committed, one provider", async ({
    page,
  }) => {
    await page.goto(`${AUTH_URL}${IDP_ROUTE}`);
    await login(page);
    const main = page.getByRole("main");
    // The appliance receives and answers the create; the browser loses it.
    await page.route("**/api/idp?*", async (route) => {
      if (route.request().method() !== "POST") {
        await route.continue();
        return;
      }
      await route.fetch();
      await route.abort("failed");
    });
    await submitCreate(page, `${PREFIX} lost`);
    await expect(main.getByText("Unresolved provider operation")).toBeVisible();
    await page.unroute("**/api/idp?*");
    const m = await marker(page);
    expect(m).not.toBeNull();
    const op = String(m?.["operationId"]);
    await expect(
      main.getByRole("button", { name: "Add provider" }),
    ).toBeDisabled();

    // Reload: the marker survives, the card returns, mutations stay blocked.
    await page.reload();
    await expect(main.getByText("Unresolved provider operation")).toBeVisible();
    await expect(
      main.getByRole("button", { name: "Add provider" }),
    ).toBeDisabled();
    expect((await marker(page))?.["operationId"]).toBe(op);

    // Recover: the appliance's ledger holds the committed record.
    await main.getByRole("button", { name: "Recover" }).click();
    await expect(main.getByText(/is committed on the appliance/)).toBeVisible();
    await expect(main.getByText("Unresolved provider operation")).toHaveCount(
      0,
    );
    expect(await marker(page)).toBeNull();
    await expect(
      main.getByRole("row", { name: new RegExp(`${PREFIX} lost`) }),
    ).toHaveCount(1);
  });

  test("J2 never sent: 404 ⇒ UNKNOWN (no re-send) across a reload; typed Abandon; the next operation is a NEW identity", async ({
    page,
  }) => {
    await page.goto(`${AUTH_URL}${IDP_ROUTE}`);
    await login(page);
    const main = page.getByRole("main");
    const sentOps: string[] = [];
    page.on("request", (req) => {
      const u = new URL(req.url());
      if (req.method() === "POST" && u.pathname === "/api/idp") {
        const id = u.searchParams.get("operationId");
        if (id !== null) sentOps.push(id);
      }
    });
    await page.route("**/api/idp?*", async (route) => {
      if (route.request().method() !== "POST") {
        await route.continue();
        return;
      }
      await route.abort("failed"); // never reaches the appliance
    });
    await submitCreate(page, `${PREFIX} never sent`);
    await expect(main.getByText("Unresolved provider operation")).toBeVisible();
    await page.unroute("**/api/idp?*");
    const op = String((await marker(page))?.["operationId"]);
    expect(sentOps).toEqual([op]);

    await main.getByRole("button", { name: "Recover" }).click();
    await expectUnknownAbsent(page);
    // Reload: still unresolved, still no re-send.
    await page.reload();
    await expect(main.getByText("Unresolved provider operation")).toBeVisible();
    await main.getByRole("button", { name: "Recover" }).click();
    await expectUnknownAbsent(page);
    expect((await marker(page))?.["operationId"]).toBe(op);
    // Nothing was ever written for this operation.
    await expect(
      main.getByRole("row", { name: new RegExp(`${PREFIX} never sent`) }),
    ).toHaveCount(0);

    // The only exit: the typed Abandon (browser marker only).
    await abandon(page, op);
    await expect(
      main.getByRole("row", { name: new RegExp(`${PREFIX} never sent`) }),
    ).toHaveCount(0);

    // A new operation after abandonment: NEW operationId, and it lands.
    await submitCreate(page, `${PREFIX} after abandon`);
    await expect(
      main.getByRole("row", { name: new RegExp(`${PREFIX} after abandon`) }),
    ).toBeVisible();
    expect(sentOps).toHaveLength(2);
    expect(sentOps[1]).not.toBe(op);
    expect(await marker(page)).toBeNull();
  });

  test("J3 evicted commit: the appliance executed the write, evicted its record, answers 404 — the page renders UNKNOWN and offers no re-send", async ({
    page,
  }) => {
    test.setTimeout(300_000);
    await page.goto(`${AUTH_URL}${IDP_ROUTE}`);
    await login(page);
    const main = page.getByRole("main");
    await page.route("**/api/idp?*", async (route) => {
      if (route.request().method() !== "POST") {
        await route.continue();
        return;
      }
      await route.fetch(); // the appliance commits it
      await route.abort("failed"); // the browser never learns
    });
    await submitCreate(page, `${PREFIX} evicted`);
    await expect(main.getByText("Unresolved provider operation")).toBeVisible();
    await page.unroute("**/api/idp?*");
    const op = String((await marker(page))?.["operationId"]);

    const api = await adminClient("10.66.0.3");
    try {
      // The committed provider exists and its ledger record is retained.
      const before = await profiles(api);
      const mine = before.profiles.find((p) => p.name === `${PREFIX} evicted`);
      expect(mine, "the appliance committed the lost create").toBeTruthy();
      let look = await api.get(`/api/idp/operations/${op}`);
      expect(look.status()).toBe(200);
      // Another admin deletes it; then 256 decided operations evict X. The
      // admin plane caps mutating requests per client identity per minute
      // (a deliberate posture, fully armed here), so the eviction is spread
      // over distinct forwarded identities the trusted-proxy premise admits.
      if (mine !== undefined) await deleteProfile(api, mine);
      let worker: APIRequestContext | null = null;
      try {
        for (let i = 0; i < 256 + 8; i++) {
          look = await api.get(`/api/idp/operations/${op}`);
          if (look.status() === 404) break;
          if (i % 20 === 0) {
            if (worker !== null) await worker.dispose();
            worker = await adminClient(`10.66.1.${String(1 + i / 20)}`);
          }
          if (worker === null) throw new Error("no worker client");
          const { revision } = await profiles(worker);
          const evictOp = crypto.randomUUID();
          const c = await worker.post(
            `/api/idp?documentRevision=${encodeURIComponent(revision)}&operationId=${evictOp}`,
            {
              data: {
                name: `${PREFIX} evict ${String(i)}`,
                type: "oidc",
                enabled: false,
                oidc: {
                  issuer: "https://203.0.113.10",
                  clientId: "cid",
                  clientSecret: "e",
                },
              },
            },
          );
          expect(c.ok(), await c.text()).toBe(true);
          const v: unknown = await c.json();
          if (!isRecord(v)) throw new Error("bad create answer");
          await deleteProfile(worker, {
            id: String(v["id"]),
            name: String(v["name"]),
            revision: Number(v["revision"]),
          });
        }
      } finally {
        if (worker !== null) await worker.dispose();
      }
      look = await api.get(`/api/idp/operations/${op}`);
      expect(look.status(), "X evicted from the ledger").toBe(404);
    } finally {
      await api.dispose();
    }

    // The browser still holds its own marker for X; the appliance answers 404
    // for a write it executed. UNKNOWN — never "never recorded", no re-send.
    await page.reload();
    await expect(main.getByText("Unresolved provider operation")).toBeVisible();
    expect((await marker(page))?.["operationId"]).toBe(op);
    await main.getByRole("button", { name: "Recover" }).click();
    await expectUnknownAbsent(page);
    await expect(
      main.getByRole("row", { name: new RegExp(`${PREFIX} evicted`) }),
    ).toHaveCount(0);
    await abandon(page, op);
    // Abandon wrote nothing: the provider stays deleted.
    await expect(
      main.getByRole("row", { name: new RegExp(`${PREFIX} evicted`) }),
    ).toHaveCount(0);
  });
});
