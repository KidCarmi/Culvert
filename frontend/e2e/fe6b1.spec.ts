// FE-6B.1 real-binary journeys — Certificates & CA (viewer read,
// /app/security/certificates, tabs Certificates / CA Management). Written
// RED against the frozen FE-6B.0 entry baseline (c540b176): the route is
// unserved there (the shell carries only a planned "Certificates" entry) and
// the harness carried no CERT / CERTDEG appliance. Real appliances only
// (scripts/e2e-smoke.sh):
//
//   CERT    — a persisted, passphrase-sealed inspection CA (-ca-path +
//             CULVERT_CA_PASSPHRASE) and NO UI pair at boot; this spec seeds
//             one through the supported admin API (never through the
//             surface), so the read surface must report it persisted and
//             NOT active — activation requires a restart.
//   CERTDEG — a MALFORMED bundle at -ca-path (load failed, bundle_malformed,
//             no Root CA), a persisted UI pair whose key does not match its
//             certificate (corrupt at boot), and a pre-seeded operation
//             ledger: a terminal superseded UNKNOWN, a pending import the
//             boot settles as reconciled_evidence_invalid (recoverable
//             UNKNOWN), an aborted persist_failed and a committed OCSP set.
//
//   J1  role matrix (admin / operator / viewer): the nav entry and the page
//       are viewer-readable; only an admin sees the operation lookup; every
//       request is a GET.
//   J2  deep-link continuity: an unauthenticated deep link returns to the
//       route after sign-in; a reload keeps it; ?tab=ca deep-links the CA
//       Management tab; the nav link is reachable.
//   J3  CERT truth: CA present / usable / persisted / encrypted with the
//       revision + fingerprint the API answers; the seeded UI pair
//       persisted, not active, restart required, with the API's revision;
//       OCSP desired vs runtime; ledger and backup facts; the CA tab's
//       rotation / cache / recovery facts.
//   J4  CERTDEG truth: load failure class, no Root CA, corrupt pair; the
//       admin lookup renders each seeded record as the server states it —
//       superseded is TERMINAL UNKNOWN naming the writer and never a
//       success / failure / cancel / retry word; the pending import is a
//       recoverable UNKNOWN; aborted + code; committed; an unknown id is
//       "no retained record"; a viewer never sees or issues the lookup.
//   J5  no mutation: the revisions of every object are unchanged after the
//       visits; every request the surface issues is a GET.
//   J6  leak sweep: the CA passphrase, PEM private-key markers, the data
//       directory path and raw dependency text never reach an API response,
//       the DOM, the URL or web storage.
//   J7  the PEM download is a viewer GET: the browser receives culvert-ca.pem
//       carrying a certificate and no private key.
//
// No retries, no enlarged timeouts, no skips.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page } from "@playwright/test";
import {
  CA_PASSPHRASE_CANARY,
  CERTDEG_DATA_DIR,
  CERTDEG_URL,
  CERT_UI_PAIR_DIR,
  CERT_URL,
  EMPTY_STATE,
  USERS,
} from "./fixtures";
import { expectNavLinkReachable, openNavToFinalState } from "./nav-open";

const ROUTE = "/app/security/certificates";
const NAV_LABEL = "Certificates & CA";
// Fixed (module re-evaluation per worker; the seed is idempotent by the
// server's own uiCert.present fact).
const SEED_OP_ID = "6b1e0000-fe6b-4e2e-9f00-00000000c0de";
const SUP_ID = "6b1e0000-fe6b-4e2e-9f00-000000000501";
const SUP_WRITER = "6b1e0000-fe6b-4e2e-9f00-0000000005aa";
const PEND_ID = "6b1e0000-fe6b-4e2e-9f00-000000000502";
const ABT_ID = "6b1e0000-fe6b-4e2e-9f00-000000000503";
const CMT_ID = "6b1e0000-fe6b-4e2e-9f00-000000000504";
const NONE_ID = "6b1e0000-fe6b-4e2e-9f00-0000000009ff";

const VIEWER_CONTROLS: readonly string[] = [
  "Certificates",
  "CA Management",
  "Refresh",
  "Download CA certificate (PEM)",
];
const ADMIN_CONTROLS: readonly string[] = [...VIEWER_CONTROLS, "Look up"];

const LEAK_NEEDLES: readonly string[] = [
  CA_PASSPHRASE_CANARY,
  "BEGIN EC PRIVATE KEY",
  "BEGIN PRIVATE KEY",
  "BEGIN RSA PRIVATE KEY",
  CERTDEG_DATA_DIR,
  "x509:",
  "no such file",
];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

async function adminClient(
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

async function inventory(
  ctx: APIRequestContext,
): Promise<Record<string, unknown>> {
  const r = await ctx.get("/api/certificates");
  expect(r.ok(), await r.text()).toBe(true);
  const v: unknown = await r.json();
  if (!isRecord(v)) throw new Error("bad inventory");
  return v;
}

function sub(v: Record<string, unknown>, k: string): Record<string, unknown> {
  const s = v[k];
  if (!isRecord(s)) throw new Error(`bad ${k}`);
  return s;
}

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
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

interface Watch {
  apiCalls: Array<{ method: string; path: string }>;
  bodies: string[];
}

function watch(page: Page): Watch {
  const w: Watch = { apiCalls: [], bodies: [] };
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.pathname.startsWith("/api/"))
      w.apiCalls.push({ method: r.method(), path: u.pathname });
  });
  page.on("response", (r) => {
    const u = new URL(r.url());
    if (!u.pathname.startsWith("/api/")) return;
    void r
      .text()
      .then((t) => {
        w.bodies.push(`${u.pathname}\n${t}`);
      })
      .catch(() => undefined);
  });
  return w;
}

async function expectNoLeak(page: Page, w: Watch): Promise<void> {
  const dom = await page.evaluate(() => document.documentElement.outerHTML);
  const url = page.url();
  const storage = await storageDump(page);
  for (const needle of LEAK_NEEDLES) {
    expect(dom, `DOM carries ${needle}`).not.toContain(needle);
    expect(url, `URL carries ${needle}`).not.toContain(needle);
    expect(storage, `storage carries ${needle}`).not.toContain(needle);
    for (const b of w.bodies)
      expect(b, `response carries ${needle}`).not.toContain(needle);
  }
  expect(storage, "the surface persists nothing").toBe("");
}

const AUTH_FLOW = new Set(["/api/auth/login", "/api/auth/logout"]);
function expectOnlyGET(w: Watch): void {
  expect(w.apiCalls.length).toBeGreaterThan(0);
  expect(
    w.apiCalls.filter((c) => c.method !== "GET" && !AUTH_FLOW.has(c.path)),
  ).toEqual([]);
}

function lookupsIn(w: Watch): number {
  return w.apiCalls.filter((c) => c.path.startsWith("/api/ca/operations/"))
    .length;
}

async function expectControls(
  page: Page,
  allowed: readonly string[],
): Promise<void> {
  const main = page.getByRole("main");
  const buttons = await main.getByRole("button").allTextContents();
  expect(buttons.length).toBeGreaterThan(0);
  expect(buttons.every((b) => allowed.includes(b.trim()))).toBe(true);
}

// ── Seed (supported admin API; the surface under test never mutates) ──────
test.beforeAll(async () => {
  const ctx = await adminClient(CERT_URL, "10.66.0.1");
  const inv = await inventory(ctx);
  const ui = sub(inv, "uiCert");
  if (ui["present"] !== true) {
    const cert = readFileSync(join(CERT_UI_PAIR_DIR, "ui.crt"));
    const key = readFileSync(join(CERT_UI_PAIR_DIR, "ui.key"));
    const rev = String(ui["revision"]);
    const qs = new URLSearchParams({
      target: "ui",
      operationId: SEED_OP_ID,
      uiCertRevision: rev,
    });
    const resp = await ctx.post(`/api/certs/upload?${qs.toString()}`, {
      multipart: {
        target: "ui",
        cert: {
          name: "ui.crt",
          mimeType: "application/x-pem-file",
          buffer: cert,
        },
        key: {
          name: "ui.key",
          mimeType: "application/x-pem-file",
          buffer: key,
        },
      },
    });
    expect(resp.ok(), await resp.text()).toBe(true);
  }
  await ctx.dispose();
});

// ── J1 / J5 / J6 admin on CERT ─────────────────────────────────────────────

test("J1/J3/J5/J6 admin on CERT: nav, healthy truth, only GETs, revisions unchanged, no leak", async ({
  page,
}) => {
  const api = await adminClient(CERT_URL, "10.66.0.2");
  const before = await inventory(api);
  const ca = sub(before, "ca");
  const ui = sub(before, "uiCert");
  const ocsp = sub(before, "ocsp");
  const ops = sub(before, "operations");
  const statusResp = await api.get("/api/ca/status");
  const status: unknown = await statusResp.json();
  if (!isRecord(status)) throw new Error("bad status");

  // CERT is a separate appliance: sign in through its own login page.
  await page.context().clearCookies();
  await page.goto(`${CERT_URL}/app/`);
  await expect(page.getByLabel("Username")).toBeVisible();
  const w = watch(page);
  await login(page, USERS.admin.user, USERS.admin.pass);
  const nav = page.getByRole("navigation", { name: "Primary" });
  await expect(nav.getByRole("link", { name: NAV_LABEL })).toBeVisible();
  await nav.getByRole("link", { name: NAV_LABEL }).click();
  await expect(page).toHaveURL(new RegExp(`${ROUTE}$`));
  await expect(page.getByRole("heading", { name: NAV_LABEL })).toBeVisible();
  const main = page.getByRole("main");
  await expect(main.getByText("Node-local").first()).toBeVisible();

  // CA truth as the API states it.
  await expect(
    main.getByText(String(ca["revision"]), { exact: true }),
  ).toBeVisible();
  await expect(main.getByText(String(ca["fingerprint"])).first()).toBeVisible();
  await expect(main.getByText(String(ca["subject"])).first()).toBeVisible();
  await expect(main.getByText("Usable", { exact: true })).toBeVisible();
  await expect(main.getByText("Bundle path configured")).toBeVisible();
  await expect(
    main.getByText("Encrypted at rest", { exact: true }),
  ).toBeVisible();
  // UI pair: persisted through the admin API, NOT active, restart required.
  expect(ui["present"]).toBe(true);
  expect(ui["active"]).toBe(false);
  await expect(main.getByText("Complete pair persisted")).toBeVisible();
  await expect(
    main.getByText(String(ui["revision"]), { exact: true }),
  ).toBeVisible();
  await expect(main.getByText("ui-fe6b1.e2e").first()).toBeVisible();
  await expect(
    main.getByText("Not active on the running listener"),
  ).toBeVisible();
  await expect(main.getByText("Activation requires a restart")).toBeVisible();
  // OCSP desired vs runtime as stated.
  const desired = sub(ocsp, "desired");
  await expect(
    main.getByText(
      `Desired: ${desired["enabled"] === true ? "Enabled" : "Disabled"}`,
    ),
  ).toBeVisible();
  await expect(
    main.getByText(`source: ${String(desired["source"])}`),
  ).toBeVisible();
  // Ledger + backup facts.
  await expect(
    main.getByText(
      `Retained: ${String(ops["retained"])} of ${String(ops["capacity"])}`,
    ),
  ).toBeVisible();
  await expect(main.getByText("UI pair: never archived")).toBeVisible();
  await expect(main.getByText("Config-version rollback: off")).toBeVisible();
  await expectControls(page, ADMIN_CONTROLS);
  await expect(main.getByRole("button", { name: "Look up" })).toBeVisible();

  // CA Management tab: rotation / cache / recovery facts.
  await main.getByRole("tab", { name: "CA Management" }).click();
  await expect(main.getByText("Auto-rotation: on")).toBeVisible();
  await expect(main.getByText("Overlap: 30 days")).toBeVisible();
  await expect(
    main.getByText(`Expires in ${String(status["expiresIn"])}`),
  ).toBeVisible();
  await expect(main.getByText("Leaf validity: 24h")).toBeVisible();
  await expect(main.getByText("Recovery attempts: 0")).toBeVisible();
  await expect(main.getByText("Runtime: Disabled")).toBeVisible();
  await expect(main.getByText("ssl_inspect_origin")).toBeVisible();
  await expect(main.getByText("Evidence limitation")).toBeVisible();

  expectOnlyGET(w);
  expect(lookupsIn(w)).toBe(0); // no lookup was issued without an explicit Look up
  await expectNoLeak(page, w);

  // J5: nothing moved.
  const after = await inventory(api);
  expect(sub(after, "ca")["revision"]).toBe(ca["revision"]);
  expect(sub(after, "uiCert")["revision"]).toBe(ui["revision"]);
  expect(sub(after, "ocsp")["revision"]).toBe(ocsp["revision"]);
  expect(sub(after, "operations")["retained"]).toBe(ops["retained"]);
  await api.dispose();
});

// ── J1 viewer / operator + J2 deep link ────────────────────────────────────

test.describe("J1/J2 viewer and operator", () => {
  test.use({ storageState: EMPTY_STATE });

  test("a viewer deep link returns to the route after sign-in, reloads in place, sees no lookup, only GETs", async ({
    page,
  }) => {
    await page.goto(`${ROUTE}?tab=ca`);
    await expect(page.getByLabel("Username")).toBeVisible();
    const w = watch(page);
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    await expect(page).toHaveURL(new RegExp(`${ROUTE}\\?tab=ca$`));
    await expect(page.getByRole("heading", { name: NAV_LABEL })).toBeVisible();
    const main = page.getByRole("main");
    await expect(
      main.getByRole("tab", { name: "CA Management" }),
    ).toHaveAttribute("aria-selected", "true");
    await expect(main.getByText("Auto-rotation: on")).toBeVisible();
    await page.reload();
    await expect(page).toHaveURL(new RegExp(`${ROUTE}\\?tab=ca$`));
    await expect(page.getByRole("heading", { name: NAV_LABEL })).toBeVisible();
    await main.getByRole("tab", { name: "Certificates" }).click();
    await expect(main.getByText("Node-local").first()).toBeVisible();
    await expectControls(page, VIEWER_CONTROLS);
    await expect(main.getByRole("button", { name: "Look up" })).toHaveCount(0);
    expect(
      await main.locator("input,select,textarea,dialog,form").count(),
    ).toBe(0);
    // GREEN-run harness correction (recorded): the off-canvas "Open
    // navigation" toggle exists only at <=1100px; the RED journey omitted the
    // viewport step every other nav-reachability journey takes. Same
    // reachability assertion, reached through the shared settled-open proof.
    await page.setViewportSize({ width: 640, height: 800 });
    await openNavToFinalState(page);
    await expectNavLinkReachable(page, NAV_LABEL);
    await page.setViewportSize({ width: 1280, height: 800 });
    expectOnlyGET(w);
    expect(lookupsIn(w)).toBe(0);
    await expectNoLeak(page, w);
  });

  test("an operator sees the surface without the lookup", async ({ page }) => {
    await page.goto(ROUTE);
    await login(page, USERS.operator.user, USERS.operator.pass);
    await expect(page).toHaveURL(new RegExp(`${ROUTE}$`));
    // GREEN-run harness correction (recorded): the sign-in gate renders AT the
    // requested URL, so the URL assertion alone does not prove the session
    // exists — wait for the authenticated page before reloading, or the
    // reload can interrupt the sign-in POST (the ordering the deep-link
    // journey already has).
    await expect(page.getByRole("heading", { name: NAV_LABEL })).toBeVisible();
    const w = watch(page);
    await page.reload();
    const main = page.getByRole("main");
    await expect(main.getByText("Node-local").first()).toBeVisible();
    await expectControls(page, VIEWER_CONTROLS);
    expect(lookupsIn(w)).toBe(0);
    expectOnlyGET(w);
  });
});

// ── J4 CERTDEG ─────────────────────────────────────────────────────────────

test.describe("J4 degraded appliance", () => {
  test.use({ storageState: EMPTY_STATE });

  test("admin: load failure class, no Root CA, corrupt pair; every ledger record renders as the server states it", async ({
    page,
  }) => {
    const api = await adminClient(CERTDEG_URL, "10.66.0.3");
    const inv = await inventory(api);
    const ca = sub(inv, "ca");
    expect(ca["loadFailed"]).toBe(true);
    expect(ca["loadFailureClass"]).toBe("bundle_malformed");
    expect(sub(inv, "uiCert")["corrupt"]).toBe(true);

    await page.goto(`${CERTDEG_URL}${ROUTE}`);
    await expect(page.getByLabel("Username")).toBeVisible();
    const w = watch(page);
    await login(page, USERS.admin.user, USERS.admin.pass);
    await expect(page).toHaveURL(new RegExp(`${ROUTE}$`));
    const main = page.getByRole("main");
    await expect(main.getByText("Load failed").first()).toBeVisible();
    await expect(main.getByText("bundle_malformed").first()).toBeVisible();
    await expect(main.getByText("No Root CA is installed")).toBeVisible();
    await expect(
      main.getByText(/did not parse as a matching pair/),
    ).toBeVisible();
    await expect(main.getByText("Not encrypted at rest")).toBeVisible();

    const rec = main.getByTestId("operation-record");
    const look = async (id: string): Promise<void> => {
      await main.getByLabel("Operation ID").fill(id);
      await main.getByRole("button", { name: "Look up" }).click();
    };
    const before = lookupsIn(w);
    await look(SUP_ID);
    await expect(rec.getByText("Outcome unknown — terminal")).toBeVisible();
    await expect(rec.getByText(SUP_WRITER)).toBeVisible();
    await expect(rec.getByText("writer_evidence_superseded")).toBeVisible();
    const supText = (await rec.textContent()) ?? "";
    expect(supText.toLowerCase()).not.toMatch(
      /succeeded|failed|cancelled|canceled|retry|safe to/,
    );
    await look(PEND_ID);
    await expect(rec.getByText("Outcome unknown — recoverable")).toBeVisible();
    await expect(rec.getByText("reconciled_evidence_invalid")).toBeVisible();
    await look(ABT_ID);
    await expect(rec.getByText("Aborted")).toBeVisible();
    await expect(rec.getByText("persist_failed")).toBeVisible();
    await look(CMT_ID);
    await expect(rec.getByText("Committed")).toBeVisible();
    await expect(rec.getByText("ocsp.set")).toBeVisible();
    await look(NONE_ID);
    await expect(rec.getByText("No retained operation record")).toBeVisible();
    expect(lookupsIn(w) - before).toBe(5); // one GET per explicit Look up
    expectOnlyGET(w);
    await expectNoLeak(page, w);

    // The lookup settled nothing new and the server truth is unchanged.
    const sup = await api.get(`/api/ca/operations/${SUP_ID}`);
    const supBody: unknown = await sup.json();
    expect(isRecord(supBody) && supBody["code"]).toBe(
      "writer_evidence_superseded",
    );
    expect(isRecord(supBody) && supBody["supersededBy"]).toBe(SUP_WRITER);
    await api.dispose();
  });

  test("viewer on CERTDEG: the degraded facts render, no lookup exists, no lookup is issued", async ({
    page,
  }) => {
    await page.goto(`${CERTDEG_URL}${ROUTE}`);
    await expect(page.getByLabel("Username")).toBeVisible();
    const w = watch(page);
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    const main = page.getByRole("main");
    await expect(main.getByText("bundle_malformed").first()).toBeVisible();
    await expect(main.getByRole("button", { name: "Look up" })).toHaveCount(0);
    expect(await main.locator("input").count()).toBe(0);
    expect(lookupsIn(w)).toBe(0);
    expectOnlyGET(w);
    await expectNoLeak(page, w);
  });
});

// ── J7 download ────────────────────────────────────────────────────────────

test("J7 the PEM download hands the browser the CA certificate and no private key", async ({
  page,
}) => {
  await page.context().clearCookies();
  await page.goto(`${CERT_URL}${ROUTE}`);
  await login(page, USERS.viewer.user, USERS.viewer.pass);
  const main = page.getByRole("main");
  await expect(main.getByText("Node-local").first()).toBeVisible();
  const w = watch(page);
  const dl = page.waitForEvent("download");
  await main
    .getByRole("button", { name: "Download CA certificate (PEM)" })
    .click();
  const download = await dl;
  expect(download.suggestedFilename()).toBe("culvert-ca.pem");
  const body = readFileSync(await download.path(), "utf8");
  expect(body).toContain("-----BEGIN CERTIFICATE-----");
  expect(body).not.toContain("PRIVATE KEY");
  expectOnlyGET(w);
});
