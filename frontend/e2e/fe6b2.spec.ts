// FE-6B.2 — real-binary browser journeys for the Certificates & CA WRITE
// surfaces, committed on the frozen FE-6B.1 baseline 212b1617 BEFORE any
// product change (every write journey fails there on the absent control;
// W1 is a CONTROL that already passes). The harness gains a TENTH
// appliance, CERTW: a passphrase-sealed persisted Root CA, a persisted UI
// pair A that its admin listener really serves over TLS (no -ui-no-tls),
// OCSP at its default. Pair B, an importable CA and a mismatched key are
// generated beside it; private keys reach the browser only through the OPEN
// ceremony's textareas and the request body.
//
//   W1 viewer / operator: no mutation control.
//   W2 rotate: server challenge (fingerprint being replaced, expiry), typed
//      ROTATE, confirm; the API's CA revision moves; the ledger record is
//      committed under the browser's operationId.
//   W3 import: dry-run review → Import; the live CA is the reviewed
//      candidate; a mismatched key is a bounded candidate_invalid refusal.
//   W4 replace the UI pair with B: persisted B, listener still serves A (a
//      REAL TLS handshake), "Activation requires a restart".
//   W5 delete (T3, typed first 8 fingerprint bytes): persisted pair gone,
//      listener still serves A.
//   W6 OCSP: the T2 ceremony states desired/runtime/coverage; Apply; the
//      durable desired posture is admin-owned.
//   W7 a LOST response (the server executed, the browser never saw the
//      answer): ceremony closed, marker retained, mutations blocked; reload;
//      Recover ⇒ committed ⇒ cleared.
//   W8 a request that NEVER reached the appliance: Recover ⇒ never recorded
//      ⇒ Re-send of the SAME operation lands.
//   W9 leak sweep across every journey: no private key, no passphrase, no
//      challenge in the DOM, the URL, storage or any response body; the
//      marker carries only its allowlisted fields.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page } from "@playwright/test";
import {
  CA_PASSPHRASE_CANARY,
  CERTW_DIR,
  CERTW_URL,
  EMPTY_STATE,
  USERS,
} from "./fixtures";

const ROUTE = "/app/security/certificates";
const SUBJECT_A = "ui-fe6b2-a.e2e";
const SUBJECT_B = "ui-fe6b2-b.e2e";
const IMPORT_SUBJECT = "FE-6B.2 Import CA";
const MARKER_KEY = "culvert.cert.operation-recovery.v1";
const MARKER_FIELDS = [
  "action",
  "candidate",
  "fence",
  "operationId",
  "previousFingerprint",
  "startedAt",
  "subject",
  "version",
];

const VIEWER_CONTROLS: readonly string[] = [
  "Certificates",
  "CA Management",
  "Refresh",
  "Download CA certificate (PEM)",
];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function sub(v: Record<string, unknown>, k: string): Record<string, unknown> {
  const s = v[k];
  if (!isRecord(s)) throw new Error(`bad ${k}`);
  return s;
}
function pem(name: string): string {
  return readFileSync(join(CERTW_DIR, name), "utf8");
}

async function adminClient(xff: string): Promise<APIRequestContext> {
  const ctx = await request.newContext({
    baseURL: CERTW_URL,
    ignoreHTTPSErrors: true,
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
async function lookup(
  ctx: APIRequestContext,
  id: string,
): Promise<Record<string, unknown>> {
  const r = await ctx.get(`/api/ca/operations/${id}`);
  expect(r.ok(), await r.text()).toBe(true);
  const v: unknown = await r.json();
  if (!isRecord(v)) throw new Error("bad record");
  return v;
}

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}
async function signInAdmin(page: Page): Promise<void> {
  const resp = await page.goto(`${CERTW_URL}${ROUTE}`);
  expect(resp).not.toBeNull();
  await expect(page.getByLabel("Username")).toBeVisible();
  await login(page, USERS.admin.user, USERS.admin.pass);
  await expect(
    page.getByRole("heading", { name: "Certificates & CA" }),
  ).toBeVisible();
  await expect(
    page.getByRole("main").getByText("Node-local").first(),
  ).toBeVisible();
}
async function servedSubject(page: Page): Promise<string> {
  const resp = await page.goto(`${CERTW_URL}${ROUTE}`);
  const tls = await resp?.securityDetails();
  return tls?.subjectName ?? "";
}

interface Watch {
  mutations: Array<{ method: string; url: string }>;
  bodies: string[];
}
function watch(page: Page): Watch {
  const w: Watch = { mutations: [], bodies: [] };
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (
      u.pathname.startsWith("/api/") &&
      r.method() !== "GET" &&
      u.pathname !== "/api/auth/login"
    )
      w.mutations.push({ method: r.method(), url: r.url() });
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
const NEEDLES = [CA_PASSPHRASE_CANARY, "PRIVATE KEY", "x509:", "no such file"];
async function expectNoLeak(
  page: Page,
  w: Watch,
  extra: readonly string[] = [],
): Promise<void> {
  const dom = await page.evaluate(() => document.documentElement.outerHTML);
  const url = page.url();
  const storage = await storageDump(page);
  for (const needle of [...NEEDLES, ...extra]) {
    expect(dom, `DOM carries ${needle}`).not.toContain(needle);
    expect(url, `URL carries ${needle}`).not.toContain(needle);
    expect(storage, `storage carries ${needle}`).not.toContain(needle);
    for (const b of w.bodies)
      expect(b, `response carries ${needle}`).not.toContain(needle);
  }
  for (const m of w.mutations) {
    expect(m.url, "a URL carries key material").not.toContain("PRIVATE");
    expect(m.url, "a URL carries a challenge").not.toMatch(
      /challenge=[0-9a-f]{64}/,
    );
  }
}
/** The operationId of the first IDENTIFIED mutation on `path` (a dry run
 * carries none by contract and is skipped). */
function opIdOf(w: Watch, path: string): string {
  for (const x of w.mutations) {
    const u = new URL(x.url);
    if (u.pathname !== path) continue;
    const id = u.searchParams.get("operationId");
    if (id !== null) return id;
  }
  throw new Error(`no identified mutation on ${path}`);
}

test.describe("FE-6B.2 CERTW write journeys", () => {
  test.use({ storageState: EMPTY_STATE, ignoreHTTPSErrors: true });

  test("W1 viewer and operator: no mutation control", async ({ page }) => {
    for (const u of [USERS.viewer, USERS.operator]) {
      await page.context().clearCookies();
      await page.goto(`${CERTW_URL}${ROUTE}`);
      await expect(page.getByLabel("Username")).toBeVisible();
      await login(page, u.user, u.pass);
      const main = page.getByRole("main");
      await expect(main.getByText("Node-local").first()).toBeVisible();
      const buttons = await main.getByRole("button").allTextContents();
      expect(buttons.length).toBeGreaterThan(0);
      expect(buttons.every((b) => VIEWER_CONTROLS.includes(b.trim()))).toBe(
        true,
      );
      await expect(
        main.getByText("Unresolved certificate operation"),
      ).toHaveCount(0);
    }
  });

  test("W2 rotate through the bound challenge ceremony", async ({ page }) => {
    const api = await adminClient("10.68.0.2");
    const before = await inventory(api);
    const rev0 = String(sub(before, "ca")["revision"]);
    const fp0 = String(sub(before, "ca")["fingerprint"]);
    await page.context().clearCookies();
    await signInAdmin(page);
    const w = watch(page);
    const main = page.getByRole("main");
    await main.getByRole("button", { name: "Rotate Root CA…" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByText(fp0)).toBeVisible();
    await dialog.getByRole("button", { name: "Request challenge" }).click();
    await expect(dialog.getByText("cannot be undone")).toBeVisible();
    await expect(dialog.getByText(/Expires at/)).toBeVisible();
    const confirm = dialog.getByRole("button", { name: "Rotate", exact: true });
    await expect(confirm).toBeDisabled();
    await dialog.getByLabel("Type ROTATE to confirm").fill("ROTATE");
    await expect(confirm).toBeEnabled();
    await confirm.click();
    await expect(main.getByText("Root CA rotated")).toBeVisible();
    const after = await inventory(api);
    const rev1 = String(sub(after, "ca")["revision"]);
    expect(rev1).not.toBe(rev0);
    await expect(main.getByText(rev1, { exact: true }).first()).toBeVisible();
    const opId = opIdOf(w, "/api/ca/rotate");
    const rec = await lookup(api, opId);
    expect(rec["state"]).toBe("committed");
    expect(rec["action"]).toBe("ca.rotate");
    expect(rec["fence"]).toBe(rev0);
    expect(rec["committedRevision"]).toBe(rev1);
    expect(await storageDump(page)).not.toContain(MARKER_KEY);
    await expectNoLeak(page, w);
    await api.dispose();
  });

  test("W3 import: dry-run review, commit; a mismatched key is refused", async ({
    page,
  }) => {
    const api = await adminClient("10.68.0.3");
    await page.context().clearCookies();
    await signInAdmin(page);
    const w = watch(page);
    const main = page.getByRole("main");
    // Refusal first: the wrong key changes nothing.
    await main.getByRole("button", { name: "Import CA…" }).click();
    let dialog = page.getByRole("dialog");
    await dialog.getByLabel("CA certificate (PEM)").fill(pem("import-ca.crt"));
    await dialog.getByLabel("CA private key (PEM)").fill(pem("mismatch.key"));
    await dialog.getByRole("button", { name: "Review candidate" }).click();
    await expect(dialog.getByText("key_mismatch")).toBeVisible();
    await expect(
      dialog.getByRole("button", { name: "Import", exact: true }),
    ).toHaveCount(0);
    await dialog.getByRole("button", { name: "Cancel" }).click();
    const mid = await inventory(api);
    // The valid pair: reviewed facts, then the commit.
    await main.getByRole("button", { name: "Import CA…" }).click();
    dialog = page.getByRole("dialog");
    await dialog.getByLabel("CA certificate (PEM)").fill(pem("import-ca.crt"));
    await dialog.getByLabel("CA private key (PEM)").fill(pem("import-ca.key"));
    await dialog.getByRole("button", { name: "Review candidate" }).click();
    await expect(dialog.getByText(IMPORT_SUBJECT).first()).toBeVisible();
    await expect(
      dialog.getByText(String(sub(mid, "ca")["revision"])),
    ).toBeVisible();
    await dialog.getByRole("button", { name: "Import", exact: true }).click();
    await expect(main.getByText("Root CA imported")).toBeVisible();
    const after = await inventory(api);
    expect(sub(after, "ca")["subject"]).toBe(IMPORT_SUBJECT);
    await expect(
      main.getByText(String(sub(after, "ca")["fingerprint"])).first(),
    ).toBeVisible();
    const rec = await lookup(api, opIdOf(w, "/api/certs/upload"));
    expect(rec["state"]).toBe("committed");
    expect(rec["action"]).toBe("ca.import");
    expect(rec["fence"]).toBe(sub(mid, "ca")["revision"]);
    await expectNoLeak(page, w, ["CERTIFICATE-----"]);
    await api.dispose();
  });

  test("W4 replace the UI pair: persisted B, listener still serves A over real TLS", async ({
    page,
  }) => {
    const api = await adminClient("10.68.0.4");
    const before = await inventory(api);
    expect(sub(before, "uiCert")["subject"]).toBe(SUBJECT_A);
    expect(sub(sub(before, "listener"), "servedCertificate")["subject"]).toBe(
      SUBJECT_A,
    );
    await page.context().clearCookies();
    expect(await servedSubject(page)).toBe(SUBJECT_A);
    await login(page, USERS.admin.user, USERS.admin.pass);
    const main = page.getByRole("main");
    await expect(main.getByText("Node-local").first()).toBeVisible();
    const w = watch(page);
    await main.getByRole("button", { name: "Replace UI certificate…" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Certificate (PEM)").fill(pem("ui-b.crt"));
    await dialog.getByLabel("Private key (PEM)").fill(pem("ui-b.key"));
    await dialog.getByRole("button", { name: "Review candidate" }).click();
    await expect(dialog.getByText(SUBJECT_B).first()).toBeVisible();
    await expect(dialog.getByText(/restart/).first()).toBeVisible();
    await dialog.getByRole("button", { name: "Replace", exact: true }).click();
    await expect(main.getByText("UI certificate replaced")).toBeVisible();
    await expect(main.getByText("Activation requires a restart")).toBeVisible();
    await expect(
      main.getByText("Active on the running listener", { exact: true }),
    ).toHaveCount(0);
    const after = await inventory(api);
    expect(sub(after, "uiCert")["subject"]).toBe(SUBJECT_B);
    expect(sub(after, "uiCert")["active"]).toBe(false);
    expect(sub(sub(after, "listener"), "servedCertificate")["subject"]).toBe(
      SUBJECT_A,
    );
    const rec = await lookup(api, opIdOf(w, "/api/certs/upload"));
    expect(rec["state"]).toBe("committed");
    expect(rec["action"]).toBe("cert.ui.replace");
    expect(rec["fence"]).toBe(sub(before, "uiCert")["revision"]);
    await expectNoLeak(page, w, ["CERTIFICATE-----"]);
    expect(await servedSubject(page)).toBe(SUBJECT_A);
    await api.dispose();
  });

  test("W5 delete the UI pair (T3): the listener keeps serving A", async ({
    page,
  }) => {
    const api = await adminClient("10.68.0.5");
    const before = await inventory(api);
    const fp = String(sub(before, "uiCert")["fingerprint"]);
    const rev = String(sub(before, "uiCert")["revision"]);
    await page.context().clearCookies();
    await signInAdmin(page);
    const w = watch(page);
    const main = page.getByRole("main");
    await main.getByRole("button", { name: "Delete UI certificate…" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByText(fp)).toBeVisible();
    await expect(dialog.getByText(/keeps serving/)).toBeVisible();
    const word = fp.slice(0, 23);
    const confirm = dialog.getByRole("button", { name: "Delete", exact: true });
    await expect(confirm).toBeDisabled();
    await dialog.getByLabel(`Type ${word} to confirm`).fill(word);
    await confirm.click();
    await expect(main.getByText("UI certificate deleted")).toBeVisible();
    const after = await inventory(api);
    expect(sub(after, "uiCert")["pairState"]).toBe("absent");
    expect(sub(sub(after, "listener"), "servedCertificate")["subject"]).toBe(
      SUBJECT_A,
    );
    const del = w.mutations.find((m) => m.method === "DELETE");
    expect(
      new URL(del?.url ?? "http://x").searchParams.get("uiCertRevision"),
    ).toBe(rev);
    const rec = await lookup(api, opIdOf(w, "/api/certs/ui"));
    expect(rec["state"]).toBe("committed");
    expect(rec["action"]).toBe("cert.ui.delete");
    await expectNoLeak(page, w);
    expect(await servedSubject(page)).toBe(SUBJECT_A);
    await api.dispose();
  });

  test("W6 OCSP: desired/runtime/coverage stated; the durable set is admin-owned", async ({
    page,
  }) => {
    const api = await adminClient("10.68.0.6");
    await page.context().clearCookies();
    await signInAdmin(page);
    const w = watch(page);
    const main = page.getByRole("main");
    await main.getByRole("button", { name: "Set OCSP posture…" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByText("Desired: Disabled")).toBeVisible();
    await expect(dialog.getByText("Runtime: Disabled")).toBeVisible();
    await expect(dialog.getByText(/not consulted/)).toBeVisible();
    await dialog.getByLabel("Enable OCSP revocation checking").check();
    await dialog.getByRole("button", { name: "Apply" }).click();
    await expect(main.getByText("OCSP posture set")).toBeVisible();
    const after = await inventory(api);
    expect(sub(sub(after, "ocsp"), "desired")).toEqual({
      enabled: true,
      source: "admin",
    });
    expect(sub(after, "ocsp")["durable"]).toBe(true);
    const rec = await lookup(api, opIdOf(w, "/api/ocsp"));
    expect(rec["state"]).toBe("committed");
    expect(rec["action"]).toBe("ocsp.set");
    await expectNoLeak(page, w);
    await api.dispose();
  });

  test("W7 a lost response: marker retained, reload, Recover ⇒ committed", async ({
    page,
  }) => {
    const api = await adminClient("10.68.0.7");
    await page.context().clearCookies();
    await signInAdmin(page);
    const w = watch(page);
    const main = page.getByRole("main");
    // The appliance executes the set; the browser never sees the answer.
    await page.route("**/api/ocsp?*", async (route) => {
      if (route.request().method() !== "POST") {
        await route.continue();
        return;
      }
      await route.fetch();
      await route.abort("failed");
    });
    await main.getByRole("button", { name: "Set OCSP posture…" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Enable OCSP revocation checking").uncheck();
    await dialog.getByRole("button", { name: "Apply" }).click();
    await expect(
      main.getByText("Unresolved certificate operation"),
    ).toBeVisible();
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(
      main.getByRole("button", { name: "Rotate Root CA…" }),
    ).toBeDisabled();
    await expect(
      main.getByRole("button", { name: "Set OCSP posture…" }),
    ).toBeDisabled();
    const opId = opIdOf(w, "/api/ocsp");
    const storage = await storageDump(page);
    expect(storage).toContain(MARKER_KEY);
    const rawMarker = storage
      .split("\n")
      .find((l) => l.startsWith(`${MARKER_KEY}=`));
    const parsed: unknown = JSON.parse(
      (rawMarker ?? "").slice(MARKER_KEY.length + 1),
    );
    if (!isRecord(parsed)) throw new Error("bad marker");
    expect(Object.keys(parsed).sort()).toEqual([...MARKER_FIELDS].sort());
    expect(parsed["operationId"]).toBe(opId);
    expect(parsed["action"]).toBe("ocsp");
    expect(parsed["candidate"]).toBe("disabled");
    expect(parsed["subject"]).toBe(USERS.admin.user);
    // The server did commit it.
    const mid = await inventory(api);
    expect(sub(sub(mid, "ocsp"), "desired")["enabled"]).toBe(false);
    await page.unroute("**/api/ocsp?*");
    await page.reload();
    await expect(
      main.getByText("Unresolved certificate operation"),
    ).toBeVisible();
    await expect(main.getByText(opId)).toBeVisible();
    await main.getByRole("button", { name: "Recover" }).click();
    await expect(main.getByText(/committed on the appliance/)).toBeVisible();
    expect(await storageDump(page)).not.toContain(MARKER_KEY);
    await expect(
      main.getByRole("button", { name: "Rotate Root CA…" }),
    ).toBeEnabled();
    await expect(
      main.getByText("Unresolved certificate operation"),
    ).toHaveCount(0);
    await expectNoLeak(page, w);
    await api.dispose();
  });

  test("W8 a request that never reached the appliance: Recover ⇒ never recorded ⇒ Re-send lands", async ({
    page,
  }) => {
    const api = await adminClient("10.68.0.8");
    await page.context().clearCookies();
    await signInAdmin(page);
    const w = watch(page);
    const main = page.getByRole("main");
    await page.route("**/api/ocsp?*", async (route) => {
      if (route.request().method() !== "POST") {
        await route.continue();
        return;
      }
      await route.abort("failed"); // never sent
    });
    await main.getByRole("button", { name: "Set OCSP posture…" }).click();
    let dialog = page.getByRole("dialog");
    await dialog.getByLabel("Enable OCSP revocation checking").check();
    await dialog.getByRole("button", { name: "Apply" }).click();
    await expect(
      main.getByText("Unresolved certificate operation"),
    ).toBeVisible();
    const opId = opIdOf(w, "/api/ocsp");
    await page.unroute("**/api/ocsp?*");
    await main.getByRole("button", { name: "Recover" }).click();
    await expect(main.getByText(/never recorded/)).toBeVisible();
    await main.getByRole("button", { name: "Re-send" }).click();
    dialog = page.getByRole("dialog");
    await expect(dialog.getByText(opId)).toBeVisible();
    await dialog.getByRole("button", { name: "Apply" }).click();
    await expect(main.getByText("OCSP posture set")).toBeVisible();
    const resent = w.mutations.filter(
      (m) => new URL(m.url).pathname === "/api/ocsp",
    );
    expect(resent).toHaveLength(2);
    expect(
      new URL(resent[1]?.url ?? "http://x").searchParams.get("operationId"),
    ).toBe(opId);
    const after = await inventory(api);
    expect(sub(sub(after, "ocsp"), "desired")["enabled"]).toBe(true);
    const rec = await lookup(api, opId);
    expect(rec["state"]).toBe("committed");
    expect(await storageDump(page)).not.toContain(MARKER_KEY);
    await expectNoLeak(page, w);
    await api.dispose();
  });
});
