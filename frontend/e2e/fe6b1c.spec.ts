// FE-6B.1 CORRECTION ROUND — real-binary journeys, committed on the reviewed
// candidate 935891f4 BEFORE any product change. The harness gains a NINTH
// appliance, CERTTLS, which boots with a persisted UI pair A already on disk
// and WITHOUT -ui-no-tls, so its admin listener actually serves A over TLS —
// the only way to compare the appliance's published served identity against
// the certificate a real TLS client sees.
//
//   T1 CERTTLS: the API publishes listener posture tls_custom with the served
//      identity A (= the certificate Playwright's TLS layer observed);
//      uploading pair B WITHOUT a restart leaves the listener on A, the
//      persisted identity on B and `active` FALSE; the page names A as served,
//      B as persisted, says a restart activates B and never claims "Active on
//      the running listener"; deleting the persisted pair leaves the listener
//      on A ("no longer persisted"). Only GETs from the page; nothing leaks.
//   T2 CERT (-ui-no-tls, pair persisted after boot): posture plain_http, the
//      page says plain HTTP and the pair is not in use; no activation claim.
//   T3 both reads carry the same evidence object.
//
// No retries, no enlarged timeouts, no skips.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page } from "@playwright/test";
import {
  CERTTLS_UI_PAIR_DIR,
  CERTTLS_URL,
  CERT_URL,
  EMPTY_STATE,
  USERS,
} from "./fixtures";

const ROUTE = "/app/security/certificates";
const OP_B = "6b1c0000-fe6b-4e2e-9f00-00000000e00b";
const OP_DEL = "6b1c0000-fe6b-4e2e-9f00-00000000e0de";
const SUBJECT_A = "ui-fe6b1c-a.e2e";
const SUBJECT_B = "ui-fe6b1c-b.e2e";

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function sub(v: Record<string, unknown>, k: string): Record<string, unknown> {
  const s = v[k];
  if (!isRecord(s)) throw new Error(`bad ${k}`);
  return s;
}

async function adminClient(
  base: string,
  xff: string,
): Promise<APIRequestContext> {
  const ctx = await request.newContext({
    baseURL: base,
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

async function network(
  ctx: APIRequestContext,
): Promise<Record<string, unknown>> {
  const r = await ctx.get("/api/settings/network");
  expect(r.ok(), await r.text()).toBe(true);
  const v: unknown = await r.json();
  if (!isRecord(v)) throw new Error("bad network settings");
  return v;
}

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}

function nonGET(page: Page): string[] {
  const out: string[] = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (
      u.pathname.startsWith("/api/") &&
      r.method() !== "GET" &&
      u.pathname !== "/api/auth/login"
    )
      out.push(`${r.method()} ${u.pathname}`);
  });
  return out;
}

test.describe("T1 CERTTLS — the served identity is real TLS evidence", () => {
  test.use({ storageState: EMPTY_STATE, ignoreHTTPSErrors: true });

  test("A served / B persisted without restart, then delete: the listener stays on A", async ({
    page,
  }) => {
    const api = await adminClient(CERTTLS_URL, "10.67.0.1");
    let inv = await inventory(api);
    let listener = sub(inv, "listener");
    expect(listener["state"]).toBe("serving");
    expect(listener["posture"]).toBe("tls_custom");
    const servedA = sub(listener, "servedCertificate");
    expect(servedA["subject"]).toBe(SUBJECT_A);
    expect(sub(inv, "uiCert")["subject"]).toBe(SUBJECT_A);
    expect(sub(inv, "uiCert")["active"]).toBe(true);
    expect(listener["servesPersistedPair"]).toBe(true);

    // Replace the persisted pair with B — no restart.
    const rev = String(sub(inv, "uiCert")["revision"]);
    const qs = new URLSearchParams({
      target: "ui",
      operationId: OP_B,
      uiCertRevision: rev,
    });
    const up = await api.post(`/api/certs/upload?${qs.toString()}`, {
      multipart: {
        target: "ui",
        cert: {
          name: "ui-b.crt",
          mimeType: "application/x-pem-file",
          buffer: readFileSync(join(CERTTLS_UI_PAIR_DIR, "ui-b.crt")),
        },
        key: {
          name: "ui-b.key",
          mimeType: "application/x-pem-file",
          buffer: readFileSync(join(CERTTLS_UI_PAIR_DIR, "ui-b.key")),
        },
      },
    });
    expect(up.ok(), await up.text()).toBe(true);

    inv = await inventory(api);
    listener = sub(inv, "listener");
    expect(sub(inv, "uiCert")["subject"]).toBe(SUBJECT_B);
    expect(sub(inv, "uiCert")["active"]).toBe(false);
    expect(sub(listener, "servedCertificate")["subject"]).toBe(SUBJECT_A);
    expect(sub(listener, "servedCertificate")["fingerprint"]).toBe(
      servedA["fingerprint"],
    );
    expect(listener["servesPersistedPair"]).toBe(false);
    const net = await network(api);
    expect(net["ui_custom_cert_active"]).toBe(false);
    expect(net["ui_listener"]).toEqual(listener); // T3

    // The browser: sign in over the REAL TLS listener and read what it serves.
    const mutations = nonGET(page);
    const resp = await page.goto(`${CERTTLS_URL}${ROUTE}`);
    expect(resp).not.toBeNull();
    const tls = await resp?.securityDetails();
    expect(tls?.subjectName, "the TLS peer is pair A").toBe(SUBJECT_A);
    await expect(page.getByLabel("Username")).toBeVisible();
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    const main = page.getByRole("main");
    await expect(main.getByText("Complete pair persisted")).toBeVisible();
    await expect(main.getByText(SUBJECT_B).first()).toBeVisible();
    await expect(
      main.getByText(String(servedA["fingerprint"]), { exact: true }),
    ).toBeVisible();
    await expect(main.getByText(/Listener serves/)).toBeVisible();
    await expect(main.getByText("Activation requires a restart")).toBeVisible();
    await expect(
      main.getByText("Active on the running listener", { exact: true }),
    ).toHaveCount(0);
    expect(mutations).toEqual([]);

    // Delete the persisted pair while A is still served.
    const rev2 = String(sub(inv, "uiCert")["revision"]);
    const del = await api.delete(
      `/api/certs/ui?operationId=${OP_DEL}&uiCertRevision=${encodeURIComponent(rev2)}`,
    );
    expect(del.ok(), await del.text()).toBe(true);
    inv = await inventory(api);
    expect(sub(inv, "uiCert")["pairState"]).toBe("absent");
    expect(sub(inv, "uiCert")["active"]).toBe(false);
    expect(sub(sub(inv, "listener"), "servedCertificate")["subject"]).toBe(
      SUBJECT_A,
    );
    await main.getByRole("button", { name: "Refresh" }).click();
    await expect(main.getByText(/no longer persisted/)).toBeVisible();
    await expect(
      main.getByText("Active on the running listener", { exact: true }),
    ).toHaveCount(0);
    await api.dispose();
  });
});

test.describe("T2 CERT (-ui-no-tls) — plain HTTP is stated, never activation", () => {
  test.use({ storageState: EMPTY_STATE });

  test("the persisted pair is not in use on a plain-HTTP listener", async ({
    page,
  }) => {
    const api = await adminClient(CERT_URL, "10.67.0.2");
    const inv = await inventory(api);
    const listener = sub(inv, "listener");
    expect(listener["state"]).toBe("serving");
    expect(listener["posture"]).toBe("plain_http");
    expect(listener["servedCertificate"]).toBeUndefined();
    expect(sub(inv, "uiCert")["active"]).toBe(false);
    expect((await network(api))["ui_listener"]).toEqual(listener);
    await api.dispose();

    await page.goto(`${CERT_URL}${ROUTE}`);
    await expect(page.getByLabel("Username")).toBeVisible();
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    const main = page.getByRole("main");
    await expect(main.getByText(/plain HTTP/).first()).toBeVisible();
    await expect(
      main.getByText("Active on the running listener", { exact: true }),
    ).toHaveCount(0);
  });
});
