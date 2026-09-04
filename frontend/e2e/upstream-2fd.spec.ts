// 2F-D real-binary browser leak sweep: the LEGACY Upstream Proxies panel
// (static/index.html — the shipped operator surface for parent proxies; the
// new SPA has no upstream route until 2F-E) over the actual CULVERT binary
// on the AUTH appliance.
//
// Directive §7 (complete leak sweep, browser half): a credential is sealed
// through the real T2 endpoint with a CANARY password, the admin exercises
// the panel (list, Health Check, export), and the spec proves that neither
// the canary nor the sealed ciphertext ever reaches the browser — in any
// response body captured on the wire, any request URL, localStorage,
// sessionStorage, or the page's own DOM. The ciphertext needle is read from
// the appliance's live admin_settings.json when the harness runs on the
// same host (the ONLY place it legitimately exists); when that file is not
// reachable the ciphertext half is reported as skipped, never faked.
//
// Everything mutated is restored in a finally block through the real
// Tier-3 clear + delete endpoints (with revision fencing), so the shared
// appliance ends the spec with no trace of the fixture entry.
import { existsSync, readFileSync } from "node:fs";
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page, Response } from "@playwright/test";
import { AUTH_URL, USERS } from "./fixtures";

test.use({ extraHTTPHeaders: { "X-Forwarded-For": "198.51.100.77" } });

const CANARY_PW = "Canary-Browser-PW-2fd-4b9e";
const HOST = "parent-2fd.test";
const PORT = 3128;
const SETTINGS = "/data/admin_settings.json";

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

async function newAdminClient(): Promise<APIRequestContext> {
  const ctx = await request.newContext({
    baseURL: AUTH_URL,
    extraHTTPHeaders: { "X-Forwarded-For": "198.51.100.78" },
  });
  const login = await ctx.post("/api/auth/login", {
    data: { user: USERS.admin.user, pass: USERS.admin.pass },
  });
  expect(login.ok()).toBe(true);
  return ctx;
}

async function poolRevision(api: APIRequestContext): Promise<number> {
  const v: unknown = await (await api.get("/api/upstream")).json();
  if (!isRecord(v) || typeof v["revision"] !== "number") {
    throw new Error("bad /api/upstream envelope");
  }
  return v["revision"];
}

async function findEntry(
  api: APIRequestContext,
  host: string,
): Promise<{ id: string; revision: number; credentialState: string } | null> {
  const v: unknown = await (await api.get("/api/upstream")).json();
  if (!isRecord(v) || !Array.isArray(v["entries"])) return null;
  for (const e of v["entries"]) {
    if (isRecord(e) && e["host"] === host) {
      return {
        id: String(e["id"]),
        revision: Number(e["revision"]),
        credentialState: String(e["credentialState"]),
      };
    }
  }
  return null;
}

/** Ciphertexts sealed for HOST on the appliance disk (same-host harness). */
function ciphertextsOnDisk(): string[] | null {
  if (!existsSync(SETTINGS)) return null;
  try {
    const s: unknown = JSON.parse(readFileSync(SETTINGS, "utf8"));
    if (!isRecord(s)) return null;
    const doc = s["upstream_proxies_v2"];
    if (!isRecord(doc) || !Array.isArray(doc["entries"])) return [];
    const out: string[] = [];
    for (const e of doc["entries"]) {
      if (!isRecord(e) || e["host"] !== HOST) continue;
      const c = e["credential"];
      if (isRecord(c) && typeof c["ciphertext"] === "string") {
        out.push(c["ciphertext"]);
      }
    }
    return out;
  } catch {
    return null;
  }
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

test.describe("2F-D — legacy Upstream Proxies panel never receives credential material", () => {
  test("canary password + sealed ciphertext are absent from every browser sink", async ({ page }) => {
    const api = await newAdminClient();
    // Stale fixture from an aborted run — remove it first so the spec is idempotent.
    const stale = await findEntry(api, HOST);
    if (stale) {
      if (stale.credentialState !== "none") {
        await api.post(`/api/upstream/entries/${stale.id}/credential`, {
          data: { action: "clear", confirm: stale.id, revision: stale.revision },
        });
      }
      const again = await findEntry(api, HOST);
      if (again) {
        await api.delete(`/api/upstream/entries/${again.id}?revision=${again.revision}`);
      }
    }

    const bodies: Array<{ url: string; body: string }> = [];
    const urls: string[] = [];
    page.on("request", (r) => urls.push(r.url()));
    page.on("response", (r: Response) => {
      const url = r.url();
      if (!url.startsWith(AUTH_URL)) return;
      void r
        .text()
        .then((t) => bodies.push({ url, body: t }))
        .catch(() => undefined);
    });

    let id = "";
    try {
      // The entry and its credential are created through the panel's own
      // same-origin fetch path (page context ⇒ browser Origin ⇒ real CSRF
      // rule), exactly as the legacy UI's api() helper does.
      await page.goto("/");
      const rev = await poolRevision(api);
      const created: unknown = await page.evaluate(
        async ([host, port, revision]) => {
          const r = await fetch("/api/upstream/entries", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scheme: "http", host, port, username: "svc", revision }),
          });
          const body: unknown = await r.json();
          return { status: r.status, body };
        },
        [HOST, PORT, rev] as const,
      );
      expect(isRecord(created) && created["status"]).toBe(201);
      const entry = isRecord(created) && isRecord(created["body"]) ? created["body"]["entry"] : null;
      if (!isRecord(entry)) throw new Error("no entry in create response");
      id = String(entry["id"]);
      const sealed: unknown = await page.evaluate(
        async ([entryID, password, revision]) => {
          const r = await fetch(`/api/upstream/entries/${entryID}/credential`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: "replace", password, revision }),
          });
          const body: unknown = await r.json();
          return { status: r.status, body };
        },
        [id, CANARY_PW, Number(entry["revision"])] as const,
      );
      expect(isRecord(sealed) && sealed["status"]).toBe(200);
      const after = await findEntry(api, HOST);
      expect(after?.credentialState).toBe("configured");

      // The sealed record now exists on the appliance disk — the one place
      // it may. Read the needle from there (same-host harness only).
      const cts = ciphertextsOnDisk();
      if (cts !== null) expect(cts.length).toBe(1);

      // Exercise the panel: navigate, read the row, run the admin-only
      // manual probe, and pull the export the operator would download.
      await page.click('.nav-item[data-view="upstream"]');
      const row = page.locator("#upstream-tbody tr", { hasText: HOST });
      await expect(row).toBeVisible();
      await expect(row).toContainText("configured");
      const healthResp = page.waitForResponse(
        (r) => r.url().includes("/api/upstream/health") && r.request().method() === "POST",
      );
      await page.click('[data-click="upstreamHealthCheck"]');
      const health = await healthResp;
      expect([200, 429]).toContain(health.status());
      const exportText = await page.evaluate(async () => {
        const r = await fetch("/api/config/export?section=upstream");
        return r.text();
      });
      expect(exportText).toContain('"upstream_credentials": "omitted"');
      expect(exportText).not.toContain("xxxxx");
      await page.evaluate(async () => {
        await fetch("/api/audit");
        await fetch("/api/upstream");
      });
      // Let every in-flight body settle before sweeping.
      await page.waitForLoadState("networkidle");

      const needles: Array<{ label: string; value: string }> = [
        { label: "canary password", value: CANARY_PW },
        ...(cts ?? []).map((c) => ({ label: "sealed ciphertext", value: c })),
      ];
      const dom = await page.content();
      const storage = await storageDump(page);
      const leaks: string[] = [];
      for (const n of needles) {
        for (const b of bodies) {
          if (b.body.includes(n.value)) leaks.push(`${n.label} in response body of ${b.url}`);
        }
        for (const u of urls) {
          if (u.includes(n.value)) leaks.push(`${n.label} in request URL ${u}`);
        }
        if (dom.includes(n.value)) leaks.push(`${n.label} in DOM`);
        if (storage.includes(n.value)) leaks.push(`${n.label} in web storage`);
        if (page.url().includes(n.value)) leaks.push(`${n.label} in page URL`);
      }
      expect(leaks).toEqual([]);
      // The sweep must have actually looked at the sinks that carry the entry.
      expect(bodies.some((b) => b.url.includes("/api/upstream") && b.body.includes(HOST))).toBe(true);
      expect(bodies.some((b) => b.url.includes("/api/config/export"))).toBe(true);
      // The credential write itself was a same-origin browser request whose
      // RESPONSE carries no material either (the request body is the only
      // legitimate carrier and is not a sink).
      const credResp = bodies.find((b) => b.url.includes(`/entries/${id}/credential`));
      expect(credResp?.body ?? "").not.toContain(CANARY_PW);
      if (cts === null) {
        test.info().annotations.push({
          type: "note",
          description: "ciphertext needle skipped: /data/admin_settings.json not reachable from the runner",
        });
      }
    } finally {
      // Restore: Tier-3 clear (typed confirm) then delete, both fenced.
      const cur = await findEntry(api, HOST);
      if (cur) {
        if (cur.credentialState !== "none") {
          const clr = await api.post(`/api/upstream/entries/${cur.id}/credential`, {
            data: { action: "clear", confirm: cur.id, revision: cur.revision },
          });
          expect(clr.status()).toBe(200);
        }
        const fresh = await findEntry(api, HOST);
        if (fresh) {
          const del = await api.delete(`/api/upstream/entries/${fresh.id}?revision=${fresh.revision}`);
          expect(del.status()).toBe(200);
        }
      }
      expect(await findEntry(api, HOST)).toBeNull();
      await api.dispose();
    }
  });
});
