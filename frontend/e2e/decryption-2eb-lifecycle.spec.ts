// 2E-B FINAL lifecycle closure — real-binary browser proof that a T3
// rotation's recovery identity survives the CLIENT lifecycle (directive §8):
//
//   1. A rotation is dispatched under a DETERMINISTIC unknown-response seam
//      (route interception executes the request against the real appliance,
//      then drops the response before the page sees it), the page is
//      RELOADED, and the SAME pending operation identity is recovered from
//      the durable sessionStorage marker; authoritative receipt resolution
//      classifies it LANDED exactly once, and ZERO second rotation is sent.
//   2. The AMBIGUOUS recovery ceremony is exercised end-to-end WITHOUT
//      mutating the pseudonym key (a ghost marker manufactures the
//      ambiguous state; the ceremony dispatches no PUT).
//
// Isolation: the harness appliance is a per-run throwaway (mktemp WORK dir,
// destroyed after the run; workers=1) — the controlled unknown-outcome
// rotation never touches shared /data. The rotation is posture-neutral
// (rotate-only preserves the OFF posture), so the sibling decryption spec's
// starting assumptions are unaffected.
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext } from "@playwright/test";
import { AUTH_URL, USERS } from "./fixtures";

test.use({ extraHTTPHeaders: { "X-Forwarded-For": "198.51.100.75" } });

const ROUTE = "/app/security/decryption";
const MARKER_KEY = "culvert.decryption.rotation-recovery.v1";

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(x: unknown): string {
  return typeof x === "string" ? x : "";
}

async function newAdminClient(xff: string): Promise<APIRequestContext> {
  const ctx = await request.newContext({
    baseURL: AUTH_URL,
    extraHTTPHeaders: { "X-Forwarded-For": xff },
  });
  const login = await ctx.post("/api/auth/login", {
    data: { user: USERS.admin.user, pass: USERS.admin.pass },
  });
  expect(login.ok()).toBe(true);
  return ctx;
}

async function getPrivacyFull(api: APIRequestContext): Promise<{
  redact: boolean;
  keyId: string;
  revision: string;
  seq: number;
  receiptOps: string[];
}> {
  const resp = await api.get("/api/decryption/redaction");
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad privacy envelope");
  const receiptOps: string[] = [];
  const rs = v["rotation_receipts"];
  if (Array.isArray(rs)) {
    for (const r of rs) {
      if (isRecord(r)) receiptOps.push(str(r["operation_id"]));
    }
  }
  return {
    redact: v["redact_hosts"] === true,
    keyId: str(v["key_id"]),
    revision: str(v["revision"]),
    seq: Number(v["rotation_seq"]),
    receiptOps,
  };
}

test("lost rotation response: identity survives a page reload, resolves LANDED from the receipt, zero second rotation", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.76");
  try {
    const before = await getPrivacyFull(api);

    await page.goto(ROUTE);
    await page.getByRole("tab", { name: "Destination Privacy" }).click();
    await expect(page.getByText("Node-local").first()).toBeVisible();

    // Deterministic transport-loss seam: the FIRST rotation PUT is executed
    // against the real appliance, then its response is dropped before the
    // page can see it.
    let intercepted = 0;
    await page.route("**/api/decryption/redaction", async (route) => {
      if (route.request().method() === "PUT" && intercepted === 0) {
        intercepted += 1;
        await route.fetch(); // the appliance executes the rotation
        await route.abort("failed"); // …but the browser never learns it
        return;
      }
      await route.continue();
    });

    await page.getByRole("button", { name: /Rotate pseudonym key/ }).click();
    await expect(
      page.getByText("NOT the TLS inspection Root CA", { exact: false }),
    ).toBeVisible();
    await page.getByLabel("Type ROTATE to confirm").fill("ROTATE");
    await page
      .getByRole("button", { name: "Rotate pseudonym key", exact: true })
      .click();
    await expect(page.getByText("Outcome unconfirmed")).toBeVisible();
    expect(intercepted).toBe(1);

    // The durable recovery marker holds the operation identity (written
    // BEFORE the dispatch — it exists even though the response was lost).
    const rawMarker = await page.evaluate(
      (k) => sessionStorage.getItem(k),
      MARKER_KEY,
    );
    expect(rawMarker).not.toBeNull();
    const parsed: unknown = JSON.parse(rawMarker ?? "null");
    if (!isRecord(parsed)) throw new Error("marker is not an object");
    const opX = str(parsed["operationId"]);
    expect(opX).toMatch(/^[0-9a-f]{32}$/);
    expect(parsed["preSeq"]).toBe(before.seq);
    expect(parsed["subject"]).toBe(USERS.admin.user);

    await page.unroute("**/api/decryption/redaction");

    // No further rotation may be dispatched by anything from here on.
    let putsAfter = 0;
    page.on("request", (r) => {
      if (r.method() === "PUT" && r.url().includes("/api/decryption/redaction"))
        putsAfter += 1;
    });

    // FULL PAGE RELOAD — only the browser session storage survives.
    await page.reload();
    await page.getByRole("tab", { name: "Destination Privacy" }).click();

    // The same pending operation is recovered and resolved from the
    // appliance's receipt: landed exactly once.
    await expect(page.getByText("landed exactly once")).toBeVisible();
    const clearedMarker = await page.evaluate(
      (k) => sessionStorage.getItem(k),
      MARKER_KEY,
    );
    expect(clearedMarker).toBeNull(); // terminal resolution retires it
    await expect(
      page.getByRole("button", { name: /Rotate pseudonym key/ }),
    ).toBeEnabled(); // a NEW deliberate rotation is possible again

    // Authoritative truth: exactly ONE rotation happened — ours.
    const after = await getPrivacyFull(api);
    expect(after.seq).toBe(before.seq + 1);
    expect(after.receiptOps).toContain(opX);
    expect(after.keyId).not.toBe(before.keyId);
    expect(after.redact).toBe(before.redact); // posture untouched
    expect(putsAfter).toBe(0); // zero second rotation dispatched
  } finally {
    await api.dispose();
  }
});

test("ambiguous recovery ceremony resolves the latch without any mutation of the pseudonym key", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.77");
  try {
    const before = await getPrivacyFull(api);

    let puts = 0;
    page.on("request", (r) => {
      if (r.method() === "PUT" && r.url().includes("/api/decryption/redaction"))
        puts += 1;
    });

    await page.goto(ROUTE);
    // Manufacture the AMBIGUOUS state without rotating: a pending marker
    // whose operation has no receipt while its sequence anchor differs from
    // the current sequence (the review's concurrent-admin shape).
    await page.evaluate(
      ([k, subject, preSeq]) => {
        sessionStorage.setItem(
          k,
          JSON.stringify({
            version: 1,
            operationId: "e2e-ghost-ambiguous-op",
            preSeq,
            startedAt: Date.now(),
            subject,
          }),
        );
      },
      [MARKER_KEY, USERS.admin.user, before.seq - 1] as const,
    );
    await page.reload();
    await page.getByRole("tab", { name: "Destination Privacy" }).click();

    await expect(page.getByText("cannot yet be proven")).toBeVisible();
    await expect(
      page.getByRole("button", { name: /Rotate pseudonym key/ }),
    ).toBeDisabled();

    // The EXPLICIT human recovery path: typed ceremony, no mutation.
    await page
      .getByRole("button", { name: /Resolve ambiguous rotation/ })
      .click();
    await expect(
      page.getByText("cannot prove", { exact: false }),
    ).toBeVisible();
    await expect(page.getByText("continuity", { exact: false })).toBeVisible();
    await page.getByLabel("Type ABANDON to confirm").fill("ABANDON");
    await page
      .getByRole("button", { name: "Abandon unresolved rotation", exact: true })
      .click();

    await expect(page.getByText("abandoned", { exact: false })).toBeVisible();
    const cleared = await page.evaluate(
      (k) => sessionStorage.getItem(k),
      MARKER_KEY,
    );
    expect(cleared).toBeNull();
    await expect(
      page.getByRole("button", { name: /Rotate pseudonym key/ }),
    ).toBeEnabled();

    // The recovery mutated NOTHING: no PUT was sent and the appliance's
    // pseudonym key, sequence, and posture are byte-identical.
    expect(puts).toBe(0);
    const after = await getPrivacyFull(api);
    expect(after.keyId).toBe(before.keyId);
    expect(after.seq).toBe(before.seq);
    expect(after.redact).toBe(before.redact);
  } finally {
    await api.dispose();
  }
});

test("SPA navigation (no reload): the stale cache never classifies; a post-return GET resolves LANDED, one rotation total", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.78");
  try {
    const before = await getPrivacyFull(api);

    // Establish cached pre-operation truth in the LIVE app instance.
    await page.goto(ROUTE);
    await page.getByRole("tab", { name: "Destination Privacy" }).click();
    await expect(page.getByText("Node-local").first()).toBeVisible();

    // Deterministic transport-loss seam (executes on the appliance, drops
    // the response before the browser sees it).
    let intercepted = 0;
    await page.route("**/api/decryption/redaction", async (route) => {
      if (route.request().method() === "PUT" && intercepted === 0) {
        intercepted += 1;
        await route.fetch();
        await route.abort("failed");
        return;
      }
      await route.continue();
    });
    await page.getByRole("button", { name: /Rotate pseudonym key/ }).click();
    await page.getByLabel("Type ROTATE to confirm").fill("ROTATE");
    await page
      .getByRole("button", { name: "Rotate pseudonym key", exact: true })
      .click();
    await expect(page.getByText("Outcome unconfirmed")).toBeVisible();
    const rawMarker = await page.evaluate(
      (k) => sessionStorage.getItem(k),
      MARKER_KEY,
    );
    const parsed: unknown = JSON.parse(rawMarker ?? "null");
    if (!isRecord(parsed)) throw new Error("marker is not an object");
    const opX = str(parsed["operationId"]);
    expect(opX).toMatch(/^[0-9a-f]{32}$/);
    await page.unroute("**/api/decryption/redaction");

    // Count every further rotation PUT and every privacy GET from here on.
    let puts = 0;
    let gets = 0;
    page.on("request", (r) => {
      if (!r.url().includes("/api/decryption/redaction")) return;
      if (r.method() === "PUT") puts += 1;
      if (r.method() === "GET") gets += 1;
    });

    // SPA navigation: SAME browser context, SAME app instance and
    // QueryClient — no reload. The pre-operation snapshot stays cached.
    await page.getByRole("link", { name: "Dashboard" }).click();
    await expect(
      page.getByRole("tab", { name: "Destination Privacy" }),
    ).toHaveCount(0);
    await page.getByRole("link", { name: "Decryption", exact: true }).click();
    await page.getByRole("tab", { name: "Destination Privacy" }).click();

    // The stale cache must not classify; an actual post-return GET is
    // forced and ITS truth (the appliance's receipt for X) proves LANDED.
    await expect(page.getByText("landed exactly once")).toBeVisible();
    expect(gets).toBeGreaterThan(0); // a real post-return GET occurred
    const cleared = await page.evaluate(
      (k) => sessionStorage.getItem(k),
      MARKER_KEY,
    );
    expect(cleared).toBeNull(); // cleared only by that fresh truth
    await expect(
      page.getByRole("button", { name: /Rotate pseudonym key/ }),
    ).toBeEnabled();

    // Exactly ONE rotation happened in total — the intercepted one.
    const after = await getPrivacyFull(api);
    expect(after.seq).toBe(before.seq + 1);
    expect(after.receiptOps).toContain(opX);
    expect(puts).toBe(0);
  } finally {
    await api.dispose();
  }
});
