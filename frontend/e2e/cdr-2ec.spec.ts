// 2E-C real-binary browser qualification: the CDR / Sluice integration
// surface over the actual CULVERT binary and committed dist, on the AUTH
// appliance. No live Sluice engine exists in this harness, so every
// engine-dependent state is proven in its TRUTHFUL degraded form (503 "no
// active CDR client", enrollment 502 against an unreachable endpoint); the
// full enroll/renew/revoke RPC flows are proven by the Go suites against a
// fake in-process Sluice (cdr_2ec_red_test.go + cdr_revoke_rpc/coverage
// suites) and the component fixtures.
//
// Directive §19 proofs:
//   1. Viewer posture: every tab readable, ZERO mutation controls, no
//      mutation request issued.
//   2. Admin posture: toggle/enroll/policy/test controls mount.
//   3. Reversible config mutation: the T2 runtime toggle round-trip,
//      verified against the authoritative API, restored in finally.
//   4. Enrollment lifecycle, isolated: the T2 ceremony dispatches exactly
//      one POST against an unreachable endpoint → the truthful 502 names
//      the OPERATION (the outcome is not settled: Sluice could not be
//      asked), the verified non-secret recovery marker survives, the
//      "Resolve enrollment" action performs a fresh authoritative
//      resolution (AMBIGUOUS — the engine is unreachable, retryable), and
//      the explicit abandon ceremony clears the browser marker while the
//      appliance keeps its durable receipt (listed, then removed in
//      finally). The single-use token appears in NO storage (the marker
//      included) and NOT in the DOM serialization afterwards; no instance
//      and no sentinel side effect is left behind.
//   5. Policy lifecycle: add → visible; duplicate name → 409 conflict
//      rendered; T2 delete → gone (authoritative API verified).
//   6. Bounded test action: one POST, truthful "no active CDR client"
//      failure, no auto-retry.
//   7. Unknown-outcome proof: a transport-lost policy delete latches the
//      page (mutations blocked) and a fresh successful refresh resolves it
//      against server truth (the rule is still there — the request never
//      reached the appliance).
//   8. Cross-surface sweep: the whole journey touches only /api/cdr/* +
//      the auth/session surfaces — no decryption, content-security,
//      policy, PAC, upstream, MCP, or certificate endpoints.
//
// /data hygiene: the harness dataDir is the SHARED absolute /data (recorded
// harness debt), so everything this spec creates is removed in finally —
// the toggle is restored to its observed pre-test state, created rules are
// deleted, and the enrollment deliberately never succeeds (nothing to
// clean; asserted).
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page } from "@playwright/test";
import { AUTH_URL, EMPTY_STATE, USERS } from "./fixtures";

test.use({ extraHTTPHeaders: { "X-Forwarded-For": "198.51.100.81" } });

const ROUTE = "/app/security/cdr";

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
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

async function getConfigEnabled(api: APIRequestContext): Promise<boolean> {
  const resp = await api.get("/api/cdr/config");
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad config envelope");
  return v["enabled"] === true;
}

async function listRuleNames(api: APIRequestContext): Promise<string[]> {
  const resp = await api.get("/api/cdr/policies");
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v) || !Array.isArray(v["rules"])) return [];
  const names: string[] = [];
  for (const r of v["rules"]) {
    if (isRecord(r) && typeof r["name"] === "string") names.push(r["name"]);
  }
  return names;
}

async function listInstanceNames(api: APIRequestContext): Promise<string[]> {
  const resp = await api.get("/api/cdr/instances");
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v) || !Array.isArray(v["instances"])) return [];
  const names: string[] = [];
  for (const r of v["instances"]) {
    if (isRecord(r) && typeof r["name"] === "string") names.push(r["name"]);
  }
  return names;
}

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}

function trackApiRequests(page: Page): Array<{ method: string; path: string }> {
  const calls: Array<{ method: string; path: string }> = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.pathname.startsWith("/api/")) {
      calls.push({ method: r.method(), path: u.pathname });
    }
  });
  return calls;
}

// Proof 8: the CDR journey stays on its own surface (auth/session reads are
// the shell's own).
const ALLOWED_PREFIXES = [
  "/api/cdr/",
  "/api/auth/",
  "/api/setup/",
  "/api/session",
];
function assertNoCrossSurface(
  calls: ReadonlyArray<{ method: string; path: string }>,
): void {
  for (const c of calls) {
    expect(
      ALLOWED_PREFIXES.some((p) => c.path.startsWith(p)),
      `unexpected cross-surface call ${c.method} ${c.path}`,
    ).toBe(true);
  }
}

// ── 1 + 8: viewer — read-only everywhere, no mutation issued ───────────────
test.describe("viewer posture", () => {
  test.use({ storageState: EMPTY_STATE });
  test("viewer reads every tab; zero mutation controls; zero mutation requests", async ({
    page,
  }) => {
    const calls = trackApiRequests(page);
    await page.goto(ROUTE);
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    await expect(page.getByText("Runtime state")).toBeVisible();
    await expect(
      page.getByRole("button", { name: /able CDR processing/ }),
    ).toHaveCount(0);

    await page.getByRole("tab", { name: "Instances" }).click();
    await expect(page.getByText(/Enrolled instances/)).toBeVisible();
    await expect(page.getByText("Enroll a new instance")).toHaveCount(0);
    await expect(page.getByRole("button", { name: /Revoke…/ })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /Delete…/ })).toHaveCount(0);

    await page.getByRole("tab", { name: "Policies" }).click();
    await expect(page.getByText(/first match by priority/)).toBeVisible();
    await expect(page.getByText("Add a rule")).toHaveCount(0);

    await page.getByRole("tab", { name: "Test" }).click();
    await expect(page.getByText("Admin only")).toBeVisible();
    await expect(page.getByRole("button", { name: "Run test" })).toHaveCount(0);

    // Every CDR-surface request the viewer journey produced was a read
    // (the shell's own /api/auth/login POST is the one non-CDR mutation).
    for (const c of calls) {
      if (c.path.startsWith("/api/cdr/")) expect(c.method).toBe("GET");
    }
    assertNoCrossSurface(calls);
  });
});

// ── 2 + 3: admin — T2 toggle round-trip against authoritative truth ────────
test("admin: runtime toggle round-trip through the T2 ceremony, restored", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.82");
  const before = await getConfigEnabled(api);
  const calls = trackApiRequests(page);
  try {
    await page.goto(ROUTE);
    await expect(page.getByText("Runtime state")).toBeVisible();

    // Flip to the opposite of the observed state through the ceremony.
    const openLabel = before
      ? "Disable CDR processing…"
      : "Enable CDR processing…";
    const confirmLabel = before ? "Disable CDR" : "Enable CDR";
    await page.getByRole("button", { name: openLabel }).click();
    await expect(
      page.getByText(before ? /NO file sanitization/ : /Enables the CDR stage/),
    ).toBeVisible();
    const put = page.waitForResponse(
      (r) =>
        r.url().includes("/api/cdr/config") && r.request().method() === "PUT",
    );
    await page.getByRole("button", { name: confirmLabel, exact: true }).click();
    expect((await put).ok()).toBe(true);

    // Authoritative truth flipped.
    await expect.poll(async () => getConfigEnabled(api)).toBe(!before);
    // And the page reflects it after its own refresh.
    await expect(
      page.getByRole("button", {
        name: before ? "Enable CDR processing…" : "Disable CDR processing…",
      }),
    ).toBeVisible();
    assertNoCrossSurface(calls);
  } finally {
    const restore = await api.put("/api/cdr/config", {
      data: { enabled: before },
    });
    expect(restore.ok()).toBe(true);
    expect(await getConfigEnabled(api)).toBe(before);
    await api.dispose();
  }
});

// ── 4: enrollment lifecycle against the REAL pinned Sluice daemon ──────────
// The harness (scripts/e2e-smoke.sh) runs the pinned Sluice daemon with real
// mTLS and exports its address, TOFU pin and first-boot token. Proofs:
//   a. a genuine token exchange through the T2 ceremony → the instance is
//      registered, the result facts are rendered truthfully (CDR enabled,
//      client active), the receipt is `stored`, the marker is cleared, and
//      the single-use token leaves NO residue (marker, storages, DOM);
//   b. a genuine DEFINITE refusal (bogus token, same engine) → 502 naming no
//      operation, "Enrollment failed", receipt `not_issued` (terminal, so
//      removable), marker cleared;
//   c. the T3 local delete lists every trusted fingerprint of the lineage;
//   d. an unresolved receipt is NOT removable (409) — proven on the real
//      daemon by a dispatch to an endpoint that cannot answer — and the
//      terminal receipts are, so /data hygiene holds.
const SLUICE_ADDR = process.env["CULVERT_E2E_SLUICE_ADDR"] ?? "";
const SLUICE_FP = process.env["CULVERT_E2E_SLUICE_FP"] ?? "";
const SLUICE_TOKEN = process.env["CULVERT_E2E_SLUICE_TOKEN"] ?? "";

test("admin: real enrollment, real definite refusal, lineage-aware delete, receipt immutability", async ({
  page,
}) => {
  test.skip(
    SLUICE_ADDR === "" || SLUICE_FP === "" || SLUICE_TOKEN === "",
    "the harness did not export a pinned Sluice daemon",
  );
  const api = await newAdminClient("198.51.100.83");
  const MARKER_KEY = "culvert.cdr.enroll-recovery.v1";
  const name = `e2e-sluice-${Date.now().toString(36)}`;
  const enabledBefore = await getConfigEnabled(api);
  const receiptsToRemove: string[] = [];
  const operationFor = async (n: string): Promise<string> => {
    const resp = await api.get("/api/cdr/instances/enroll/receipts");
    const v: unknown = await resp.json();
    if (!isRecord(v) || !Array.isArray(v["receipts"])) return "";
    for (const r of v["receipts"]) {
      if (
        isRecord(r) &&
        r["name"] === n &&
        typeof r["operationId"] === "string"
      )
        return r["operationId"];
    }
    return "";
  };
  const receiptState = async (op: string): Promise<string> => {
    const resp = await api.get("/api/cdr/instances/enroll/receipts");
    const v: unknown = await resp.json();
    if (!isRecord(v) || !Array.isArray(v["receipts"])) return "";
    for (const r of v["receipts"]) {
      if (
        isRecord(r) &&
        r["operationId"] === op &&
        typeof r["state"] === "string"
      )
        return r["state"];
    }
    return "";
  };
  try {
    await page.goto(ROUTE);
    await page.getByRole("tab", { name: "Instances" }).click();
    await expect(page.getByText("Enroll a new instance")).toBeVisible();

    // (a) genuine exchange.
    await page.getByLabel("Instance name").fill(name);
    await page.getByLabel("Endpoint (host:port)").fill(SLUICE_ADDR);
    await page
      .getByLabel("Server certificate fingerprint (TOFU pin)")
      .fill(SLUICE_FP);
    await page.getByLabel("Enrollment token (single-use)").fill(SLUICE_TOKEN);
    await page.getByRole("button", { name: "Enroll instance…" }).click();
    await expect(
      page.getByText(/consumed by a successful exchange/),
    ).toBeVisible();
    const post = page.waitForResponse(
      (r) =>
        r.url().includes("/api/cdr/instances/enroll") &&
        r.request().method() === "POST",
    );
    await page
      .getByRole("button", { name: "Enroll instance", exact: true })
      .click();
    const resp = await post;
    expect(resp.status()).toBe(200);
    const body: unknown = await resp.json();
    expect(isRecord(body) && body["stored"]).toBe(true);
    expect(isRecord(body) && body["cdrEnabled"]).toBe(true);
    await expect(page.getByText(`Enrolled ${name}`)).toBeVisible();
    await expect(page.getByText(/Credential issued and stored/)).toBeVisible();
    await expect(page.getByText(/auto-enabled/)).toHaveCount(0);
    await expect(page.getByRole("cell", { name })).toBeVisible();
    const opA = await operationFor(name);
    expect(opA).not.toBe("");
    expect(await receiptState(opA)).toBe("stored");
    receiptsToRemove.push(opA);

    // No secret residue anywhere; the marker is cleared on success.
    const residue = await page.evaluate((key: string) => {
      const stores: string[] = [];
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        if (k !== null) stores.push(sessionStorage.getItem(k) ?? "");
      }
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k !== null) stores.push(localStorage.getItem(k) ?? "");
      }
      return {
        storageBlob: stores.join("|"),
        marker: sessionStorage.getItem(key),
        html: document.body.innerHTML,
      };
    }, MARKER_KEY);
    expect(residue.storageBlob).not.toContain(SLUICE_TOKEN);
    expect(residue.html).not.toContain(SLUICE_TOKEN);
    expect(residue.marker).toBeNull();

    // (b) genuine DEFINITE refusal on the same engine.
    const bogus = `${name}-bogus`;
    await page.getByLabel("Instance name").fill(bogus);
    await page.getByLabel("Endpoint (host:port)").fill(SLUICE_ADDR);
    await page
      .getByLabel("Server certificate fingerprint (TOFU pin)")
      .fill(SLUICE_FP);
    await page.getByLabel("Enrollment token (single-use)").fill("bogus-token");
    await page.getByRole("button", { name: "Enroll instance…" }).click();
    const post2 = page.waitForResponse(
      (r) =>
        r.url().includes("/api/cdr/instances/enroll") &&
        r.request().method() === "POST",
    );
    await page
      .getByRole("button", { name: "Enroll instance", exact: true })
      .click();
    const resp2 = await post2;
    expect(resp2.status()).toBe(502);
    expect(await resp2.text()).not.toContain("outcome unknown");
    await expect(
      page.getByText("Enrollment failed", { exact: true }),
    ).toBeVisible();
    await expect(page.getByLabel("Enrollment token (single-use)")).toHaveValue(
      "",
    );
    const opB = await operationFor(bogus);
    expect(opB).not.toBe("");
    expect(await receiptState(opB)).toBe("not_issued");
    receiptsToRemove.push(opB);
    expect(
      await page.evaluate(
        (key: string) => sessionStorage.getItem(key),
        MARKER_KEY,
      ),
    ).toBeNull();
    expect(await listInstanceNames(api)).not.toContain(bogus);

    // (d) an UNRESOLVED receipt cannot be removed: a dispatch to a port
    // that never answers leaves the operation "dispatched" (the engine
    // could not be asked), and the appliance refuses to forget it.
    const stuck = `${name}-stuck`;
    const stuckResp = await api.post("/api/cdr/instances/enroll", {
      data: {
        name: stuck,
        endpoint: "127.0.0.1:1",
        serverFingerprint: SLUICE_FP,
        token: "unused",
        operationId: `e2e-stuck-${Date.now().toString(16)}-0123456789`,
      },
    });
    expect(stuckResp.status()).toBe(502);
    const opStuck = await operationFor(stuck);
    expect(await receiptState(opStuck)).toBe("dispatched");
    const refused = await api.delete(
      `/api/cdr/instances/enroll/receipts?operationId=${encodeURIComponent(opStuck)}`,
    );
    expect(refused.status()).toBe(409);
    // A repeated dispatch of the SAME operation id performs no RPC: 409
    // naming the recovery path, receipt unchanged.
    const again = await api.post("/api/cdr/instances/enroll", {
      data: {
        name: stuck,
        endpoint: "127.0.0.1:1",
        serverFingerprint: SLUICE_FP,
        token: "unused",
        operationId: opStuck,
      },
    });
    expect(again.status()).toBe(409);
    expect(await again.text()).toContain("/api/cdr/instances/enroll/recover");
    // Resolution against the bound (unreachable) endpoint is truthfully
    // AMBIGUOUS; a caller-supplied endpoint override is refused.
    const override = await api.post("/api/cdr/instances/enroll/recover", {
      data: { operationId: opStuck, endpoint: SLUICE_ADDR },
    });
    expect(override.status()).toBe(409);
    const rec = await api.post("/api/cdr/instances/enroll/recover", {
      data: { operationId: opStuck },
    });
    expect(rec.ok()).toBe(true);
    const recBody: unknown = await rec.json();
    expect(isRecord(recBody) && recBody["classification"]).toBe("AMBIGUOUS");
    expect(await receiptState(opStuck)).toBe("dispatched");

    // (c) T3 local delete lists the trusted lineage.
    await page.getByRole("button", { name: "Refresh" }).click();
    await page
      .getByRole("row", { name: new RegExp(name) })
      .getByRole("button", { name: "Delete…" })
      .click();
    await expect(page.getByText(/does NOT revoke anything/)).toBeVisible();
    await page.getByLabel(`Type ${name} to confirm`).fill(name);
    const del = page.waitForResponse(
      (r) =>
        r.url().includes("/api/cdr/instances?name=") &&
        r.request().method() === "DELETE",
    );
    await page.getByRole("button", { name: "Delete locally" }).click();
    const delResp = await del;
    expect(delResp.ok()).toBe(true);
    const delBody: unknown = await delResp.json();
    const fps =
      isRecord(delBody) && Array.isArray(delBody["clientCertFingerprints"])
        ? delBody["clientCertFingerprints"]
        : [];
    expect(fps).toHaveLength(1);
    await expect(page.getByText(`Deleted ${name} (locally)`)).toBeVisible();
    expect(await listInstanceNames(api)).not.toContain(name);
  } finally {
    // /data hygiene: terminal receipts are removable; the deliberately
    // unresolved one is NOT (by contract) and is recorded as harness debt.
    for (const op of receiptsToRemove) {
      const r = await api.delete(
        `/api/cdr/instances/enroll/receipts?operationId=${encodeURIComponent(op)}`,
      );
      expect(r.ok()).toBe(true);
    }
    if ((await listInstanceNames(api)).includes(name)) {
      await api.delete(`/api/cdr/instances?name=${encodeURIComponent(name)}`);
    }
    const restore = await api.put("/api/cdr/config", {
      data: { enabled: enabledBefore },
    });
    expect(restore.ok()).toBe(true);
    await api.dispose();
  }
});

// ── 5 + 7: policy lifecycle + transport-lost delete latches ────────────────
test("admin: policy add → duplicate 409 → unknown-outcome latch → real delete", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.84");
  const ruleName = `e2e-cdr-rule-${Date.now().toString(36)}`;
  try {
    await page.goto(ROUTE);
    await page.getByRole("tab", { name: "Policies" }).click();
    await expect(page.getByText("Add a rule")).toBeVisible();

    // Add through the UI.
    await page
      .getByLabel("Name (unique — this is the rule's identity)")
      .fill(ruleName);
    await page.getByLabel("Priority (higher matches first)").fill("7");
    const addPost = page.waitForResponse(
      (r) =>
        r.url().includes("/api/cdr/policies") &&
        r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Add rule" }).click();
    expect((await addPost).ok()).toBe(true);
    await expect(page.getByRole("cell", { name: ruleName })).toBeVisible();
    expect(await listRuleNames(api)).toContain(ruleName);

    // Duplicate name → the 2E-C 409 identity conflict, rendered verbatim.
    await page
      .getByLabel("Name (unique — this is the rule's identity)")
      .fill(ruleName);
    await page.getByLabel("Priority (higher matches first)").fill("9");
    await page.getByRole("button", { name: "Add rule" }).click();
    await expect(page.getByText(/already exists/)).toBeVisible();
    expect(
      (await listRuleNames(api)).filter((n) => n === ruleName),
    ).toHaveLength(1);

    // Transport-lost delete: the DELETE never leaves the browser, so the
    // truthful state is UNKNOWN → latched, mutations blocked, resolved by a
    // fresh successful refresh showing the rule still present.
    await page.route("**/api/cdr/policies?name=*", (route) => {
      if (route.request().method() === "DELETE") {
        void route.abort("failed");
        return;
      }
      void route.fallback();
    });
    await page
      .getByRole("row", { name: new RegExp(ruleName) })
      .getByRole("button", { name: "Delete…" })
      .click();
    await expect(
      page.getByText(/Enforcement changes immediately/),
    ).toBeVisible();
    await page
      .getByRole("button", { name: "Delete rule", exact: true })
      .click();
    await expect(page.getByText("Last change unconfirmed")).toBeVisible();
    await expect(page.getByRole("button", { name: "Add rule" })).toBeDisabled();
    await page.unroute("**/api/cdr/policies?name=*");

    // Resolve against fresh truth.
    await page.getByRole("button", { name: "Refresh" }).click();
    await expect(page.getByText("Last change unconfirmed")).toHaveCount(0);
    await expect(page.getByRole("cell", { name: ruleName })).toBeVisible();
    expect(await listRuleNames(api)).toContain(ruleName);

    // Real T2 delete, verified against the authoritative API.
    const del = page.waitForResponse(
      (r) =>
        r.url().includes("/api/cdr/policies") &&
        r.request().method() === "DELETE",
    );
    await page
      .getByRole("row", { name: new RegExp(ruleName) })
      .getByRole("button", { name: "Delete…" })
      .click();
    await page
      .getByRole("button", { name: "Delete rule", exact: true })
      .click();
    expect((await del).ok()).toBe(true);
    await expect(page.getByRole("cell", { name: ruleName })).toHaveCount(0);
    expect(await listRuleNames(api)).not.toContain(ruleName);
  } finally {
    // /data hygiene: the rule must not survive this spec even on failure.
    await api.delete(`/api/cdr/policies?name=${encodeURIComponent(ruleName)}`);
    await api.dispose();
  }
});

// ── 6: bounded test action — truthful degraded outcome, no retry ───────────
test("admin: the test harness reports the truthful no-active-client failure once", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.85");
  try {
    // Harness truth: no enrolled instance exists, so regardless of the
    // enable toggle there is no active client and the test must say so.
    expect(await listInstanceNames(api)).toHaveLength(0);
    const calls = trackApiRequests(page);
    await page.goto(ROUTE);
    await page.getByRole("tab", { name: "Test" }).click();
    await expect(page.getByText(/report-only/).first()).toBeVisible();

    await page.getByLabel("Test file").setInputFiles({
      name: "sample.txt",
      mimeType: "text/plain",
      buffer: Buffer.from("e2e cdr test payload"),
    });
    const post = page.waitForResponse(
      (r) =>
        r.url().includes("/api/cdr/test") && r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Run test" }).click();
    const resp = await post;
    expect(resp.status()).toBe(503);
    await expect(page.getByText(/no active CDR client/)).toBeVisible();
    await expect(page.getByText(/never retried automatically/)).toBeVisible();
    expect(
      calls.filter((c) => c.method === "POST" && c.path === "/api/cdr/test"),
    ).toHaveLength(1);
    assertNoCrossSurface(calls);
  } finally {
    await api.dispose();
  }
});
