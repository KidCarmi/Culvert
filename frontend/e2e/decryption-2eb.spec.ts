// 2E-B real-binary browser qualification: the Decryption Operations surface
// over the actual CULVERT binary and committed dist, on the AUTH appliance.
//
// Directive §11 proofs:
//   1. Viewer reads the Decryption page; ZERO mutation controls mount.
//   2. Operator gets exactly the volatile auto-exclusion actions; no Admin
//      privacy/tunable controls.
//   3. Admin destination privacy: reversible posture round-trip (enable →
//      verify via authoritative API → disable), restored in finally.
//      PLUS one REAL pseudonym-key rotation through the T3 typed ceremony —
//      permitted here because the harness appliance is a FULLY isolated
//      throwaway (per-run mktemp WORK dir, per-run AdminSettings/log data,
//      destroyed after the run; playwright workers=1). The rotation is
//      verified by the non-secret key_id changing; no key material is ever
//      observed.
//   4. Tunables: one reversible bounded mutation (tightening — saves without
//      ceremony), authoritative refresh, a DETERMINISTIC stale-write 409
//      (racer API write after the page's post-save refresh), restore.
//   5. Auto-exclusions: clear-all ceremony truth against the real volatile
//      cache (empty here — the truthful outcome is "Cleared 0"; populated
//      evict/clear truth is proven by the Go suites + component fixtures).
//   6. Node-local ownership scope is visible in the UI.
//   7. The Decryption journey makes NO request to CDR, Content Security
//      write surfaces, or certificate-rotation endpoints.
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page } from "@playwright/test";
import { AUTH_URL, EMPTY_STATE, USERS } from "./fixtures";

test.use({ extraHTTPHeaders: { "X-Forwarded-For": "198.51.100.71" } });

const ROUTE = "/app/security/decryption";

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

function str(x: unknown): string {
  return typeof x === "string" ? x : "";
}

async function getPrivacy(
  api: APIRequestContext,
): Promise<{ redact: boolean; keyId: string; revision: string }> {
  const resp = await api.get("/api/decryption/redaction");
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad privacy envelope");
  return {
    redact: v["redact_hosts"] === true,
    keyId: str(v["key_id"]),
    revision: str(v["revision"]),
  };
}

async function getExclusions(api: APIRequestContext): Promise<{
  active: number;
  confirmN: number;
  revision: string;
}> {
  const resp = await api.get("/api/decryption-exclusions");
  const v: unknown = await resp.json();
  if (!isRecord(v) || !isRecord(v["stats"])) throw new Error("bad envelope");
  return {
    active: Number(v["stats"]["active"]),
    confirmN: Number(v["stats"]["confirm_n"]),
    revision: str(v["tunables_revision"]),
  };
}

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}

function trackApiRequests(page: Page): string[] {
  const urls: string[] = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.pathname.startsWith("/api/")) urls.push(u.pathname);
  });
  return urls;
}

function assertNoCrossSurface(apiCalls: readonly string[]): void {
  for (const u of apiCalls) {
    expect(u).not.toContain("/api/cdr");
    expect(u).not.toContain("/api/security-scan");
    expect(u).not.toContain("/api/certs");
    expect(u.startsWith("/api/ca")).toBe(false);
  }
}

// ── 1 + 6: viewer — read-only, node-local visibility ───────────────────────
test.describe("viewer posture", () => {
  test.use({ storageState: EMPTY_STATE });
  test("viewer reads every section; zero mutation controls; node-local scope visible", async ({
    page,
  }) => {
    const apiCalls = trackApiRequests(page);
    await page.goto(ROUTE);
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    await expect(
      page.getByText("Coverage — since process start"),
    ).toBeVisible();

    await page.getByRole("tab", { name: "Destination Privacy" }).click();
    await expect(page.getByText("Node-local").first()).toBeVisible();
    await expect(
      page.getByRole("button", { name: /Enable destination privacy/ }),
    ).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: /Disable destination privacy/ }),
    ).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: /Rotate pseudonym key/ }),
    ).toHaveCount(0);

    await page.getByRole("tab", { name: "Auto-Exclusions" }).click();
    await expect(
      page.getByText("Volatile / runtime-generated").first(),
    ).toBeVisible();
    await expect(page.getByRole("button", { name: "Evict" })).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: /Clear all learned exclusions/ }),
    ).toHaveCount(0);
    await expect(page.getByText("Cache tuning")).toHaveCount(0);

    assertNoCrossSurface(apiCalls);
  });
});

// ── 2: operator — exactly the volatile actions ─────────────────────────────
test.describe("operator posture", () => {
  test.use({ storageState: EMPTY_STATE });
  test("operator gets the exclusion actions and nothing admin-only", async ({
    page,
  }) => {
    await page.goto(ROUTE);
    await login(page, USERS.operator.user, USERS.operator.pass);
    await expect(
      page.getByText("Coverage — since process start"),
    ).toBeVisible();

    await page.getByRole("tab", { name: "Auto-Exclusions" }).click();
    await expect(
      page.getByRole("button", { name: /Clear all learned exclusions/ }),
    ).toBeVisible();
    await expect(page.getByText("Cache tuning")).toHaveCount(0);

    await page.getByRole("tab", { name: "Destination Privacy" }).click();
    await expect(page.getByText("Destination privacy").first()).toBeVisible();
    await expect(
      page.getByRole("button", { name: /Enable destination privacy/ }),
    ).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: /Rotate pseudonym key/ }),
    ).toHaveCount(0);
  });
});

// ── 3: admin privacy round trip + one REAL isolated rotation ───────────────
test("admin: privacy posture round-trip and a real T3 pseudonym rotation, restored", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.72");
  const before = await getPrivacy(api);
  expect(before.redact).toBe(false); // harness default posture
  const apiCalls = trackApiRequests(page);
  try {
    await page.goto(ROUTE);
    await page.getByRole("tab", { name: "Destination Privacy" }).click();
    await expect(page.getByText("Node-local").first()).toBeVisible();

    // Enable (light confirm) — verified against the authoritative API.
    const enablePut = page.waitForResponse(
      (r) =>
        r.url().includes("/api/decryption/redaction") &&
        r.request().method() === "PUT",
    );
    await page
      .getByRole("button", { name: /Enable destination privacy/ })
      .click();
    await expect(
      page.getByText("Log search by plaintext host stops resolving", {
        exact: false,
      }),
    ).toBeVisible();
    await page
      .getByRole("button", { name: "Enable destination privacy", exact: true })
      .click();
    await enablePut;
    const enabled = await getPrivacy(api);
    expect(enabled.redact).toBe(true);
    expect(enabled.keyId).not.toBe("");

    // One REAL rotation through the typed T3 ceremony (isolated throwaway
    // appliance — see the header note). Verified by key_id changing.
    const rotatePut = page.waitForResponse(
      (r) =>
        r.url().includes("/api/decryption/redaction") &&
        r.request().method() === "PUT",
    );
    await page.getByRole("button", { name: /Rotate pseudonym key/ }).click();
    await expect(
      page.getByText("NOT the TLS inspection Root CA", { exact: false }),
    ).toBeVisible();
    await page.getByLabel("Type ROTATE to confirm").fill("ROTATE");
    await page
      .getByRole("button", { name: "Rotate pseudonym key", exact: true })
      .click();
    await rotatePut;
    const rotated = await getPrivacy(api);
    expect(rotated.redact).toBe(true); // rotate-only preserves the posture
    expect(rotated.keyId).not.toBe("");
    expect(rotated.keyId).not.toBe(enabled.keyId);
    await expect(
      page.getByText(`New pseudonym generation: ${rotated.keyId}`),
    ).toBeVisible();

    // Disable through the T2 ceremony.
    const disablePut = page.waitForResponse(
      (r) =>
        r.url().includes("/api/decryption/redaction") &&
        r.request().method() === "PUT",
    );
    await page
      .getByRole("button", { name: /Disable destination privacy/ })
      .click();
    await expect(
      page.getByText("More destination detail is retained", { exact: false }),
    ).toBeVisible();
    await page
      .getByRole("button", { name: "Disable destination privacy", exact: true })
      .click();
    await disablePut;
    expect((await getPrivacy(api)).redact).toBe(false);
    assertNoCrossSurface(apiCalls);
  } finally {
    // Restore the harness default posture whatever happened above.
    const cur = await getPrivacy(api);
    if (cur.redact) {
      await api.put("/api/decryption/redaction", {
        data: { redact_hosts: false, ifRevision: cur.revision },
      });
    }
    await api.dispose();
  }
});

// ── 4: tunables — bounded reversible mutation + deterministic stale 409 ────
test("admin: tunable mutation with fence, deterministic stale conflict, restored", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.73");
  const before = await getExclusions(api);
  try {
    await page.goto(ROUTE);
    await page.getByRole("tab", { name: "Auto-Exclusions" }).click();
    await expect(page.getByText("Cache tuning")).toBeVisible();

    // Tightening change (confirm 2 → 3): saves directly, fenced. Register
    // the page's post-save exclusions refresh BEFORE confirming so the form
    // deterministically holds the refreshed revision afterwards.
    const refreshed = page.waitForResponse(
      (r) =>
        r.url().includes("/api/decryption-exclusions?") &&
        r.request().method() === "GET",
    );
    await page
      .getByLabel("Confirm count (distinct clients)")
      .fill(String(before.confirmN + 1));
    await page.getByRole("button", { name: "Save tunables" }).click();
    await refreshed;
    const tightened = await getExclusions(api);
    expect(tightened.confirmN).toBe(before.confirmN + 1);

    // Deterministic stale conflict: a racer lands a NEWER configuration via
    // the API (with fresh revision), then the page saves against the
    // revision it refreshed BEFORE the racer — the appliance must refuse
    // with the structured 409 and the form entries survive.
    const racer = await api.put(
      `/api/decryption-exclusions/tunables?ifRevision=${encodeURIComponent(tightened.revision)}`,
      {
        data: {
          confirm_n: tightened.confirmN,
          ttl_secs: 0,
          pinned_ttl_secs: 0,
          window_secs: 300,
          max_entries: 0,
        },
      },
    );
    expect(racer.ok()).toBe(true);
    await page
      .getByLabel("Confirm count (distinct clients)")
      .fill(String(before.confirmN + 2));
    await page.getByRole("button", { name: "Save tunables" }).click();
    await expect(
      page.getByText("your entries are preserved", { exact: false }),
    ).toBeVisible();
    await expect(
      page.getByLabel("Confirm count (distinct clients)"),
    ).toHaveValue(String(before.confirmN + 2));
  } finally {
    // Restore defaults (zeros = reset) with a fresh fence.
    const cur = await getExclusions(api);
    await api.put(
      `/api/decryption-exclusions/tunables?ifRevision=${encodeURIComponent(cur.revision)}`,
      {
        data: {
          confirm_n: 0,
          ttl_secs: 0,
          pinned_ttl_secs: 0,
          window_secs: 0,
          max_entries: 0,
        },
      },
    );
    await api.dispose();
  }
});

// ── 5: volatile cache truth through the ceremony ───────────────────────────
test("clear-all runs the ceremony and reports the truthful volatile outcome", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.74");
  try {
    await page.goto(ROUTE);
    await page.getByRole("tab", { name: "Auto-Exclusions" }).click();
    await expect(
      page.getByRole("button", { name: /Clear all learned exclusions/ }),
    ).toBeVisible();
    await page
      .getByRole("button", { name: /Clear all learned exclusions/ })
      .click();
    await expect(
      page.getByText("does not delete Decryption Profiles or policy rules", {
        exact: false,
      }),
    ).toBeVisible();
    const del = page.waitForResponse(
      (r) =>
        r.url().endsWith("/api/decryption-exclusions") &&
        r.request().method() === "DELETE",
    );
    await page
      .getByRole("button", { name: "Clear all exclusions", exact: true })
      .click();
    await del;
    // The harness cache is empty (no fail-open learning traffic): the
    // truthful outcome is "Cleared 0", never a fabricated success count.
    await expect(
      page.getByText("Cleared 0 learned exclusion(s)", { exact: false }),
    ).toBeVisible();
    expect((await getExclusions(api)).active).toBe(0);
  } finally {
    await api.dispose();
  }
});
