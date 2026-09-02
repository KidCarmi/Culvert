// 2E-A real-binary browser qualification: the Content Security surface over
// the actual CULVERT binary and committed dist, on the AUTH appliance.
//
// Directive §10 proofs:
//   1. Viewer inspects Content Security; ZERO write controls mount.
//   2. Operator permissions are exact (DPI pattern surface only).
//   3. Admin performs a safe reversible config mutation (DPI bypass host)
//      and restores it — verified against the authoritative API.
//   4. YARA validate is VALIDATION-ONLY: a valid answer creates no file.
//   5. A stale concurrent DPI-bypass write is refused by the revision fence
//      (structured 409 → the fresh-truth notice; nothing applied).
//   6. A destructive rule operation (YARA rule delete) runs through the
//      required ceremony and the authoritative result shows after refresh.
//   7. The browser makes NO request to the deprecated /api/content-scan
//      aliases.
//   8. No public threat-feed infrastructure is contacted: the appliance has
//      no feeds enabled, the manual Sync answers its truthful refusal, and
//      the zero-external-request watch stays empty throughout.
//   9. Every mutated shared state is restored at exit (bypass list, DPI
//      patterns, YARA rule files) via the API in finally blocks.
//
// The YARA rules directory is a per-run LOCAL premise of the harness
// (e2e-smoke.sh) — deterministic, empty at boot, no external service.
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page } from "@playwright/test";
import { AUTH_URL, EMPTY_STATE, USERS } from "./fixtures";

test.use({ extraHTTPHeaders: { "X-Forwarded-For": "198.51.100.61" } });

const ROUTE = "/app/security/content-security";

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

async function getBypass(
  api: APIRequestContext,
): Promise<{ hosts: string[]; revision: string }> {
  const resp = await api.get("/api/dpi/bypass");
  const v: unknown = await resp.json();
  if (!isRecord(v) || !Array.isArray(v["hosts"])) {
    throw new Error("bad bypass envelope");
  }
  return {
    hosts: v["hosts"].map((h: unknown) => String(h)),
    revision: String(v["revision"]),
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

function trackExternal(page: Page): string[] {
  const external: string[] = [];
  const origin = new URL(AUTH_URL).origin;
  page.on("request", (r) => {
    if (new URL(r.url()).origin !== origin) external.push(r.url());
  });
  return external;
}

// ── 1: viewer — read-only, zero write controls ─────────────────────────────
test.describe("viewer posture", () => {
  test.use({ storageState: EMPTY_STATE });
  test("viewer inspects every section; no write controls mount; no deprecated aliases", async ({
    page,
  }) => {
    const apiCalls = trackApiRequests(page);
    const external = trackExternal(page);
    await page.goto(ROUTE);
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    await expect(page.getByText("Scan engine").first()).toBeVisible();

    await page.getByRole("tab", { name: "Threat Intelligence" }).click();
    await expect(page.getByText("Feed synchronization")).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Sync feeds now" }),
    ).toHaveCount(0);

    await page.getByRole("tab", { name: "YARA" }).click();
    await expect(page.getByText("Rule files").first()).toBeVisible();
    await expect(
      page.getByRole("button", { name: "New rule file…" }),
    ).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: "Edit settings…" }),
    ).toHaveCount(0);

    await page.getByRole("tab", { name: "DPI" }).click();
    await expect(page.getByText("Signature patterns")).toBeVisible();
    await expect(page.getByRole("button", { name: "Add pattern" })).toHaveCount(
      0,
    );
    await expect(page.locator("textarea")).toHaveCount(0);

    await page.getByRole("tab", { name: "Exclusions & Cache" }).click();
    await expect(page.getByText("Scan exclusions").first()).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Save exclusions" }),
    ).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: "Clear cache…" }),
    ).toHaveCount(0);

    expect(apiCalls.filter((u) => u.includes("/api/content-scan"))).toEqual([]);
    expect(external).toEqual([]);
  });
});

// ── 2: operator — exact permission surface ─────────────────────────────────
test.describe("operator posture", () => {
  test.use({ storageState: EMPTY_STATE });
  test("operator gets the DPI pattern surface and nothing admin-only", async ({
    page,
  }) => {
    await page.goto(ROUTE);
    await login(page, USERS.operator.user, USERS.operator.pass);
    await expect(page.getByText("Scan engine").first()).toBeVisible();

    await page.getByRole("tab", { name: "DPI" }).click();
    await expect(page.getByText("Signature patterns")).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Add pattern" }),
    ).toBeVisible();
    // Bypass replace is Admin-only: read-only presentation, no editor.
    await expect(page.getByText("Bypass hosts").first()).toBeVisible();
    await expect(page.locator("textarea")).toHaveCount(0);

    await page.getByRole("tab", { name: "Threat Intelligence" }).click();
    await expect(page.getByText("Feed synchronization")).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Sync feeds now" }),
    ).toHaveCount(0);

    await page.getByRole("tab", { name: "Exclusions & Cache" }).click();
    await expect(page.getByText("Scan exclusions").first()).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Save exclusions" }),
    ).toHaveCount(0);
  });
});

// ── 3 + 5 + 7: admin bypass round trip, fence refusal, alias non-use ───────
test("admin: reversible DPI bypass mutation with ceremony, stale fence refused, state restored", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.62");
  const before = await getBypass(api);
  const apiCalls = trackApiRequests(page);
  try {
    await page.goto(ROUTE);
    await page.getByRole("tab", { name: "DPI" }).click();
    await expect(page.getByText("Bypass hosts").first()).toBeVisible();
    const editor = page.getByLabel("DPI bypass hosts");
    await expect(editor).toBeVisible();

    // Safe reversible mutation: add one host through the T2 ceremony.
    await editor.fill([...before.hosts, "e2e-2ea-bypass.test"].join("\n"));
    await page.getByRole("button", { name: "Save DPI bypass hosts" }).click();
    await expect(
      page.getByText("Replace the DPI bypass host list"),
    ).toBeVisible();
    await expect(page.getByText("NOT inspected by DPI")).toBeVisible();
    // Register the wait BEFORE confirming: the first bypass GET after the
    // confirm is the page's own post-save refetch — once it lands, the
    // page's held revision is FIXED, so the racer below is deterministically
    // concurrent-stale (no timing dependence).
    const pageRefetch = page.waitForResponse(
      (r) =>
        r.url().includes("/api/dpi/bypass") &&
        r.request().method() === "GET" &&
        r.ok(),
    );
    await page
      .getByRole("button", { name: "Replace DPI bypass hosts" })
      .click();
    await expect
      .poll(async () => (await getBypass(api)).hosts)
      .toContain("e2e-2ea-bypass.test");
    await pageRefetch;

    // Stale concurrent write: another admin changes the list via the API;
    // the page still holds the pre-change revision, so its next save is the
    // structured 409 and NOTHING applies.
    const current = await getBypass(api);
    const put = await api.put("/api/dpi/bypass", {
      data: {
        hosts: [...current.hosts, "raced-writer.test"],
        ifRevision: current.revision,
      },
    });
    expect(put.ok()).toBe(true);
    const editor2 = page.getByLabel("DPI bypass hosts");
    await editor2.fill(
      [...before.hosts, "e2e-2ea-bypass.test", "stale-edit.test"].join("\n"),
    );
    await page.getByRole("button", { name: "Save DPI bypass hosts" }).click();
    await page
      .getByRole("button", { name: "Replace DPI bypass hosts" })
      .click();
    await expect(page.getByText("Not applied").first()).toBeVisible();
    await expect(
      page.getByText("changed on the appliance").first(),
    ).toBeVisible();
    const after = await getBypass(api);
    expect(after.hosts).not.toContain("stale-edit.test");
    expect(after.hosts).toContain("raced-writer.test");

    expect(apiCalls.filter((u) => u.includes("/api/content-scan"))).toEqual([]);
  } finally {
    // 9: restore the authoritative pre-test list (unfenced restore).
    await api.put("/api/dpi/bypass", { data: { hosts: before.hosts } });
    await api.dispose();
  }
});

// ── 4 + 6: YARA validate-only + destructive delete ceremony ────────────────
test("admin: YARA validate is validation-only; rule create + ceremonial delete reflect authoritative state", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.63");
  const RULE = "e2e2ea";
  const SRC = 'rule e2e_2ea { strings: $a = "e2e-2ea-token" condition: $a }';
  try {
    await page.goto(ROUTE);
    await page.getByRole("tab", { name: "YARA" }).click();
    await expect(page.getByText("Rule files").first()).toBeVisible();

    // Validate-only: run the dry run inside the create dialog, then CANCEL.
    await page.getByRole("button", { name: "New rule file…" }).click();
    await page
      .getByLabel("File name (stem, no extension)")
      .fill(`${RULE}-validated-only`);
    await page.getByLabel("Rule source").fill(SRC);
    await page.getByRole("button", { name: "Validate (dry run)" }).click();
    await expect(page.getByText("Valid — defines 1 rule")).toBeVisible();
    await expect(
      page.getByText("nothing was saved, loaded, or activated"),
    ).toBeVisible();
    await page.getByRole("button", { name: "Cancel" }).click();
    const listAfterValidate = await api.get("/api/security-scan/yara/rules");
    const inv1: unknown = await listAfterValidate.json();
    if (!isRecord(inv1) || !Array.isArray(inv1["files"])) {
      throw new Error("bad yara inventory");
    }
    expect(inv1["files"]).not.toContain(`${RULE}-validated-only`);

    // Create for real, then delete through the ceremony.
    await page.getByRole("button", { name: "New rule file…" }).click();
    await page.getByLabel("File name (stem, no extension)").fill(RULE);
    await page.getByLabel("Rule source").fill(SRC);
    await page.getByRole("button", { name: "Create rule file" }).click();
    await expect(page.getByText(RULE).first()).toBeVisible();

    await page
      .getByRole("button", { name: `Delete rule file ${RULE}` })
      .click();
    await expect(page.getByText(`Delete YARA rule file ${RULE}`)).toBeVisible();
    await expect(page.getByText("no longer be blocked by YARA")).toBeVisible();
    // 2E-A-2 §3: the ceremony is bound to the authoritative reviewed revision
    // (the confirm control only takes its final name once the review loaded)
    // and the DELETE must assert it on the wire.
    await expect(page.getByText("bound to the current version")).toBeVisible();
    const deleteReq = page.waitForRequest(
      (req) =>
        req.method() === "DELETE" &&
        req.url().includes("/api/security-scan/yara/rules/") &&
        req.url().includes("ifRevision="),
    );
    await page
      .getByRole("button", { name: "Delete rule file", exact: true })
      .click();
    await deleteReq;

    // Authoritative result after refresh: the file is gone.
    await expect
      .poll(async () => {
        const resp = await api.get("/api/security-scan/yara/rules");
        const v: unknown = await resp.json();
        return isRecord(v) && Array.isArray(v["files"]) ? v["files"] : null;
      })
      .not.toContain(RULE);
    await page.getByRole("button", { name: "Refresh" }).first().click();
    await expect(
      page.getByRole("cell", { name: RULE, exact: true }),
    ).toHaveCount(0);
  } finally {
    // 9: remove anything the test may have left behind.
    await api.delete(`/api/security-scan/yara/rules/${RULE}`);
    await api.delete(`/api/security-scan/yara/rules/${RULE}-validated-only`);
    await api.dispose();
  }
});

// ── 8: no external feed infrastructure; sync answers its truthful refusal ──
test("admin: manual feed sync is truthful with feeds disabled; zero external requests", async ({
  page,
}) => {
  const external = trackExternal(page);
  await page.goto(ROUTE);
  await page.getByRole("tab", { name: "Threat Intelligence" }).click();
  await expect(page.getByText("Feed synchronization")).toBeVisible();
  await page.getByRole("button", { name: "Sync feeds now" }).click();
  // The appliance has no threat feeds enabled: the imperative action answers
  // its truthful refusal (503) and the page shows the failure — it never
  // invents a healthy sync and never dials a public feed.
  await expect(page.getByText("Sync failed")).toBeVisible();
  await expect(page.getByText("threat feeds not enabled")).toBeVisible();
  expect(external).toEqual([]);
});
