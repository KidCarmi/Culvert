// FE-4 browser qualification (§24): the Snapshot Operations & Monitor round
// against the real Go binary and the committed production dist. Proves the
// ADR-FE-002 product decision end-to-end:
//   * Overview is snapshot-only — one fetch set, manual Refresh, honest
//     freshness ("Updated" advances ONLY on success; a failed refresh keeps
//     the previous snapshot behind an explicit stale indicator).
//   * Traffic is a query console over the keyset-cursor contract — seeded
//     real POLICY_DEFAULT_DENY history, server-side filters, Previous/Next
//     cursor paging with distinct pages, deep-linkable safe query state,
//     truthful empty state, and superseded-query cancellation.
//   * History availability is truthful (FRESH appliance has no store).
//   * Audit is bounded time-windowed pages; Diagnostics snapshot carries
//     operator_action first-class and active runs fire only on explicit
//     operator action; Governance is admin-only with a server-authoritative
//     error state for the viewer.
//   * ZERO /api/events traffic anywhere (§16), zero external requests, zero
//     unexpected console/page errors, strict CSP untouched.
import { expect } from "@playwright/test";
import { test } from "./test";
import type { Page } from "@playwright/test";
import { AUTH_URL, EMPTY_STATE, FRESH_URL, USERS } from "./fixtures";

// Chromium logs a console error line for any 4xx/5xx resource fetch; the
// suite exercises real role boundaries (403) and expected auth probes
// (401/429) plus rate-limit/5xx noise tolerated by the FE-3 suites.
const TOLERATED = [/Failed to load resource: .* status of (401|403|429|500)/];

interface Watch {
  errors: string[];
  external: string[];
  sse: string[];
}

function watch(page: Page, base: string, extraTolerated: RegExp[] = []): Watch {
  const tolerated = [...TOLERATED, ...extraTolerated];
  const errors: string[] = [];
  const external: string[] = [];
  const sse: string[] = [];
  const origin = new URL(base).origin;
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    const text = m.text();
    if (tolerated.some((re) => re.test(text))) return;
    errors.push(text);
  });
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.origin !== origin) external.push(r.url());
    // §16: the v2 client must never consume the SSE surface.
    if (u.pathname.startsWith("/api/events")) sse.push(r.url());
  });
  return { errors, external, sse };
}

function assertClean(w: Watch): void {
  expect(w.errors).toEqual([]);
  expect(w.external).toEqual([]);
  expect(w.sse).toEqual([]);
}

async function noHorizontalOverflow(page: Page): Promise<void> {
  const overflow = await page.evaluate(
    () =>
      document.documentElement.scrollWidth -
      document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(0);
}

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}

// ── Overview (§9/§10/§17) ─────────────────────────────────────────────────

test("overview loads one snapshot set, manual refresh advances freshness, zero SSE", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto("/app/");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("Management health")).toBeVisible();
  await expect(
    page.getByText("Traffic counters — since process start"),
  ).toBeVisible();
  await expect(
    page.getByText("Requests per minute — last 60 minutes", { exact: true }),
  ).toBeVisible();
  const updated = page.getByText(/^Updated \d\d:\d\d:\d\d$/);
  await expect(updated).toBeVisible();
  const before = await updated.textContent();

  // Manual Refresh: freshness advances only via the operator's action. The
  // display granularity is one second, so cross a second boundary first.
  await page.waitForTimeout(1100);
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect
    .poll(async () => updated.textContent(), { timeout: 5000 })
    .not.toBe(before);
  await expect(page.getByText("Management health")).toBeVisible();
  assertClean(w);
});

test("failed refresh keeps the previous snapshot and never fakes freshness", async ({
  page,
  baseURL,
}) => {
  // An aborted fetch surfaces as ERR_FAILED console noise — expected here.
  const w = watch(page, baseURL ?? AUTH_URL, [/net::ERR_FAILED/]);
  await page.goto("/app/");
  await expect(page.getByText("Management health")).toBeVisible();
  const updated = page.getByText(/^Updated \d\d:\d\d:\d\d$/);
  const before = await updated.textContent();

  // Network fixture over the real instance: the next stats read fails.
  await page.route(
    (u) => u.pathname === "/api/stats",
    (route) => route.abort(),
  );
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(
    page.getByText("Refresh failed — showing previous snapshot"),
  ).toBeVisible();
  // Previous snapshot stays on screen; "Updated" did NOT advance (§17).
  await expect(page.getByText("Management health")).toBeVisible();
  expect(await updated.textContent()).toBe(before);

  // Recovery: a later successful refresh clears the stale indicator.
  await page.unrouteAll();
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(
    page.getByText("Refresh failed — showing previous snapshot"),
  ).toBeHidden();
  assertClean(w);
});

// ── Traffic query console (§4–§8, §20 in-browser half) ────────────────────

test("traffic: bounded default query over seeded history, cursor paging with distinct pages", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto("/app/monitor/traffic");
  await expect(page.getByRole("heading", { name: "Traffic" })).toBeVisible();

  // Page 1: newest-first, bounded to the server page size (100 of 150 seeds).
  await expect(page.getByText("fe4-seed-149.test")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(100);
  await expect(
    page.getByText("100 results — more results available"),
  ).toBeVisible();
  // Seeded entries carry the real Zero-Trust verdict (scoped to the table —
  // the Status filter's <option> also carries this text).
  await expect(
    page.locator("tbody").getByText("POLICY_DEFAULT_DENY").first(),
  ).toBeVisible();

  // Next: page 2 is a DIFFERENT slice (no fake exact totals anywhere).
  // Cross an epoch-second boundary first: the applied window is FROZEN per
  // query, so a later click must reuse the cursor's exact from/to — a
  // per-render re-resolved window would 400 the fingerprint-bound cursor.
  await page.waitForTimeout(1100);
  await page.getByRole("button", { name: "Next" }).click();
  await expect(page.getByText("(page 2)")).toBeVisible();
  await expect(page.getByText("fe4-seed-49.test")).toBeVisible();
  await expect(page.getByText("fe4-seed-149.test")).toBeHidden();
  // 151 seeded entries since 2A (150 default-deny + the rule-hit block that
  // backs the Traffic → Policy deep-link proof): page 2 carries the tail 51.
  await expect(page.locator("tbody tr")).toHaveCount(51);
  // End of history: Next disables instead of inventing a page count.
  await expect(page.getByRole("button", { name: "Next" })).toBeDisabled();

  // Previous returns to page 1.
  await page.getByRole("button", { name: "Previous" }).click();
  await expect(page.getByText("fe4-seed-149.test")).toBeVisible();
  await expect(page.getByText("(page 2)")).toBeHidden();

  // Row detail expansion carries the full record (URI only here, never in
  // the table).
  await page
    .getByRole("button", { name: /Details for fe4-seed-149\.test/ })
    .click();
  await expect(page.getByText("Full URI")).toBeVisible();
  await expect(page.getByText("Bytes sent / received")).toBeVisible();
  assertClean(w);
});

test("traffic: draft→Apply server-side filters, deep-link reload, empty state, range validation", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto("/app/monitor/traffic");
  await expect(page.getByText("fe4-seed-149.test")).toBeVisible();

  // Draft edits run nothing until Apply (no per-keystroke queries).
  await page.getByLabel("Host / IP contains").fill("fe4-seed-1.");
  await page.getByLabel("Status").selectOption("POLICY_DEFAULT_DENY");
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(page.getByText("1 results")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(1);
  await expect(page.getByText("fe4-seed-1.test")).toBeVisible();
  // Safe query state landed in the URL (cursor deliberately NOT included).
  expect(page.url()).toContain("filter=fe4-seed-1.");
  expect(page.url()).toContain("status=POLICY_DEFAULT_DENY");
  expect(page.url()).not.toContain("cursor");

  // Deep-link reload: the applied query is reconstructed from the URL and
  // re-executed at page 1.
  await page.reload();
  await expect(page.getByRole("heading", { name: "Traffic" })).toBeVisible();
  await expect(page.getByLabel("Host / IP contains")).toHaveValue(
    "fe4-seed-1.",
  );
  await expect(page.getByLabel("Status")).toHaveValue("POLICY_DEFAULT_DENY");
  await expect(page.getByText("1 results")).toBeVisible();
  await expect(page.getByText("(page")).toBeHidden();

  // Truthful empty state — an empty page is not an error.
  await page.getByLabel("Host / IP contains").fill("no-such-host-zzz");
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(page.getByText("No matching requests")).toBeVisible();

  // Custom range validation: both bounds required, from < to (§4).
  await page.getByLabel("Time range").selectOption("custom");
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(
    page.getByText("Custom range requires both a start and an end time."),
  ).toBeVisible();
  await page.getByLabel("From").fill("2026-08-22T10:00");
  await page.getByLabel("To").fill("2026-08-22T09:00");
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(
    page.getByText("The start of the range must be before its end."),
  ).toBeVisible();
  assertClean(w);
});

test("traffic: a superseded in-flight query is cancelled and never overwrites the newer result", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL, [/net::ERR_(FAILED|ABORTED)/]);
  const cancelled: string[] = [];
  page.on("requestfailed", (r) => {
    if (r.url().includes("slow-marker")) cancelled.push(r.url());
  });
  // Delay only the query this test supersedes; everything else is live.
  await page.route(
    (u) => u.pathname === "/api/logs",
    async (route) => {
      if (route.request().url().includes("slow-marker")) {
        await new Promise((r) => setTimeout(r, 1500));
        try {
          await route.continue();
        } catch {
          // request already aborted — exactly the behavior under test
        }
        return;
      }
      await route.continue();
    },
  );
  await page.goto("/app/monitor/traffic");
  await expect(page.getByText("fe4-seed-149.test")).toBeVisible();

  await page.getByLabel("Host / IP contains").fill("slow-marker");
  await page.getByRole("button", { name: "Apply" }).click();
  // Supersede the in-flight query immediately.
  await page.getByLabel("Host / IP contains").fill("fe4-seed-149.test");
  await page.getByRole("button", { name: "Apply" }).click();

  await expect(page.getByText("1 results")).toBeVisible();
  await expect(page.getByText("fe4-seed-149.test")).toBeVisible();
  // The superseded request was aborted at the network layer (FE-3 §18
  // teardown contract carried into FE-4 queries).
  await expect
    .poll(() => cancelled.length, { timeout: 5000 })
    .toBeGreaterThan(0);
  // Even after the slow window elapses, the newer result stands.
  await page.waitForTimeout(2000);
  await expect(page.getByText("1 results")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(1);
  assertClean(w);
});

test("traffic: a scan-limited segment is never a terminal empty state and Continue searches on", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  // Network fixture over the REAL response: the first page is rewritten to
  // report a scan-limited empty segment carrying the REAL continuation
  // cursor; the continuation request passes through to the live backend.
  let patched = false;
  await page.route(
    (u) => u.pathname === "/api/logs",
    async (route) => {
      const url = new URL(route.request().url());
      if (url.searchParams.get("cursor") === "" && !patched) {
        patched = true;
        const resp = await route.fetch();
        const body: unknown = await resp.json();
        const rec =
          typeof body === "object" && body !== null && !Array.isArray(body)
            ? body
            : {};
        await route.fulfill({
          response: resp,
          json: { ...rec, logs: [], has_more: true, scan_limited: true },
        });
        return;
      }
      await route.continue();
    },
  );
  await page.goto("/app/monitor/traffic");

  // Honest partial-segment state — NOT the terminal empty state.
  await expect(
    page.getByText("No matches in this scanned segment"),
  ).toBeVisible();
  await expect(page.getByText("No matching requests")).toBeHidden();
  await expect(
    page.getByText(/0 results in this scan segment — more retained history/),
  ).toBeVisible();

  // Continuation is explicit and bounded: ONE click issues ONE follow-up
  // query (no auto-chaining), which reaches real history. The crossed
  // second boundary pins the frozen-window contract (cursor from/to reuse).
  await page.waitForTimeout(1100);
  await page.getByRole("button", { name: "Continue search" }).click();
  await expect(page.getByText("fe4-seed-49.test")).toBeVisible();
  await expect(page.getByText("(page 2)")).toBeVisible();
  assertClean(w);
});

// ── Truthful history availability (§8) — FRESH appliance, no store ────────

test.describe("history-disabled appliance", () => {
  test.use({ storageState: EMPTY_STATE });

  test("traffic tells the truth when persistent history is disabled", async ({
    page,
  }) => {
    const w = watch(page, FRESH_URL);
    // Deep link carries route intent through login (fe3-setup configured
    // this appliance with root-admin earlier in the suite).
    await page.goto(`${FRESH_URL}/app/monitor/traffic`);
    await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
    await login(page, "root-admin", "StrongPass123");
    await expect(page.getByRole("heading", { name: "Traffic" })).toBeVisible();

    // Enforce this test's premise through the supported admin API: dataDir
    // is the fixed absolute /data shared by every harness instance on the
    // machine, so an admin-settings save from ANY instance in a PREVIOUS
    // run (e.g. the 2A draft fixture on the AUTH appliance, whose store is
    // enabled) can persist log_store_enabled=true and silently re-enable a
    // history store on this "store-less" appliance at boot. CI runners are
    // ephemeral and never see this; a long-lived dev machine does.
    const off = await page.request.put(`${FRESH_URL}/api/logs/retention`, {
      data: { enabled: false },
    });
    expect(off.ok()).toBe(true);
    await page.goto(`${FRESH_URL}/app/monitor/traffic`);
    await expect(page.getByRole("heading", { name: "Traffic" })).toBeVisible();

    // Degraded ≠ error ≠ empty: the disabled store is a first-class state.
    await expect(
      page.getByText("Persistent history is disabled"),
    ).toBeVisible();
    await expect(page.getByText("Query failed")).toBeHidden();
    await expect(page.getByText("No matching requests")).toBeHidden();

    // The memory fallback is an EXPLICIT choice and clearly labelled as a
    // different, volatile source — never silently substituted.
    await page
      .getByRole("button", { name: "Query recent memory instead" })
      .click();
    await expect(
      page.getByText(/Showing the in-memory RECENT ring \(0 of 0 matches\)/),
    ).toBeVisible();
    await expect(page.locator("tbody tr")).toHaveCount(0);
    assertClean(w);
  });
});

// ── Audit (§11/§12) ───────────────────────────────────────────────────────

test("audit: bounded window, pagination controls, detail expansion", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto("/app/monitor/audit");
  await expect(page.getByRole("heading", { name: "Audit Log" })).toBeVisible();

  // The suite's own logins are audited — the default 24h window has rows.
  await expect(
    page.getByText(/Page 1 of \d+ · \d+ matching entries/),
  ).toBeVisible();
  const rows = await page.locator("tbody tr").count();
  expect(rows).toBeGreaterThan(0);
  expect(rows).toBeLessThanOrEqual(100); // never an unbounded dump
  await expect(page.getByRole("button", { name: "Previous" })).toBeDisabled();

  // Detail expansion renders text-only before/after + object id.
  await page.locator("tbody tr").first().getByRole("button").click();
  await expect(page.getByText("Object ID")).toBeVisible();

  // Time range narrows server-side (the suite logged in minutes ago).
  await page.getByLabel("Time range").selectOption("15m");
  await page.getByRole("button", { name: "Apply" }).click();
  await expect(
    page.getByText(/Page 1 of \d+ · \d+ matching entries/),
  ).toBeVisible();
  assertClean(w);
});

// ── Diagnostics (§13/§14) ─────────────────────────────────────────────────

test("diagnostics: snapshot with first-class operator_action; explicit run only", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  const diagnoseCalls: string[] = [];
  page.on("request", (r) => {
    if (new URL(r.url()).pathname.startsWith("/api/diagnose/"))
      diagnoseCalls.push(r.url());
  });
  await page.goto("/app/diagnostics");
  await expect(
    page.getByRole("heading", { name: "Diagnostics" }),
  ).toBeVisible();

  // The AUTH appliance runs default-auth Exempt, so the operator contract
  // deterministically carries a WARN row with its operator_action.
  await expect(page.getByText("default_auth_open")).toBeVisible();
  await expect(
    page.getByText(/Set default authentication to Require under Settings/),
  ).toBeVisible();

  // Loading the page ran NO active diagnostic (§14: explicit action only).
  expect(diagnoseCalls).toEqual([]);

  // Explicit runs as admin. The full fixed backend verb registry is
  // exposed (storage/upstream/dns/tls/cluster/etcd/config/support/all).
  await expect(page.getByText("Run a diagnostic")).toBeVisible();
  await expect(
    page.getByRole("group", { name: "Diagnostic" }).getByRole("button"),
  ).toHaveCount(9);

  // storage: per-verb decoded, deliberately presented (summary + checks).
  await page.getByRole("button", { name: "Run storage diagnostic" }).click();
  await expect(page.getByText("Data directory", { exact: true })).toBeVisible();
  expect(diagnoseCalls.length).toBe(1);

  // support: explicitly runnable, decoded through its own contract.
  await page.getByRole("button", { name: "support", exact: true }).click();
  await page.getByRole("button", { name: "Run support diagnostic" }).click();
  await expect(page.getByText("Pending approval")).toBeVisible();
  expect(diagnoseCalls.length).toBe(2);

  // all: nested sub-results render as deliberate sections, not a dump.
  await page.getByRole("button", { name: "all", exact: true }).click();
  await page.getByRole("button", { name: "Run all diagnostic" }).click();
  await expect(page.getByText("Verbs aggregated")).toBeVisible();
  await expect(page.getByRole("heading", { name: "cluster" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "config" })).toBeVisible();
  expect(diagnoseCalls.length).toBe(3);
  assertClean(w);
});

// ── Governance (§15) + viewer role boundaries ─────────────────────────────

test("governance: admin sees enforcement posture and counters", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto("/app/governance");
  await expect(page.getByRole("heading", { name: "Governance" })).toBeVisible();
  await expect(page.getByText("Enforcement posture")).toBeVisible();
  await expect(page.getByText("enforce (fail-closed)")).toBeVisible();
  await expect(
    page.getByText("Enforcement counters (since start)"),
  ).toBeVisible();
  await expect(page.getByText("would_deny").first()).toBeVisible();
  await expect(page.getByText("role_divergence").first()).toBeVisible();
  assertClean(w);
});

test.describe("viewer boundaries", () => {
  test.use({ storageState: EMPTY_STATE });

  test("viewer: no run-diagnostic card, no governance nav, server-authoritative 403", async ({
    page,
    baseURL,
  }) => {
    const w = watch(page, baseURL ?? AUTH_URL);
    await page.goto("/app/");
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    await expect(
      page.getByRole("heading", { name: "Dashboard" }),
    ).toBeVisible();

    // Role-aware nav: Monitor surfaces present, Governance absent.
    await expect(page.getByRole("link", { name: "Diagnostics" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Governance" })).toHaveCount(0);

    // Diagnostics snapshot is viewer-readable; active runs are not offered.
    await page.getByRole("link", { name: "Diagnostics" }).click();
    await expect(page.getByText("default_auth_open")).toBeVisible();
    await expect(page.getByText("Run a diagnostic")).toHaveCount(0);

    // Direct navigation cannot bypass the server: the admin-only snapshot
    // fails closed into the explicit error state (no data, no crash).
    await page.goto("/app/governance");
    await expect(
      page.getByText("Governance snapshot unavailable"),
    ).toBeVisible();
    await expect(page.getByText("Enforcement posture")).toHaveCount(0);
    assertClean(w);
  });
});

// ── Viewport / zoom reflow (§24) ──────────────────────────────────────────

test("monitor surfaces reflow at 1024×768 and 640×800 (≈200% zoom)", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.setViewportSize({ width: 1024, height: 768 });
  await page.goto("/app/monitor/traffic");
  await expect(page.getByText("fe4-seed-149.test")).toBeVisible();
  await noHorizontalOverflow(page);

  await page.setViewportSize({ width: 640, height: 800 });
  await page.reload();
  await expect(page.getByRole("heading", { name: "Traffic" })).toBeVisible();
  await noHorizontalOverflow(page);

  await page.goto("/app/monitor/audit");
  await expect(page.getByRole("heading", { name: "Audit Log" })).toBeVisible();
  await noHorizontalOverflow(page);

  await page.goto("/app/");
  await expect(page.getByText("Management health")).toBeVisible();
  await noHorizontalOverflow(page);
  assertClean(w);
});
