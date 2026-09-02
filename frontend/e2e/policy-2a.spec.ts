// Slice 2A real-binary browser qualification (directive §28). Against the
// real CULVERT binary + committed production dist, on the AUTH appliance
// whose -policy fixture loads 502 Stage-2 access rules (incl. the
// deterministic "E2E Match Rule" behind the seeded rule-hit.test history
// entry) + 2 valid Stage-1 auth rules. Globally per test: zero unexpected
// console/page errors, zero external-origin requests, zero /api/events
// requests (ADR-FE-002).
import { expect } from "@playwright/test";
import { test } from "./test";
import type { Page } from "@playwright/test";
import { AUTH_URL, EMPTY_STATE, USERS } from "./fixtures";

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
    if (u.pathname.startsWith("/api/events")) sse.push(r.url());
  });
  return { errors, external, sse };
}

function assertClean(w: Watch): void {
  expect(w.errors).toEqual([]);
  expect(w.external).toEqual([]);
  expect(w.sse).toEqual([]);
}

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}

interface ApiRule {
  id: string;
  name: string;
  priority: number;
  hitCount: number;
  ruleType?: string;
}

interface ApiPolicy {
  rules: ApiRule[];
  version: number;
  draft: boolean;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Test-side read of the policy envelope (harness introspection only — the
// app itself always goes through the runtime decoders). Narrowed without
// casts, per the contract §7.T1 lint wall.
function readPolicy(v: unknown): ApiPolicy {
  if (!isRecord(v)) throw new Error("bad /api/policy payload");
  const rulesRaw = v["rules"];
  const version = v["version"];
  const draft = v["draft"];
  if (
    !Array.isArray(rulesRaw) ||
    typeof version !== "number" ||
    typeof draft !== "boolean"
  ) {
    throw new Error("bad /api/policy envelope");
  }
  const rules: ApiRule[] = rulesRaw.map((r: unknown) => {
    if (!isRecord(r)) throw new Error("bad rule row");
    const id = r["id"];
    const name = r["name"];
    const priority = r["priority"];
    const hitCount = r["hitCount"];
    const ruleType = r["ruleType"];
    const out: ApiRule = {
      id: typeof id === "string" ? id : "",
      name: typeof name === "string" ? name : "",
      priority: typeof priority === "number" ? priority : 0,
      hitCount: typeof hitCount === "number" ? hitCount : 0,
    };
    if (typeof ruleType === "string") out.ruleType = ruleType;
    return out;
  });
  return { rules, version, draft };
}

async function apiPolicy(page: Page): Promise<ApiPolicy> {
  const resp = await page.request.get("/api/policy");
  expect(resp.ok()).toBe(true);
  return readPolicy(await resp.json());
}

async function ruleByName(page: Page, name: string): Promise<ApiRule> {
  const pol = await apiPolicy(page);
  const rule = pol.rules.find((r) => r.name === name);
  if (rule === undefined) throw new Error(`fixture rule ${name} must exist`);
  return rule;
}

const RULES_HEADING = { name: "Access Rules" };

// ── Flows 1–3: all three roles get the same read surface ──────────────────

for (const who of ["viewer", "operator"] as const) {
  test.describe(`${who} access`, () => {
    test.use({ storageState: EMPTY_STATE });
    test(`${who} → Access Rules renders the read surface (viewer without mutation controls)`, async ({
      page,
      baseURL,
    }) => {
      const w = watch(page, baseURL ?? AUTH_URL);
      await page.goto("/app/policies/access-rules");
      await login(page, USERS[who].user, USERS[who].pass);
      await expect(
        page.getByRole("heading", RULES_HEADING).first(),
      ).toBeVisible();
      await expect(page.getByText("of 502 access rules")).toBeVisible();
      await expect(page.getByText("Live-write mode")).toBeVisible();
      if (who === "viewer") {
        // Viewer mounts NO mutation affordances (2B posture: absent, not
        // disabled). Operator+ write flows are proven in policy-2b.spec.ts.
        await expect(
          page.getByRole("button", {
            name: /delete|edit|create|commit|revert/i,
          }),
        ).toHaveCount(0);
      } else {
        await expect(
          page.getByRole("button", { name: "New rule…" }),
        ).toBeVisible();
      }
      assertClean(w);
    });
  });
}

test("admin → Access Rules renders the same read surface (server order preserved)", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto("/app/policies/access-rules");
  await expect(page.getByRole("heading", RULES_HEADING).first()).toBeVisible();
  await expect(page.getByText("502 of 502 access rules")).toBeVisible();

  // Server priority order preserved: the first data rows are priorities 1, 5,
  // 10 in that order (evaluation order is load-bearing — §6).
  const priorities = await page
    .locator("tbody tr td:nth-child(2)")
    .allInnerTexts();
  const nums = priorities
    .map((t) => Number(t))
    .filter((n) => Number.isFinite(n));
  expect(nums.slice(0, 3)).toEqual([1, 5, 10]);
  const sorted = [...nums].sort((a, b) => a - b);
  expect(nums).toEqual(sorted);
  assertClean(w);
});

// ── Flow 4: Stage-1 auth rules never leak into Access Rules ───────────────

test("Stage-1 auth rules are absent from the Access Rules table", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  // The fixture proves the envelope really carries them…
  const pol = await apiPolicy(page);
  expect(pol.rules.filter((r) => r.ruleType === "auth")).toHaveLength(2);
  // …and the surface really excludes them.
  await page.goto("/app/policies/access-rules");
  await expect(page.getByText("502 of 502 access rules")).toBeVisible();
  await expect(page.getByText("E2E Auth Exempt")).toHaveCount(0);
  await expect(
    page.getByText(
      "2 authentication rules managed on the Authentication Rules surface",
    ),
  ).toBeVisible();
  assertClean(w);
});

// ── Flows 6–7: snapshot model ─────────────────────────────────────────────

test("manual Refresh advances freshness; failed Refresh preserves the previous snapshot", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL, [/ERR_FAILED/]);
  await page.goto("/app/policies/access-rules");
  await expect(page.getByText("502 of 502 access rules")).toBeVisible();
  const updated = page.getByText(/^Updated \d\d:\d\d:\d\d$/);
  await expect(updated).toBeVisible();
  const first = await updated.innerText();

  // Manual refresh (crossing a second boundary so the clock text can move).
  await page.waitForTimeout(1100);
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(updated).toBeVisible();
  await expect(updated).not.toHaveText(first);
  const second = await updated.innerText();

  // Failed refresh: the old rulebase and its freshness stamp stay, behind an
  // explicit stale indicator.
  await page.route("**/api/policy", (route) => route.abort());
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(
    page.getByText("Refresh failed — showing previous snapshot"),
  ).toBeVisible();
  await expect(page.getByText("502 of 502 access rules")).toBeVisible();
  await expect(updated).toHaveText(second);
  await page.unrouteAll();
  assertClean(w);
});

// ── Flows 8–9: filter + row detail ────────────────────────────────────────

test("filter narrows without reordering; clearing restores; row detail expands", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto("/app/policies/access-rules");
  await expect(page.getByText("502 of 502 access rules")).toBeVisible();

  await page.getByLabel("Filter").fill("Bulk rule 500");
  await expect(page.getByText("1 of 502 access rules")).toBeVisible();
  await expect(page.getByText("Bulk rule 500")).toBeVisible();

  await page.getByLabel("Filter").fill("");
  await expect(page.getByText("502 of 502 access rules")).toBeVisible();

  // Row detail: secondary metadata incl. the stable Rule ID and references.
  const matchRule = await ruleByName(page, "E2E Reference Rule");
  await page
    .getByRole("button", { name: "Details for rule E2E Reference Rule" })
    .click();
  await expect(page.getByText("Rule ID", { exact: true })).toBeVisible();
  await expect(page.getByText(matchRule.id)).toBeVisible();
  await expect(page.getByText("Where-used fixture")).toBeVisible();
  assertClean(w);
});

// ── Flow 15: Where Used against real reference data ───────────────────────

test("Where Used fetches on explicit interest and lists the real referencing rule", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto("/app/policies/access-rules");
  await expect(page.getByText("502 of 502 access rules")).toBeVisible();

  const refRequests: string[] = [];
  page.on("request", (r) => {
    if (r.url().includes("/api/objects/references")) refRequests.push(r.url());
  });

  await page
    .getByRole("button", { name: "Details for rule E2E Reference Rule" })
    .click();
  // Opening the detail row fires NO reference queries (§18).
  expect(refRequests).toHaveLength(0);

  await page.getByRole("button", { name: /Where used: File profile/ }).click();
  // Both fixture rules reference the "Executables" file profile; each is an
  // access-rule consumer deep-linked by its stable ID.
  await expect(page.getByText(/is referenced by 2 consumers/)).toBeVisible();
  const refPanelLink = page.getByRole("link", { name: "E2E Reference Rule" });
  await expect(refPanelLink).toBeVisible();
  await expect(
    page.getByRole("link", { name: "E2E Match Rule" }),
  ).toBeVisible();
  expect(refRequests).toHaveLength(1);
  assertClean(w);
});

// ── Deep-link navigation correction: filter-hidden target via a REAL
//    Where Used link (same mounted route, no document reload), A → B → A,
//    and stale-state cleanup ─────────────────────────────────────────────

test("a new deep link overrides the active filter via a real Where Used link; A → B → A re-locates", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  const ruleA = await ruleByName(page, "E2E Reference Rule");
  const ruleB = await ruleByName(page, "E2E Match Rule");

  await page.goto("/app/policies/access-rules");
  await expect(page.getByText("502 of 502 access rules")).toBeVisible();

  // Filter to A only — the future target B is now hidden from the table.
  await page.getByLabel("Filter").fill("E2E Reference");
  await expect(page.getByText("1 of 502 access rules")).toBeVisible();
  await expect(page.getByText("E2E Match Rule")).toHaveCount(0);

  // Real in-app path: A's detail → Where Used → click the OTHER access-rule
  // consumer (B). Same React route; only the ?rule= query changes.
  await page
    .getByRole("button", { name: "Details for rule E2E Reference Rule" })
    .click();
  await page.getByRole("button", { name: /Where used: File profile/ }).click();
  await page.getByRole("link", { name: "E2E Match Rule" }).click();

  // URL carries B's stable ID; the filter was reset by the navigation; B's
  // row exists, is fully in viewport, holds focus, is highlighted; and the
  // announcement names B.
  await expect(page).toHaveURL(
    new RegExp(`/app/policies/access-rules\\?rule=${ruleB.id}`),
  );
  const highlighted = page.locator('tr[data-highlight="true"]');
  await expect(highlighted).toHaveCount(1);
  await expect(highlighted).toContainText("E2E Match Rule");
  await expect(page.getByLabel("Filter")).toHaveValue("");
  // "Fully visible" for a row inside the horizontally-scrollable table means
  // the row intersects the viewport and its FULL HEIGHT is inside it (the
  // row is deliberately wider than the viewport — table-local x-scroll — so
  // an intersection ratio of 1 is unreachable by design).
  await expect(highlighted).toBeInViewport();
  const rowBox = await highlighted.boundingBox();
  const vp = page.viewportSize();
  expect(rowBox).not.toBeNull();
  expect(vp).not.toBeNull();
  if (rowBox !== null && vp !== null) {
    expect(rowBox.y).toBeGreaterThanOrEqual(0);
    expect(rowBox.y + rowBox.height).toBeLessThanOrEqual(vp.height);
  }
  await expect(highlighted).toBeFocused();
  await expect(page.getByRole("status").first()).toContainText(
    "Rule E2E Match Rule",
  );

  // B → A through the same real consumer path (B also carries the profile).
  await page
    .getByRole("button", { name: "Details for rule E2E Match Rule" })
    .click();
  await page.getByRole("button", { name: /Where used: File profile/ }).click();
  await page.getByRole("link", { name: "E2E Reference Rule" }).click();
  await expect(page).toHaveURL(
    new RegExp(`/app/policies/access-rules\\?rule=${ruleA.id}`),
  );
  await expect(highlighted).toHaveCount(1);
  await expect(highlighted).toContainText("E2E Reference Rule");
  await expect(highlighted).toBeFocused();
  await expect(page.getByRole("status").first()).toContainText(
    "Rule E2E Reference Rule",
  );

  // Back to B (history navigation — still no document reload): B highlights
  // and is announced again.
  await page.goBack();
  await expect(page).toHaveURL(
    new RegExp(`/app/policies/access-rules\\?rule=${ruleB.id}`),
  );
  await expect(highlighted).toHaveCount(1);
  await expect(highlighted).toContainText("E2E Match Rule");
  await expect(page.getByRole("status").first()).toContainText(
    "Rule E2E Match Rule",
  );
  assertClean(w);
});

// ── Flows 10–12 + 14: Policy Tester ───────────────────────────────────────

test("tester: no-match renders default action, running rulebase, and the full trace", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto("/app/policies/tester");
  await expect(
    page.getByRole("heading", { name: "Policy Tester" }).first(),
  ).toBeVisible();

  // Run test is gated on the required host; no request fires while typing.
  const testRequests: string[] = [];
  page.on("request", (r) => {
    if (r.url().includes("/api/policy/test")) testRequests.push(r.url());
  });
  await page.getByLabel("Host").fill("unmatched-xyz.test");
  expect(testRequests).toHaveLength(0);
  await page.getByRole("button", { name: "Run test" }).click();

  await expect(page.getByText("Running rulebase")).toBeVisible();
  await expect(page.getByText("No rule matched")).toBeVisible();
  await expect(page.getByText("Default action →")).toBeVisible();
  await expect(page.getByText("deny", { exact: true })).toBeVisible();
  // The trace explains every evaluated rule.
  await expect(
    page.getByRole("heading", { name: "Rule evaluation trace" }),
  ).toBeVisible();
  await expect(
    page.getByRole("cell", { name: "E2E Match Rule" }),
  ).toBeVisible();
  expect(testRequests).toHaveLength(1);
  assertClean(w);
});

test("tester: matched rule renders verdict + rulebase=running, and mutates NOTHING", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);

  // Before-state: version + the target rule's hit count.
  const before = await apiPolicy(page);
  const beforeRule = await ruleByName(page, "E2E Match Rule");

  // Any non-GET API call other than the dry-run POST is a violation.
  const mutations: string[] = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (!u.pathname.startsWith("/api/")) return;
    if (r.method() === "GET") return;
    if (u.pathname === "/api/policy/test") return;
    mutations.push(`${r.method()} ${u.pathname}`);
  });

  await page.goto("/app/policies/tester");
  await page.getByLabel("Host").fill("rule-hit.test");
  await page.getByRole("button", { name: "Run test" }).click();

  await expect(page.getByText("Running rulebase")).toBeVisible();
  await expect(page.getByText("Matched", { exact: true })).toBeVisible();
  await expect(page.getByText("E2E Match Rule").first()).toBeVisible();
  await expect(page.getByText("Block_Page").first()).toBeVisible();
  await expect(page.getByText("matched — evaluation stops")).toBeVisible();

  // After-state: no version bump, no hit-count change, no rule set change,
  // no mutating API call.
  const after = await apiPolicy(page);
  const afterRule = await ruleByName(page, "E2E Match Rule");
  expect(after.version).toBe(before.version);
  expect(after.rules.length).toBe(before.rules.length);
  expect(afterRule.hitCount).toBe(beforeRule.hitCount);
  expect(mutations).toEqual([]);
  assertClean(w);
});

// ── Flows 5 + 13: draft fixture truthfulness (staged candidate) ───────────

test("draft=true: Access Rules shows the candidate truth and the tester reports rulebase=draft", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  // Arm Draft Mode and stage one rule through the supported admin API
  // (test fixture mechanics — the 2A UI itself has no write surface).
  const arm = await page.request.put("/api/policy/draft", {
    data: { require_commit: true },
  });
  expect(arm.ok()).toBe(true);
  try {
    const stage = await page.request.post("/api/policy", {
      data: {
        name: "E2E Draft Probe",
        priority: 950,
        destFQDN: "draft-probe.test",
        action: "Block_Page",
        sslAction: "",
      },
    });
    expect(stage.ok()).toBe(true);
    expect((await apiPolicy(page)).draft).toBe(true);

    // Flow 5: the surface tells the candidate truth.
    await page.goto("/app/policies/access-rules");
    await expect(
      page.getByText("Editing the shared Policy Draft"),
    ).toBeVisible();
    await expect(
      page.getByText("Changes take effect only when the draft is committed."),
    ).toBeVisible();
    await expect(page.getByText("E2E Draft Probe")).toBeVisible();
    await expect(page.getByText("503 of 503 access rules")).toBeVisible();

    // Flow 13: the tester labels the tested set as the draft candidate.
    await page.goto("/app/policies/tester");
    await page.getByLabel("Host").fill("draft-probe.test");
    await page.getByRole("button", { name: "Run test" }).click();
    await expect(
      page.getByText("Policy Draft candidate").first(),
    ).toBeVisible();
    await expect(
      page.getByText("This tested the Policy Draft candidate"),
    ).toBeVisible();
    await expect(page.getByText("E2E Draft Probe").first()).toBeVisible();
  } finally {
    // Discard the staged fixture and disarm — the appliance returns to the
    // running-rulebase state for every later spec.
    await page.request.post("/api/policy/draft/revert");
    await page.request.put("/api/policy/draft", {
      data: { require_commit: false },
    });
  }
  expect((await apiPolicy(page)).draft).toBe(false);
  await page.goto("/app/policies/access-rules");
  await expect(page.getByText("Live-write mode")).toBeVisible();
  await expect(page.getByText("502 of 502 access rules")).toBeVisible();
  assertClean(w);
});

// ── Flows 16–17: Traffic → Policy deep link ───────────────────────────────

test("real Traffic ruleId deep-links to the exact highlighted Access Rule", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  const matchRule = await ruleByName(page, "E2E Match Rule");

  await page.goto("/app/monitor/traffic");
  // The rule-hit seed is the NEWEST history entry (page 1, default query),
  // and its row links by the real stable ULID recorded by the proxy.
  const ruleLink = page.getByRole("link", { name: "E2E Match Rule" });
  await expect(ruleLink.first()).toBeVisible();
  await ruleLink.first().click();

  await expect(page).toHaveURL(
    new RegExp(`/app/policies/access-rules\\?rule=${matchRule.id}`),
  );
  const highlighted = page.locator('tr[data-highlight="true"]');
  await expect(highlighted).toHaveCount(1);
  await expect(highlighted).toContainText("E2E Match Rule");
  assertClean(w);
});

test("stale/nonexistent ruleId gets the truthful not-in-snapshot callout", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto("/app/policies/access-rules?rule=01AAAAAAAAAAAAAAAAAAAAAAAA");
  await expect(
    page.getByText("Referenced rule not in this snapshot"),
  ).toBeVisible();
  await expect(
    page.getByText(
      "It may represent historical data or a rule outside the current effective Access Rules view.",
    ),
  ).toBeVisible();
  // It is NOT claimed deleted, the rulebase still renders normally, and no
  // row is highlighted next to the callout.
  await expect(page.getByText(/deleted/i)).toHaveCount(0);
  await expect(page.getByText("502 of 502 access rules")).toBeVisible();
  await expect(page.locator('tr[data-highlight="true"]')).toHaveCount(0);

  // Malformed parameter: its own truthful callout, and again no highlight.
  await page.goto("/app/policies/access-rules?rule=not%20a%20rule%3Cid%3E");
  await expect(page.getByText("Invalid rule reference")).toBeVisible();
  await expect(page.locator('tr[data-highlight="true"]')).toHaveCount(0);
  assertClean(w);
});

// ── Flow 18: 500-rule scale qualification ─────────────────────────────────

for (const vp of [
  { name: "1024x768", width: 1024, height: 768 },
  { name: "1440x900", width: 1440, height: 900 },
  { name: "zoom200-ish 640x800", width: 640, height: 800 },
]) {
  test(`scale: 502 rules interactive at ${vp.name}`, async ({
    page,
    baseURL,
  }) => {
    const w = watch(page, baseURL ?? AUTH_URL);
    await page.setViewportSize({ width: vp.width, height: vp.height });
    await page.goto("/app/policies/access-rules");
    await expect(page.getByText("502 of 502 access rules")).toBeVisible();
    await expect(page.locator("tbody tr")).toHaveCount(502);

    // Interaction budget: filter → visible result settles within 1 s.
    const t0 = Date.now();
    await page.getByLabel("Filter").fill("Bulk rule 250");
    await expect(page.getByText("1 of 502 access rules")).toBeVisible({
      timeout: 1000,
    });
    const filterMs = Date.now() - t0;
    await page.getByLabel("Filter").fill("");
    await expect(page.getByText("502 of 502 access rules")).toBeVisible({
      timeout: 1000,
    });

    // No page-level horizontal overflow; wide content scrolls table-locally.
    const overflow = await page.evaluate(
      () =>
        document.documentElement.scrollWidth -
        document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(0);

    // Keyboard interaction stays usable at scale: the first row's detail
    // toggle activates from the keyboard.
    const firstToggle = page
      .getByRole("button", { name: /Details for rule/ })
      .first();
    await firstToggle.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByText("Rule ID", { exact: true })).toBeVisible();

    test.info().annotations.push({
      type: "perf",
      description: `${vp.name}: filter settled in ${String(filterMs)}ms`,
    });
    assertClean(w);
  });
}

test("scale: deep link to a bottom rule reaches and highlights it within budget", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  const bottom = await ruleByName(page, "Bulk rule 500");
  await page.goto(
    `/app/policies/access-rules?rule=${encodeURIComponent(bottom.id)}`,
  );
  await expect(page.getByText("502 of 502 access rules")).toBeVisible();
  const t0 = Date.now();
  const highlighted = page.locator('tr[data-highlight="true"]');
  await expect(highlighted).toBeVisible({ timeout: 1000 });
  await expect(highlighted).toContainText("Bulk rule 500");
  await expect(highlighted).toBeInViewport();
  test.info().annotations.push({
    type: "perf",
    description: `deep-link highlight visible in ${String(Date.now() - t0)}ms after snapshot`,
  });
  assertClean(w);
});

// ── Flow 20: deep link + hard refresh ─────────────────────────────────────

test("deep link survives a hard refresh; in-memory filter state does not", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  const matchRule = await ruleByName(page, "E2E Match Rule");
  await page.goto(
    `/app/policies/access-rules?rule=${encodeURIComponent(matchRule.id)}`,
  );
  await expect(page.locator('tr[data-highlight="true"]')).toContainText(
    "E2E Match Rule",
  );
  await page.getByLabel("Filter").fill("Bulk");
  await expect(page.getByText("500 of 502 access rules")).toBeVisible();

  await page.reload();
  // The URL-borne rule intent resolves again; the memory-only filter reset.
  await expect(page.locator('tr[data-highlight="true"]')).toContainText(
    "E2E Match Rule",
  );
  await expect(page.getByLabel("Filter")).toHaveValue("");
  await expect(page.getByText("502 of 502 access rules")).toBeVisible();
  assertClean(w);
});

// ── Flow 19: authentication-boundary cancellation ─────────────────────────
// A FRESH operator login (never the shared admin storageState): signing out
// revokes the session token server-side, and revoking the suite-wide admin
// token would break every later spec that reuses it.

test.describe("auth-boundary cancellation", () => {
  test.use({ storageState: EMPTY_STATE });

  test("auth boundary aborts an in-flight tester run; no result crosses identities", async ({
    page,
    baseURL,
  }) => {
    // Aborted in-flight fetches surface as ERR_FAILED console noise — expected.
    const w = watch(page, baseURL ?? AUTH_URL, [/ERR_FAILED/, /ERR_ABORTED/]);
    await page.goto("/app/policies/tester");
    await login(page, USERS.operator.user, USERS.operator.pass);
    await expect(
      page.getByRole("heading", { name: "Policy Tester" }).first(),
    ).toBeVisible();

    // Hold the dry-run open client-side long enough to sign out through it.
    await page.route("**/api/policy/test", async (route) => {
      await new Promise((r) => setTimeout(r, 8000));
      await route.abort();
    });
    await page.getByLabel("Host").fill("boundary-probe.test");
    await page.getByRole("button", { name: "Run test" }).click();
    await expect(page.getByRole("button", { name: "Running…" })).toBeVisible();

    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();

    // Sign back in as a DIFFERENT identity: FE-3 route intent returns to the
    // tester, and nothing from the aborted run may render into the new
    // session.
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    await expect(
      page.getByRole("heading", { name: "Policy Tester" }).first(),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Rule evaluation trace" }),
    ).toHaveCount(0);
    await expect(page.getByText("No rule matched")).toHaveCount(0);
    await expect(page.getByLabel("Host")).toHaveValue("");
    await page.unrouteAll();
    assertClean(w);
  });
});
