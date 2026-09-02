// Slice 2C real-binary browser qualification: the Stage-1 Authentication
// Policy surface + Policy Learning over the actual CULVERT binary and
// committed dist, on the AUTH appliance.
//
// Covers the directive's §39/§40 browser proofs:
//   - two-client auth fencing against the REAL server (stale edit 409;
//     reorder-vs-edit exactly one winner),
//   - the flagship boundary proof: a LIVE auth mutation stales an active
//     Access-Policy Draft's baseline end-to-end (draft GET baseStale, the
//     DraftBar critical state, the commit's fail-closed 409, revert recovery),
//   - the admin CRUD journey on the Authentication Rules page (create/edit/
//     T2 delete, all live),
//   - the default-auth-outcome TIER-3 typed ceremonies (REQUIRE, then OPEN
//     to restore the harness posture),
//   - the honest Policy Learning journey (enable → session → controlled
//     proxied traffic → complete → generate → factual summary; unauth
//     traffic yields synthetic-scope evidence, so zero generated
//     recommendations IS the honest outcome — the accept path is proven by
//     the M5B backend suite and the unit contract tests),
//   - role posture (operator: auth surface read-only).
//
// Harness isolation: every premise is API-established; mode-touching tests
// restore state (draft mode, default outcome, learning enablement, created
// rules). Learning state persists in the SHARED /data (recorded harness
// debt), so the learning premise cancels any inherited active session and
// never asserts exact retained-session counts.
import { expect, request } from "@playwright/test";
import { identityHeaders, test } from "./test";
import type { Page } from "@playwright/test";
import { AUTH_URL, EMPTY_STATE, USERS } from "./fixtures";

const TOLERATED = [
  /Failed to load resource: .* status of (401|403|409|429|500)/,
];

interface Watch {
  errors: string[];
  external: string[];
  sse: string[];
}

function watch(page: Page, base: string): Watch {
  const errors: string[] = [];
  const external: string[] = [];
  const sse: string[] = [];
  const origin = new URL(base).origin;
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    const text = m.text();
    if (TOLERATED.some((re) => re.test(text))) return;
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

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

interface ApiAuthRule {
  id: string;
  name: string;
  priority: number;
  reason: string;
}

interface ApiAuthPolicy {
  rules: ApiAuthRule[];
  version: number;
}

async function apiAuthPolicy(page: Page): Promise<ApiAuthPolicy> {
  const resp = await page.request.get("/api/authpolicy");
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad /api/authpolicy payload");
  const rulesRaw = v["rules"];
  const version = v["version"];
  if (!Array.isArray(rulesRaw) || typeof version !== "number") {
    throw new Error("bad /api/authpolicy envelope");
  }
  const rules: ApiAuthRule[] = rulesRaw.map((r: unknown) => {
    if (!isRecord(r)) throw new Error("bad auth rule row");
    const auth = r["auth"];
    return {
      id: typeof r["id"] === "string" ? r["id"] : "",
      name: typeof r["name"] === "string" ? r["name"] : "",
      priority: typeof r["priority"] === "number" ? r["priority"] : 0,
      reason:
        isRecord(auth) && typeof auth["reason"] === "string"
          ? auth["reason"]
          : "",
    };
  });
  return { rules, version };
}

function authRuleBody(
  name: string,
  reason: string,
  destFQDN: string,
): Record<string, unknown> {
  return {
    name,
    ruleType: "auth",
    destFQDN,
    subjectMatch: {
      schemaVersion: 1,
      all: [{ type: "cidr", values: ["10.77.0.0/24"] }],
    },
    auth: { outcome: "Exempt", owner: "e2e-2c", reason },
  };
}

/** Delete every 2C-created auth rule (by name prefix) through the API. */
async function cleanupAuthRules(page: Page): Promise<void> {
  const snap = await apiAuthPolicy(page);
  for (const r of snap.rules) {
    if (r.name.startsWith("E2E 2C ")) {
      await page.request.delete(`/api/authpolicy?id=${r.id}`);
    }
  }
}

async function apiDraftState(
  page: Page,
): Promise<{ requireCommit: boolean; active: boolean; baseStale: boolean }> {
  const resp = await page.request.get("/api/policy/draft");
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad draft payload");
  return {
    requireCommit: v["requireCommit"] === true,
    active: v["active"] === true,
    baseStale: v["baseStale"] === true,
  };
}

async function resetDraftMode(page: Page): Promise<void> {
  const d = await apiDraftState(page);
  if (d.active) {
    await page.request.post("/api/policy/draft/revert");
  }
  if (d.requireCommit) {
    await page.request.put("/api/policy/draft", {
      data: { require_commit: false },
    });
  }
}

const AUTH_ROUTE = "/app/policies/authentication-rules";
const LEARNING_ROUTE = "/app/policies/learning";

// ── Authentication Rules page: fixture visibility + admin CRUD journey ─────

test("auth rules: fixture rules render with Exempt-is-not-Allow; admin create/edit/T2-delete journey (all live)", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await cleanupAuthRules(page);
  await page.goto(AUTH_ROUTE);

  // The two Stage-1 fixture rules and the server's contract note.
  await expect(
    page.getByText("E2E Auth Exempt", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("E2E Auth Exempt B")).toBeVisible();
  await expect(
    page.getByText("Exempt skips end-user authentication only").first(),
  ).toBeVisible();

  // Create (live).
  await page.getByRole("button", { name: "New authentication rule…" }).click();
  await expect(
    page.getByText("New authentication rule", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("take effect IMMEDIATELY in the running Stage-1 policy"),
  ).toBeVisible();
  await page.getByLabel("Rule name").fill("E2E 2C Created");
  await page.getByLabel("IPs / CIDRs").fill("10.77.0.0/24");
  await page.getByLabel("Destination FQDN").fill("e2e-2c.test");
  await page.getByLabel("Owner").fill("e2e-2c");
  await page.getByLabel("Reason").fill("browser journey");
  await page.getByRole("button", { name: "Create rule (live)" }).click();
  await expect(
    page.getByText("New authentication rule", { exact: true }),
  ).toBeHidden();
  let snap = await apiAuthPolicy(page);
  const created = snap.rules.find((r) => r.name === "E2E 2C Created");
  expect(created).toBeDefined();

  // Edit (live) — stable-ID addressed by the page.
  await page.getByRole("button", { name: "Edit rule E2E 2C Created" }).click();
  await expect(
    page.getByText("Edit authentication rule: E2E 2C Created"),
  ).toBeVisible();
  await page.getByLabel("Reason").fill("browser journey (edited)");
  await page.getByRole("button", { name: "Save changes (live)" }).click();
  await expect(
    page.getByText("Edit authentication rule: E2E 2C Created"),
  ).toBeHidden();
  snap = await apiAuthPolicy(page);
  expect(snap.rules.find((r) => r.name === "E2E 2C Created")?.reason).toBe(
    "browser journey (edited)",
  );

  // T2 delete ceremony names the rule and immediacy.
  await page
    .getByRole("button", { name: "Delete rule E2E 2C Created", exact: true })
    .click();
  await expect(
    page.getByText("Delete authentication rule: E2E 2C Created"),
  ).toBeVisible();
  await expect(page.getByText("takes effect IMMEDIATELY")).toBeVisible();
  await page.getByRole("button", { name: "Delete rule", exact: true }).click();
  await expect(
    page.getByText("Delete authentication rule: E2E 2C Created"),
  ).toBeHidden();
  snap = await apiAuthPolicy(page);
  expect(snap.rules.some((r) => r.name === "E2E 2C Created")).toBe(false);
  assertClean(w);
});

// ── Role posture: operator is read-only on the auth surface ────────────────

test("operator: authentication rules render read-only — no mutation or default-outcome controls", async ({
  browser,
  baseURL,
  clientIdentity,
}) => {
  const ctx = await browser.newContext({
    storageState: EMPTY_STATE,
    extraHTTPHeaders: identityHeaders(clientIdentity),
  });
  const page = await ctx.newPage();
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto(`${AUTH_URL}${AUTH_ROUTE}`);
  await login(page, USERS.operator.user, USERS.operator.pass);
  await expect(
    page.getByText("E2E Auth Exempt", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "New authentication rule…" }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Reorder rules…" }),
  ).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Edit rule/ })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Delete rule/ })).toHaveCount(
    0,
  );
  await expect(
    page.getByRole("button", { name: "Require authentication…" }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Open unmatched traffic…" }),
  ).toHaveCount(0);
  assertClean(w);
  await ctx.close();
});

// ── §39: two-client fenced auth mutations against the REAL server ──────────

test("two-client auth fencing: a stale edit gets the structured 409; reorder vs edit has exactly one winner", async ({
  page,
}) => {
  await cleanupAuthRules(page);
  // Seed two rules to reorder.
  const a = await page.request.post("/api/authpolicy", {
    data: authRuleBody("E2E 2C Fence A", "seed", "fence-a.test"),
  });
  expect(a.ok()).toBe(true);
  const b = await page.request.post("/api/authpolicy", {
    data: authRuleBody("E2E 2C Fence B", "seed", "fence-b.test"),
  });
  expect(b.ok()).toBe(true);

  const snap = await apiAuthPolicy(page);
  const ruleA = snap.rules.find((r) => r.name === "E2E 2C Fence A");
  const ruleB = snap.rules.find((r) => r.name === "E2E 2C Fence B");
  expect(ruleA).toBeDefined();
  expect(ruleB).toBeDefined();
  if (ruleA === undefined || ruleB === undefined) return;

  // Client 1 edits with the current version — wins.
  const edit1 = await page.request.put(
    `/api/authpolicy?id=${ruleA.id}&ifVersion=${String(snap.version)}`,
    { data: authRuleBody("E2E 2C Fence A", "first writer", "fence-a.test") },
  );
  expect(edit1.status()).toBe(200);

  // Client 2 edits with the SAME (now stale) version — structured 409.
  const edit2 = await page.request.put(
    `/api/authpolicy?id=${ruleA.id}&ifVersion=${String(snap.version)}`,
    { data: authRuleBody("E2E 2C Fence A", "second writer", "fence-a.test") },
  );
  expect(edit2.status()).toBe(409);
  const conflict: unknown = await edit2.json();
  expect(isRecord(conflict)).toBe(true);
  if (isRecord(conflict)) {
    expect(typeof conflict["currentVersion"]).toBe("number");
    expect(typeof conflict["yourVersion"]).toBe("number");
    expect(typeof conflict["error"]).toBe("string");
  }
  // The winner's content survived.
  expect(
    (await apiAuthPolicy(page)).rules.find((r) => r.id === ruleA.id)?.reason,
  ).toBe("first writer");

  // Reorder vs edit, same asserted version, genuinely concurrent — exactly
  // one mutation lands (the atomic running-domain fence).
  const cur = await apiAuthPolicy(page);
  const authIDs = cur.rules.map((r) => r.id);
  const reversed = [...authIDs].reverse();
  const [reorderResp, editResp] = await Promise.all([
    page.request.post(
      `/api/authpolicy/reorder?ifVersion=${String(cur.version)}`,
      { data: { ids: reversed } },
    ),
    page.request.put(
      `/api/authpolicy?id=${ruleB.id}&ifVersion=${String(cur.version)}`,
      { data: authRuleBody("E2E 2C Fence B", "racer", "fence-b.test") },
    ),
  ]);
  const codes = [reorderResp.status(), editResp.status()].sort();
  expect(codes[0]).toBe(200);
  expect([409, 404]).toContain(codes[1]);

  await cleanupAuthRules(page);
});

// ── §39 flagship: LIVE auth mutation stales the Access Draft end-to-end ────

test("auth mutation under an active draft: baseStale surfaces, the DraftBar goes critical, commit refuses, revert recovers", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await cleanupAuthRules(page);
  await resetDraftMode(page);
  try {
    // Arm Require Commit and stage one access edit so the draft opens.
    await page.request.put("/api/policy/draft", {
      data: { require_commit: true },
    });
    const staged = await page.request.post("/api/policy", {
      data: { name: "E2E 2C Staged Access", action: "Allow" },
    });
    expect(staged.ok()).toBe(true);
    expect((await apiDraftState(page)).active).toBe(true);
    expect((await apiDraftState(page)).baseStale).toBe(false);

    // A LIVE Stage-1 mutation — lands in RUNNING, never the candidate.
    const authCreate = await page.request.post("/api/authpolicy", {
      data: authRuleBody(
        "E2E 2C Live Under Draft",
        "stales the draft",
        "under-draft.test",
      ),
    });
    expect(authCreate.ok()).toBe(true);

    // Server truth: the draft's fork baseline is now stale.
    expect((await apiDraftState(page)).baseStale).toBe(true);

    // Browser truth: the DraftBar goes critical and withholds the commit entry.
    await page.goto("/app/policies/access-rules");
    await expect(page.getByText("Draft baseline is stale")).toBeVisible();
    await expect(
      page.getByText(
        "The running policy changed after this Access Policy Draft was opened.",
      ),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Review & commit…" }),
    ).toHaveCount(0);

    // The commit fails closed server-side regardless.
    const commit = await page.request.post("/api/policy/draft/commit", {
      data: { comment: "must fail — stale base" },
    });
    expect(commit.status()).toBe(409);

    // Recovery: revert, and the surface returns to a committable state.
    await page.getByRole("button", { name: "Revert draft…" }).click();
    await page
      .getByRole("button", { name: "Revert draft", exact: true })
      .click();
    await expect(page.getByText("Draft baseline is stale")).toBeHidden();
    expect((await apiDraftState(page)).active).toBe(false);
    assertClean(w);
  } finally {
    await resetDraftMode(page);
    await cleanupAuthRules(page);
  }
});

// ── §19: default-auth-outcome tier-3 typed ceremonies (REQUIRE then OPEN) ──

test("default authentication: tier-3 typed REQUIRE flips to Default, typed OPEN restores the fixture's Exempt", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto(AUTH_ROUTE);
  // Fixture posture: Exempt (open unmatched traffic).
  await expect(
    page.getByRole("button", { name: "Require authentication…" }),
  ).toBeVisible();

  await page.getByRole("button", { name: "Require authentication…" }).click();
  await expect(
    page.getByText("Require authentication for unmatched traffic"),
  ).toBeVisible();
  // Typed gate: the confirm is inert until the exact word is typed.
  await expect(
    page.getByRole("button", { name: "Require authentication", exact: true }),
  ).toBeDisabled();
  await page.getByLabel("Type REQUIRE to confirm").fill("REQUIRE");
  await page
    .getByRole("button", { name: "Require authentication", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Open unmatched traffic…" }),
  ).toBeVisible();

  // Restore: typed OPEN, with the §19 copy verbatim.
  await page.getByRole("button", { name: "Open unmatched traffic…" }).click();
  await expect(
    page.getByText(
      "Unmatched clients may proceed without end-user authentication.",
    ),
  ).toBeVisible();
  await expect(
    page.getByText(
      "This does NOT allow traffic by itself; Stage-2 Access Policy still decides.",
    ),
  ).toBeVisible();
  await page.getByLabel("Type OPEN to confirm").fill("OPEN");
  await page
    .getByRole("button", { name: "Open unmatched traffic", exact: true })
    .click();
  await expect(
    page.getByRole("button", { name: "Require authentication…" }),
  ).toBeVisible();
  assertClean(w);
});

// ── §40: the honest Policy Learning journey ────────────────────────────────

async function learningStatus(
  page: Page,
): Promise<{ enabled: boolean; activeID: string }> {
  const resp = await page.request.get("/api/policy-learning");
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad learning status");
  const act = v["active_session"];
  return {
    enabled: v["enabled"] === true,
    activeID: isRecord(act) && typeof act["id"] === "string" ? act["id"] : "",
  };
}

/** Premise: no inherited active session (SHARED /data — recorded debt); the
 * feature disabled so the journey exercises the enable ceremony. */
async function resetLearning(page: Page): Promise<void> {
  const st = await learningStatus(page);
  if (st.activeID !== "") {
    await page.request.post("/api/policy-learning/session", {
      data: { action: "cancel" },
    });
  }
  if (st.enabled) {
    await page.request.put("/api/policy-learning/config", {
      data: { enabled: false },
    });
  }
}

test("policy learning journey: enable → session → proxied traffic → complete → generate (honest facts) → disable", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await resetLearning(page);
  try {
    await page.goto(LEARNING_ROUTE);
    await expect(page.getByText("Node-local and advisory")).toBeVisible();
    await expect(
      page.getByText("advisory only", { exact: true }),
    ).toBeVisible();
    await expect(page.getByText("node-local", { exact: true })).toBeVisible();

    // Enable (T2).
    await page.getByRole("button", { name: "Enable learning…" }).click();
    await expect(page.getByText("Enable Policy Learning")).toBeVisible();
    await page
      .getByRole("button", { name: "Enable learning", exact: true })
      .click();
    await expect(page.getByText("Learning is enabled.")).toBeVisible();

    // Start a session (T1).
    await page.getByRole("button", { name: "Start session…" }).click();
    await expect(page.getByText("Start a Learning session")).toBeVisible();
    await page
      .getByRole("button", { name: "Start session", exact: true })
      .click();
    await expect(page.getByText("actively observing")).toBeVisible();
    const st = await learningStatus(page);
    expect(st.activeID).not.toBe("");

    // Controlled traffic THROUGH THE PROXY (default-deny observations; the
    // clients are unauthenticated, so evidence lands in the synthetic
    // s:unauth scope — honest, and deliberately not recommendable).
    const proxyPort = process.env["CULVERT_E2E_PROXY_PORT"] ?? "19080";
    const proxied = await request.newContext({
      proxy: { server: `http://127.0.0.1:${proxyPort}` },
    });
    for (let i = 0; i < 5; i++) {
      await proxied
        .get(`http://pl-e2e-${String(i)}.test/`, { timeout: 3000 })
        .catch(() => undefined);
    }
    await proxied.dispose();

    // Complete the session (T1).
    await page.getByRole("button", { name: "Complete session…" }).click();
    await page
      .getByRole("button", { name: "Complete session", exact: true })
      .click();
    await expect(page.getByText("No session is active.")).toBeVisible();

    // Generate from THAT session (explicit action) — the summary renders the
    // engine's honest facts: nothing eligible from synthetic-scope traffic.
    const row = page
      .locator("li")
      .filter({ hasText: st.activeID.slice(0, 12) })
      .first();
    await row.getByRole("button", { name: "Generate recommendations" }).click();
    await expect(page.getByText("Recommendations generated")).toBeVisible();
    await expect(page.getByText("0 generated")).toBeVisible();

    assertClean(w);
  } finally {
    await resetLearning(page);
  }
});

// ── Post-accept concurrency: the real-server lifecycle the verification
// classifier consumes ─────────────────────────────────────────────────────
//
// A REAL browser-level Accept needs an honestly generated recommendation,
// which requires grouped authenticated identity this harness cannot mint
// (recorded constraint — the learning journey above proves the honest zero
// outcome). The M5B Go suite owns the Accept protocol proofs through the
// supported API handlers, including TestM5B_ConcurrentDoubleAccept
// (already_done=true, same target rule id, zero duplicate rules). What the
// FRONTEND classifier consumes is the SERVER LIFECYCLE of the accepted
// target: a DISABLED rule in the Policy Draft candidate that a SECOND admin
// commits between the confirmed Accept and the verification GETs, after
// which the same stable rule id is present in RUNNING. This test reproduces
// exactly that ordering through supported server calls with two authenticated
// clients and pins the envelope fields the classifier keys on (draft flag,
// stable id, enabled) — binding the component-test fixtures for states A/B
// to real server truth. Accept itself never enforces anything: the rule is
// running only because of B's separate commit.
test("post-accept lifecycle: disabled draft rule committed by a second admin keeps its stable id into RUNNING (the running-now shape)", async () => {
  // Each admin is a dedicated authenticated API client with its OWN
  // X-Forwarded-For identity (the harness trusts loopback as a reverse
  // proxy — the RISK-019 deployment shape), so this test's mutation burst
  // draws on per-client admin-API rate budgets instead of the suite-shared
  // 127.0.0.1 budget that the accumulated specs exhaust (the deliberate
  // 60-mutations/min posture stays fully armed per identity).
  const newAdminClient = async (xff: string) => {
    const ctx = await request.newContext({
      baseURL: AUTH_URL,
      extraHTTPHeaders: { "X-Forwarded-For": xff },
    });
    const login = await ctx.post("/api/auth/login", {
      data: { user: USERS.admin.user, pass: USERS.admin.pass },
    });
    expect(login.ok()).toBe(true);
    return ctx;
  };
  const adminA = await newAdminClient("198.51.100.10");
  const adminB = await newAdminClient("198.51.100.11");
  const draftStateA = async () => {
    const resp = await adminA.get("/api/policy/draft");
    expect(resp.ok()).toBe(true);
    const v: unknown = await resp.json();
    if (!isRecord(v)) throw new Error("bad draft payload");
    return {
      requireCommit: v["requireCommit"] === true,
      active: v["active"] === true,
    };
  };
  const resetDraftA = async () => {
    const d = await draftStateA();
    if (d.active) await adminA.post("/api/policy/draft/revert");
    if (d.requireCommit) {
      await adminA.put("/api/policy/draft", {
        data: { require_commit: false },
      });
    }
  };
  try {
    await resetDraftA();
    // Arm Require Commit; admin A stages the DISABLED rule (the exact shape
    // Accept's draft append creates: born disabled, in the candidate).
    const armed = await adminA.put("/api/policy/draft", {
      data: { require_commit: true },
    });
    expect(armed.ok()).toBe(true);
    const created = await adminA.post("/api/policy", {
      data: {
        name: "E2E 2C PostAccept Target",
        action: "Allow",
        enabled: false,
      },
    });
    expect(created.ok()).toBe(true);

    // Admin A's pre-commit observation: the EFFECTIVE snapshot is the
    // candidate (draft:true) and carries the disabled target — the
    // draft-confirmed shape (state A).
    const preResp = await adminA.get("/api/policy");
    expect(preResp.ok()).toBe(true);
    const pre: unknown = await preResp.json();
    if (!isRecord(pre) || !Array.isArray(pre["rules"]))
      throw new Error("bad policy envelope");
    expect(pre["draft"]).toBe(true);
    const preRule = pre["rules"]
      .map((r: unknown) => r)
      .find((r) => isRecord(r) && r["name"] === "E2E 2C PostAccept Target");
    expect(preRule).toBeDefined();
    if (!isRecord(preRule)) return;
    const targetID = preRule["id"];
    expect(typeof targetID).toBe("string");
    expect(preRule["enabled"]).toBe(false);
    expect((await draftStateA()).active).toBe(true);

    // Admin B (a separate authenticated client) commits the draft — the
    // concurrent lifecycle that advances the Policy state after acceptance.
    const commit = await adminB.post("/api/policy/draft/commit", {
      data: { comment: "concurrent commit during A's verification window" },
    });
    expect(
      commit.ok(),
      `commit refused: ${String(commit.status())} ${await commit.text()}`,
    ).toBe(true);

    // Admin A's verification observation now sees the running-now shape
    // (state B): effective snapshot is RUNNING, SAME stable id, still the
    // born-safe disabled state — Accept never enforced anything; the commit
    // moved it.
    const postResp = await adminA.get("/api/policy");
    expect(postResp.ok()).toBe(true);
    const post: unknown = await postResp.json();
    if (!isRecord(post) || !Array.isArray(post["rules"]))
      throw new Error("bad policy envelope");
    expect(post["draft"]).toBe(false);
    const postRule = post["rules"]
      .map((r: unknown) => r)
      .find((r) => isRecord(r) && r["id"] === targetID);
    expect(postRule).toBeDefined();
    if (!isRecord(postRule)) return;
    expect(postRule["enabled"]).toBe(false);
    expect((await draftStateA()).active).toBe(false);
  } finally {
    // Restore: remove the committed rule from RUNNING and disarm.
    const snap = await adminA.get("/api/policy");
    const v: unknown = await snap.json();
    if (isRecord(v) && Array.isArray(v["rules"])) {
      for (const r of v["rules"]) {
        if (isRecord(r) && r["name"] === "E2E 2C PostAccept Target") {
          await adminA.delete(`/api/policy?id=${String(r["id"])}`);
        }
      }
    }
    await resetDraftA();
    await adminA.dispose();
    await adminB.dispose();
  }
});
