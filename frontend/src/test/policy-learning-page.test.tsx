// 2C.4–2C.6 — Policy Learning page proofs: NODE-LOCAL + ADVISORY prominence
// (server notes verbatim), RBAC (viewer read-only; operator session/generate/
// reject but never accept or governance; admin accept + governance), the M5B
// Accept-to-Draft contract (exact wording, body {id, action, if_version},
// draft-not-armed absence + no arming from this page, staleness blocks
// fresh-accept), reject with bounded reason, generate as an explicit action,
// active-session 409 rendering, and read-only thresholds (no sliders).
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { PolicyLearningPage } from "../features/learning/PolicyLearningPage";

const SCOPE_NOTE =
  "Learning observes traffic on this node only; sessions, evidence, and recommendations are node-local and are not aggregated across the fleet.";
const ADVISORY_NOTE =
  "Policy Learning is advisory only: it observes and recommends, and cannot alter enforcement policy.";

const REC = {
  id: "rec-abc123def456",
  session_id: "sess-0001",
  state: "generated",
  group: "engineering",
  category: "Software Downloads",
  proposed_rule: {
    action: "Allow",
    ssl_action: "Inspect",
    enabled: false,
    source_group: "engineering",
    dest_category: "Software Downloads",
  },
  confidence: "medium",
  confidence_reasons: ["allowed_requests >= 10"],
  confidence_limits: ["transport loss occurred"],
  coverage: {
    observed_subjects: 4,
    observation_days: 3,
    membership_denominator_known: false,
  },
  evidence: {
    allowed_requests: 42,
    observed_allowed_subjects: 4,
    allowed_observation_days: 3,
  },
  baseline: { policy_generation: 12 },
  policy: {
    algorithm_version: 1,
    high_min_allowed_requests: 30,
    high_min_subjects: 5,
    high_min_days: 5,
    medium_min_allowed_requests: 10,
    medium_min_subjects: 3,
    medium_min_days: 2,
    community_tiers: ["community"],
  },
  policy_hash: "ph-1",
  generated_at: "2026-08-27T00:00:00Z",
  stale_reasons: [],
};

const COMPLETED_SESSION = {
  id: "sess-0001",
  state: "completed",
  created_at: "2026-08-25T00:00:00Z",
  started_at: "2026-08-25T00:00:00Z",
  stopped_at: "2026-08-27T00:00:00Z",
  created_by: "op-user",
  stopped_by: "op-user",
  baseline: { policy_generation: 12 },
  transport: {
    accepted: 100,
    dropped: 0,
    rejected: 0,
    consumer_panics: 0,
    groups_truncated: 0,
    degraded: false,
  },
  churn_events: 0,
  cells: 6,
  cells_dropped: 0,
  churn_overflow: 0,
  subject_key_changed: false,
};

function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

function plainText(status: number, text: string): Promise<Response> {
  return Promise.resolve(new Response(text, { status }));
}

let container: HTMLDivElement;
let root: Root;
let statusBody: unknown;
let configBody: unknown;
let sessionsBody: unknown;
let recsBody: unknown;
let policyBody: unknown;
let draftBody: unknown;
let mutations: Array<{ method: string; url: string; body: unknown }>;
let onMutate: (method: string, url: string, body: unknown) => Promise<Response>;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  Element.prototype.scrollIntoView = vi.fn();
  Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = true;
    },
  });
  Object.defineProperty(HTMLDialogElement.prototype, "close", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = false;
    },
  });
  statusBody = {
    enabled: true,
    scope: "node-local",
    scope_note: SCOPE_NOTE,
    advisory_note: ADVISORY_NOTE,
    learning_active: false,
    engine: {
      sessions: 1,
      recommendations: 1,
      read_only: false,
      schema_version: 7,
      max_retained: 16,
      max_duration_sec: 86400,
    },
    observation: {
      accepted: 100,
      dropped: 0,
      rejected: 0,
      consumer_panics: 0,
      groups_truncated: 0,
      degraded: false,
    },
    recommendation_policy: REC.policy,
    recommendation_policy_hash: "ph-1",
    guardrails_hash: "gh-1",
  };
  configBody = {
    enabled: true,
    governed: true,
    recommendable_categories: ["Software Downloads"],
    categories_are_seed: false,
    seed_source: "embedded business-category set",
    thresholds_editable: false,
    advisory_note: ADVISORY_NOTE,
    scope: "node-local",
  };
  sessionsBody = {
    enabled: true,
    scope: "node-local",
    sessions: [COMPLETED_SESSION],
  };
  recsBody = {
    enabled: true,
    scope: "node-local",
    recommendations: [REC],
    draft_mode_armed: true,
    policy_version: 12,
  };
  policyBody = {
    rules: [],
    count: 0,
    version: 13,
    updatedAt: "t",
    draft: true,
  };
  draftBody = {
    requireCommit: true,
    active: true,
    actor: "admin-user",
    startedAt: "t",
    diff: { added: ["x"], modified: [], removed: [] },
    pendingCount: 1,
    version: 5,
    shadows: [],
  };
  mutations = [];
  onMutate = () => okJSON({ ok: true });
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method !== "GET") {
        const body: unknown =
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        mutations.push({ method, url, body });
        return onMutate(method, url, body);
      }
      if (url.includes("/api/policy-learning/recommendations"))
        return okJSON(recsBody);
      if (url.includes("/api/policy-learning/sessions"))
        return okJSON(sessionsBody);
      if (url.includes("/api/policy-learning/config"))
        return okJSON(configBody);
      if (url.includes("/api/policy-learning")) return okJSON(statusBody);
      if (url.includes("/api/policy/draft")) return okJSON(draftBody);
      if (url.includes("/api/policy")) return okJSON(policyBody);
      if (url.includes("/api/urlcat"))
        return okJSON([{ name: "News" }, { name: "Software Downloads" }]);
      return Promise.reject(new TypeError(`unexpected ${method} ${url}`));
    }),
  );
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  container.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function machineFor(
  role: "viewer" | "operator" | "admin",
  qc: QueryClient,
): AuthMachine {
  return new AuthMachine(qc, {
    getSetupStatus: () =>
      Promise.resolve({
        needsSetup: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    getAuthStatus: () =>
      Promise.resolve({
        loggedIn: true,
        user: `${role}-user`,
        role,
        bootstrap: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout: () => Promise.resolve({ ok: true }),
  });
}

async function mount(role: "viewer" | "operator" | "admin"): Promise<void> {
  const router = createMemoryRouter(
    [
      { path: "/policies/learning", element: <PolicyLearningPage /> },
      { path: "/policies/access-rules", element: <div>access rules page</div> },
    ],
    { initialEntries: ["/policies/learning"] },
  );
  const qc = new QueryClient();
  const machine = machineFor(role, qc);
  await machine.boot();
  act(() => {
    root = createRoot(container);
    root.render(
      <StrictMode>
        <QueryClientProvider client={qc}>
          <AuthProvider machine={machine}>
            <RouterProvider router={router} />
          </AuthProvider>
        </QueryClientProvider>
      </StrictMode>,
    );
  });
  await flushUntil(() => {
    expect(container.textContent).toContain("Node-local and advisory");
  });
}

async function flushUntil(cond: () => void): Promise<void> {
  await vi.waitFor(async () => {
    await act(async () => {
      await new Promise((r) => {
        setTimeout(r, 0);
      });
    });
    cond();
  });
}

function findButton(match: (t: string) => boolean): HTMLButtonElement {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    match(el.textContent ?? ""),
  );
  if (b === undefined) throw new Error("button not found");
  return b;
}

function hasButton(match: (t: string) => boolean): boolean {
  return Array.from(container.querySelectorAll("button")).some((el) =>
    match(el.textContent ?? ""),
  );
}

async function click(btn: HTMLButtonElement): Promise<void> {
  await act(async () => {
    btn.click();
    await new Promise((r) => {
      setTimeout(r, 0);
    });
  });
}

// ── prominence + factual quality (§21/§26) ─────────────────────────────────

it("viewer: NODE-LOCAL + ADVISORY notes render verbatim; quality facts shown; zero controls", async () => {
  await mount("viewer");
  expect(container.textContent).toContain(SCOPE_NOTE);
  expect(container.textContent).toContain(ADVISORY_NOTE);
  expect(container.textContent).toContain("accepted 100");
  // No generic "healthy" badge is invented.
  expect(container.textContent).not.toMatch(/healthy/i);
  // Read-only thresholds, no sliders.
  expect(container.textContent).toContain("read-only");
  expect(container.querySelectorAll('input[type="range"]')).toHaveLength(0);
  // Zero mutation controls.
  expect(hasButton((t) => t.includes("Start session"))).toBe(false);
  expect(hasButton((t) => t.includes("Enable learning"))).toBe(false);
  expect(hasButton((t) => t.includes("Disable learning"))).toBe(false);
  expect(hasButton((t) => t.includes("Edit guardrail"))).toBe(false);
  expect(hasButton((t) => t.includes("Generate recommendations"))).toBe(false);
  expect(hasButton((t) => t.includes("Accept to Policy Draft"))).toBe(false);
  expect(hasButton((t) => t.includes("Reject"))).toBe(false);
});

it("operator: session + generate + reject offered; governance and accept are NOT", async () => {
  await mount("operator");
  expect(hasButton((t) => t.includes("Start session"))).toBe(true);
  expect(hasButton((t) => t.includes("Generate recommendations"))).toBe(true);
  expect(hasButton((t) => t.includes("Reject…"))).toBe(true);
  expect(hasButton((t) => t.includes("Disable learning"))).toBe(false);
  expect(hasButton((t) => t.includes("Edit guardrail"))).toBe(false);
  expect(hasButton((t) => t.includes("Accept to Policy Draft"))).toBe(false);
});

// ── session lifecycle (§23) ────────────────────────────────────────────────

it("operator start: POSTs {action:start}; the T1 ceremony states scope honestly", async () => {
  await mount("operator");
  await click(findButton((t) => t.includes("Start session…")));
  await flushUntil(() => {
    expect(container.textContent).toContain("Start a Learning session");
  });
  expect(container.textContent).toContain("THIS NODE");
  onMutate = () => okJSON({ ...COMPLETED_SESSION, state: "learning" });
  await click(findButton((t) => t === "Start session"));
  await flushUntil(() => {
    expect(mutations.length).toBe(1);
  });
  expect(mutations[0]?.url).toContain("/api/policy-learning/session");
  expect(mutations[0]?.body).toEqual({ action: "start" });
});

// ── generate (§27): explicit action, POST body {session_id} ────────────────

it("operator generate: POSTs {session_id} and renders the server summary facts", async () => {
  onMutate = () =>
    okJSON({
      session_id: "sess-0001",
      recommendations: [REC],
      eligible_cells: 3,
      truncated_cells: 0,
      skipped_synthetic_scope: 1,
      skipped_category: 2,
      skipped_no_allowed_evidence: 0,
      superseded: 1,
      unchanged: 0,
    });
  await mount("operator");
  await click(findButton((t) => t.includes("Generate recommendations")));
  await flushUntil(() => {
    expect(container.textContent).toContain("Recommendations generated");
  });
  expect(mutations[0]?.url).toContain(
    "/api/policy-learning/recommendations/generate",
  );
  expect(mutations[0]?.body).toEqual({ session_id: "sess-0001" });
  expect(container.textContent).toContain("1 superseded");
  expect(container.textContent).toContain("3 eligible cells");
});

// ── Accept-to-Draft (§28–§32) ──────────────────────────────────────────────

it("admin accept: exact ceremony wording; POST body is exactly {id, action, if_version}; success renders server truth + review link", async () => {
  onMutate = (_method, url, body) => {
    const b = JSON.stringify(body);
    if (url.includes("recommendations") && b.includes("accept")) {
      return okJSON({
        recommendation: {
          ...REC,
          state: "accepted",
          target_rule_id: "01J3ZV9E3JD0CCCCCCCCCCCCCC",
          accepted_at: "t",
          accepted_by: "admin-user",
        },
        rule_id: "01J3ZV9E3JD0CCCCCCCCCCCCCC",
        already_done: false,
        note: "Created a DISABLED rule in the Policy Draft. Enforcement is unchanged until the draft is reviewed and committed.",
      });
    }
    return okJSON({ ok: true });
  };
  // The §33 agreement check reads the draft rulebase: it must carry the
  // created DISABLED rule.
  policyBody = {
    rules: [
      {
        priority: 1,
        id: "01J3ZV9E3JD0CCCCCCCCCCCCCC",
        name: "learned rule",
        action: "Allow",
        enabled: false,
      },
    ],
    count: 1,
    version: 13,
    updatedAt: "t",
    draft: true,
  };
  await mount("admin");
  await click(findButton((t) => t.includes("Accept to Policy Draft…")));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "This creates a DISABLED Access Rule in the shared Policy Draft.",
    );
  });
  expect(container.textContent).toContain("It does not change enforcement.");
  expect(container.textContent).toContain(
    "The rule must be reviewed and explicitly committed before it can affect live traffic.",
  );
  await click(findButton((t) => t === "Accept to Policy Draft"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Accepted to Policy Draft");
  });
  const acceptCall = mutations.find(
    (m) =>
      typeof m.body === "object" && JSON.stringify(m.body).includes("accept"),
  );
  expect(acceptCall?.body).toEqual({
    id: REC.id,
    action: "accept",
    if_version: 12,
  });
  expect(container.textContent).toContain("01J3ZV9E3JD0CCCCCCCCCCCCCC");
  const link = Array.from(container.querySelectorAll("a")).find((a) =>
    (a.textContent ?? "").includes("Review created rule"),
  );
  expect(link).toBeDefined();
  expect(link?.getAttribute("href")).toContain(
    "/policies/access-rules?rule=01J3ZV9E3JD0CCCCCCCCCCCCCC",
  );
  // §33 agreement check passed — no inconsistency warning.
  await flushUntil(() => {
    expect(container.textContent).not.toContain("inconsistency");
  });
});

it("draft mode NOT armed: no Accept button, an explanation instead, and NO way to arm from this page", async () => {
  recsBody = {
    enabled: true,
    scope: "node-local",
    recommendations: [REC],
    draft_mode_armed: false,
    policy_version: 12,
  };
  await mount("admin");
  expect(hasButton((t) => t.includes("Accept to Policy Draft"))).toBe(false);
  expect(container.textContent).toContain("Policy Draft mode is not armed");
  // No Require-Commit arming control exists on this page.
  expect(hasButton((t) => t.includes("Require commit"))).toBe(false);
  expect(hasButton((t) => t.includes("Arm"))).toBe(false);
});

it("stale recommendation: server stale_reasons render; Accept is not offered as fresh", async () => {
  recsBody = {
    enabled: true,
    scope: "node-local",
    recommendations: [{ ...REC, stale_reasons: ["policy_content_changed"] }],
    draft_mode_armed: true,
    policy_version: 12,
  };
  await mount("admin");
  expect(container.textContent).toContain("policy_content_changed");
  expect(container.textContent).toContain("Stale (server-evaluated)");
  expect(hasButton((t) => t.includes("Accept to Policy Draft"))).toBe(false);
});

it("already_done accept converges idempotently and says so", async () => {
  onMutate = () =>
    okJSON({
      recommendation: {
        ...REC,
        state: "accepted",
        target_rule_id: "01J3ZV9E3JD0CCCCCCCCCCCCCC",
      },
      rule_id: "01J3ZV9E3JD0CCCCCCCCCCCCCC",
      already_done: true,
      note: "Created a DISABLED rule in the Policy Draft. Enforcement is unchanged until the draft is reviewed and committed.",
    });
  await mount("admin");
  await click(findButton((t) => t.includes("Accept to Policy Draft…")));
  await click(findButton((t) => t === "Accept to Policy Draft"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Already accepted (idempotent)");
  });
});

// ── Reject (§32) ───────────────────────────────────────────────────────────

it("operator reject: decision-only POST with the bounded reason", async () => {
  onMutate = () => okJSON({ recommendation: { ...REC, state: "rejected" } });
  await mount("operator");
  await click(findButton((t) => t.includes("Reject…")));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "no policy or configuration changes",
    );
  });
  const ta = Array.from(container.querySelectorAll("textarea")).find(
    (el) => el.closest("dialog") !== null,
  );
  expect(ta).toBeDefined();
  if (ta !== undefined) {
    Object.getOwnPropertyDescriptor(
      HTMLTextAreaElement.prototype,
      "value",
    )?.set?.call(ta, "not enough evidence");
    act(() => {
      ta.dispatchEvent(new Event("input", { bubbles: true }));
    });
  }
  await click(findButton((t) => t === "Reject"));
  await flushUntil(() => {
    expect(mutations.length).toBe(1);
  });
  expect(mutations[0]?.body).toEqual({
    id: REC.id,
    action: "reject",
    reason: "not enough evidence",
  });
});

// ── active-session fencing (§22) ───────────────────────────────────────────

it("disable while a session is active: the server 409 renders verbatim (complete or cancel first)", async () => {
  statusBody = {
    enabled: true,
    scope: "node-local",
    scope_note: SCOPE_NOTE,
    advisory_note: ADVISORY_NOTE,
    learning_active: true,
    active_session: { ...COMPLETED_SESSION, state: "learning", stopped_at: "" },
  };
  onMutate = () =>
    plainText(
      409,
      "cannot disable policy learning: a learning session is active — complete or cancel it first",
    );
  await mount("admin");
  await click(findButton((t) => t.includes("Disable learning…")));
  await click(findButton((t) => t === "Disable learning"));
  await flushUntil(() => {
    expect(container.textContent).toContain("complete or cancel it first");
  });
});
