// 2C.2/2C.3 — Authentication Rules page proofs: ADMIN-only writes (viewer AND
// operator mount zero mutation controls — the backend is stricter than the
// Stage-2 surface and the page mirrors it), the Exempt-is-not-Allow
// presentation from server truth, the fenced create/edit/delete/reorder flows
// (stable-ID addressing + {ids} reorder + always-asserted ifVersion), the §9
// active-draft pre-save warning, unknown-outcome degradation, and the
// default-auth-outcome TIER-3 typed ceremony.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { AuthRulesPage } from "../features/policy/AuthRulesPage";

const EXEMPT_NOTE =
  "Exempt skips end-user authentication only — it never allows traffic. " +
  "It applies only when the client presents no credentials; Stage-2 policy still decides access and default-deny still applies.";

const RULE_A = {
  priority: 9001,
  id: "01J3ZV9E3JD0AAAAAAAAAAAAAA",
  ruleType: "auth",
  name: "Exempt printers",
  action: "",
  destFQDN: "updates.printers.test",
  subjectMatch: {
    schemaVersion: 1,
    all: [{ type: "cidr", values: ["10.99.0.0/24"] }],
  },
  auth: {
    outcome: "Exempt",
    owner: "netops",
    reason: "printer fleet cannot authenticate",
  },
  warnings: [],
};

const RULE_B = {
  priority: 9002,
  id: "01J3ZV9E3JD0BBBBBBBBBBBBBB",
  ruleType: "auth",
  name: "SSO for finance",
  action: "",
  destFQDN: "erp.example.test",
  subjectMatch: {
    schemaVersion: 1,
    all: [{ type: "cidr", values: ["10.20.0.0/16"] }],
  },
  auth: {
    outcome: "SSORequired",
    owner: "secops",
    reason: "interactive app requires SSO",
    providerRefs: ["corp-oidc"],
  },
  warnings: [],
};

function authPolicyBody(rules: unknown[], version: number): unknown {
  return {
    rules,
    count: rules.length,
    defaultAction: "deny",
    note: EXEMPT_NOTE,
    version,
    updatedAt: "2026-08-28T12:00:00Z",
  };
}

function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

let container: HTMLDivElement;
let root: Root;
let authBody: unknown;
let draftBody: unknown;
let idpBody: unknown;
let securityBody: unknown;
let mutations: Array<{ method: string; url: string; body: unknown }>;
let onMutate: (method: string, url: string) => Promise<Response>;

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
  authBody = authPolicyBody([RULE_A, RULE_B], 7);
  draftBody = { requireCommit: false, active: false, actor: "", startedAt: "" };
  idpBody = {
    persisted: true,
    profiles: [
      { id: "corp-oidc", name: "Corp OIDC", type: "oidc", enabled: true },
      { id: "old-saml", name: "Old SAML", type: "saml", enabled: false },
    ],
  };
  securityBody = {
    authEnabled: true,
    user: "",
    proxyPort: 8080,
    uiPort: 9090,
    defaultAuthOutcome: "Default",
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
        return onMutate(method, url);
      }
      if (url.includes("/api/authpolicy")) return okJSON(authBody);
      if (url.includes("/api/policy/draft")) return okJSON(draftBody);
      if (url.includes("/api/idp")) return okJSON(idpBody);
      if (url.includes("/api/settings")) return okJSON(securityBody);
      if (url.includes("/api/urlcat")) return okJSON([{ name: "News" }]);
      if (url.includes("/api/category-groups"))
        return okJSON({ names: ["Business"] });
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

async function mount(
  role: "viewer" | "operator" | "admin",
  readyText = "Exempt printers",
): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/policies/authentication-rules", element: <AuthRulesPage /> }],
    { initialEntries: ["/policies/authentication-rules"] },
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
    expect(container.textContent).toContain(readyText);
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

function findButtonByLabel(labelIncludes: string): HTMLButtonElement {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    (el.getAttribute("aria-label") ?? "").includes(labelIncludes),
  );
  if (b === undefined)
    throw new Error(`button not found by label: ${labelIncludes}`);
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

function setField(labelIncludes: string, value: string): void {
  const label = Array.from(container.querySelectorAll("label")).find((l) =>
    (l.textContent ?? "").includes(labelIncludes),
  );
  if (label === undefined) throw new Error(`label not found: ${labelIncludes}`);
  const forId = label.getAttribute("for");
  const el =
    forId !== null
      ? document.getElementById(forId)
      : label.querySelector("input,textarea,select");
  if (
    !(el instanceof HTMLInputElement) &&
    !(el instanceof HTMLTextAreaElement) &&
    !(el instanceof HTMLSelectElement)
  ) {
    throw new Error(`control not found for label: ${labelIncludes}`);
  }
  const proto =
    el instanceof HTMLInputElement
      ? HTMLInputElement.prototype
      : el instanceof HTMLTextAreaElement
        ? HTMLTextAreaElement.prototype
        : HTMLSelectElement.prototype;
  Object.getOwnPropertyDescriptor(proto, "value")?.set?.call(el, value);
  act(() => {
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  });
}

// ── RBAC (§10): admin-only writes; viewer AND operator are read-only ────────

it("viewer: rules render read-only; no mutation or default-outcome controls", async () => {
  await mount("viewer");
  expect(container.textContent).toContain("SSO for finance");
  expect(hasButton((t) => t.includes("New authentication rule"))).toBe(false);
  expect(hasButton((t) => t.includes("Reorder rules"))).toBe(false);
  expect(hasButton((t) => t === "Edit")).toBe(false);
  expect(hasButton((t) => t === "Delete")).toBe(false);
  expect(hasButton((t) => t.includes("Open unmatched traffic"))).toBe(false);
  expect(hasButton((t) => t.includes("Require authentication…"))).toBe(false);
});

it("operator: STILL read-only — the backend is admin-only and the page mirrors it", async () => {
  await mount("operator");
  expect(hasButton((t) => t.includes("New authentication rule"))).toBe(false);
  expect(hasButton((t) => t.includes("Reorder rules"))).toBe(false);
  expect(hasButton((t) => t === "Edit")).toBe(false);
  expect(hasButton((t) => t === "Delete")).toBe(false);
  expect(hasButton((t) => t.includes("Open unmatched traffic"))).toBe(false);
});

// ── Exempt ≠ Allow (§12) ────────────────────────────────────────────────────

it("renders the server's Exempt note verbatim and badges Exempt as a warning-class waiver", async () => {
  await mount("viewer");
  expect(container.textContent).toContain("it never allows traffic");
  const badges = Array.from(container.querySelectorAll("[data-status]")).filter(
    (el) => el.textContent === "Exempt",
  );
  expect(badges.length).toBeGreaterThan(0);
  for (const b of badges) {
    expect(b.getAttribute("data-status")).not.toBe("ok");
  }
});

// ── Create (admin): fenced POST with the serialized auth body ───────────────

it("admin create: POSTs the serialized auth rule with ifVersion asserted", async () => {
  await mount("admin");
  await click(findButton((t) => t.includes("New authentication rule")));
  await flushUntil(() => {
    expect(container.textContent).toContain("New authentication rule");
  });
  setField("Rule name", "Lab exemption");
  setField("IPs / CIDRs", "10.50.0.0/24");
  setField("Destination FQDN", "lab.example.test");
  setField("Owner", "lab-team");
  setField("Reason", "lab devices");
  await click(findButton((t) => t.includes("Create rule (live)")));
  await flushUntil(() => {
    expect(mutations.length).toBe(1);
  });
  const m = mutations[0];
  expect(m?.method).toBe("POST");
  expect(m?.url).toContain("/api/authpolicy");
  expect(m?.url).toContain("ifVersion=7");
  expect(m?.body).toEqual({
    name: "Lab exemption",
    ruleType: "auth",
    subjectMatch: {
      schemaVersion: 1,
      all: [{ type: "cidr", values: ["10.50.0.0/24"] }],
    },
    auth: { outcome: "Exempt", owner: "lab-team", reason: "lab devices" },
    destFQDN: "lab.example.test",
    destCategory: "",
    destCategoryGroup: "",
    comment: "",
  });
});

// ── §9: active Access Draft warns before an auth save ───────────────────────

it("editor warns when an Access Policy Draft is active: the save invalidates its baseline", async () => {
  draftBody = {
    requireCommit: true,
    active: true,
    actor: "someone",
    startedAt: "2026-08-28T10:00:00Z",
    diff: { added: [], modified: [], removed: [] },
    pendingCount: 0,
    version: 3,
    shadows: [],
  };
  await mount("admin");
  await click(findButton((t) => t.includes("New authentication rule")));
  await flushUntil(() => {
    expect(container.textContent).toContain("An Access Policy Draft is active");
  });
  expect(container.textContent).toContain(
    "will invalidate that draft's running-generation baseline",
  );
});

// ── Delete (admin): T2 ceremony + stable-ID fenced DELETE ───────────────────

it("admin delete: tier-2 ceremony names the rule and immediacy; DELETE goes by stable id with ifVersion", async () => {
  await mount("admin");
  const deleteButtons = Array.from(container.querySelectorAll("button")).filter(
    (b) => b.textContent === "Delete",
  );
  const first = deleteButtons[0];
  expect(first).toBeDefined();
  if (first === undefined) return;
  await click(first);
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "Delete authentication rule: Exempt printers",
    );
  });
  expect(container.textContent).toContain("takes effect IMMEDIATELY");
  await click(findButton((t) => t === "Delete rule"));
  await flushUntil(() => {
    expect(mutations.length).toBe(1);
  });
  const m = mutations[0];
  expect(m?.method).toBe("DELETE");
  expect(m?.url).toContain(`id=${RULE_A.id}`);
  expect(m?.url).toContain("ifVersion=7");
  expect(m?.url).not.toContain("priority=");
});

// ── Reorder (admin): staged locally, applied as {ids} with ifVersion ────────

it("admin reorder: staged move + apply POSTs {ids} in the new order; a 409 discards visibly", async () => {
  await mount("admin");
  await click(findButton((t) => t.includes("Reorder rules")));
  await click(findButtonByLabel(`Move rule ${RULE_A.name} down`));
  expect(container.textContent).toContain("Reorder staged");
  await click(findButton((t) => t.includes("Apply reorder (live)")));
  await flushUntil(() => {
    expect(mutations.length).toBe(1);
  });
  const m = mutations[0];
  expect(m?.method).toBe("POST");
  expect(m?.url).toContain("/api/authpolicy/reorder");
  expect(m?.url).toContain("ifVersion=7");
  expect(m?.body).toEqual({ ids: [RULE_B.id, RULE_A.id] });
});

it("admin reorder conflict: the 409 discards the staging visibly, nothing silently reapplies", async () => {
  onMutate = () =>
    okJSON(
      { error: "the rulebase changed", currentVersion: 9, yourVersion: 7 },
      409,
    );
  await mount("admin");
  await click(findButton((t) => t.includes("Reorder rules")));
  await click(findButtonByLabel(`Move rule ${RULE_A.name} down`));
  await click(findButton((t) => t.includes("Apply reorder (live)")));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "The auth rulebase changed while you were reordering.",
    );
  });
  expect(hasButton((t) => t.includes("Apply reorder (live)"))).toBe(false);
  expect(mutations.length).toBe(1);
});

// ── Unknown outcome (§11): degraded, read-only ──────────────────────────────

it("a rule with an unknown outcome renders its raw value and its Edit control is disabled", async () => {
  authBody = authPolicyBody(
    [
      RULE_A,
      {
        ...RULE_B,
        name: "Future rule",
        auth: { ...RULE_B.auth, outcome: "QuantumChallenge" },
      },
    ],
    7,
  );
  await mount("admin");
  expect(container.textContent).toContain("QuantumChallenge");
  const editButtons = Array.from(container.querySelectorAll("button")).filter(
    (b) => b.textContent === "Edit",
  );
  expect(editButtons).toHaveLength(2);
  expect(editButtons[0]?.disabled).toBe(false);
  expect(editButtons[1]?.disabled).toBe(true);
});

// ── Default auth outcome (§17–§19): tier-3 typed ceremony ───────────────────

it("default outcome to Exempt: tier-3 requires the typed word OPEN; PUT carries the exact body", async () => {
  await mount("admin");
  await flushUntil(() => {
    expect(hasButton((t) => t.includes("Open unmatched traffic…"))).toBe(true);
  });
  await click(findButton((t) => t.includes("Open unmatched traffic…")));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "Unmatched clients may proceed without end-user authentication.",
    );
  });
  expect(container.textContent).toContain(
    "This does NOT allow traffic by itself; Stage-2 Access Policy still decides.",
  );
  // The confirm is inert until the exact word is typed.
  const confirm = findButton((t) => t === "Open unmatched traffic");
  expect(confirm.disabled).toBe(true);
  setField("Type OPEN to confirm", "OPEN");
  await flushUntil(() => {
    expect(findButton((t) => t === "Open unmatched traffic").disabled).toBe(
      false,
    );
  });
  await click(findButton((t) => t === "Open unmatched traffic"));
  await flushUntil(() => {
    expect(mutations.length).toBe(1);
  });
  const m = mutations[0];
  expect(m?.method).toBe("PUT");
  expect(m?.url).toContain("/api/settings/default-auth-outcome");
  expect(m?.body).toEqual({ defaultAuthOutcome: "Exempt" });
});

it("default outcome back to Default: tier-3 typed REQUIRE", async () => {
  securityBody = {
    authEnabled: true,
    user: "",
    proxyPort: 8080,
    uiPort: 9090,
    defaultAuthOutcome: "Exempt",
  };
  await mount("admin");
  await flushUntil(() => {
    expect(hasButton((t) => t.includes("Require authentication…"))).toBe(true);
  });
  await click(findButton((t) => t.includes("Require authentication…")));
  setField("Type REQUIRE to confirm", "REQUIRE");
  await flushUntil(() => {
    expect(findButton((t) => t === "Require authentication").disabled).toBe(
      false,
    );
  });
  await click(findButton((t) => t === "Require authentication"));
  await flushUntil(() => {
    expect(mutations.length).toBe(1);
  });
  expect(mutations[0]?.body).toEqual({ defaultAuthOutcome: "Default" });
});

it("unknown current default (§19): the control blocks changes until fresh recognizable truth", async () => {
  securityBody = {
    authEnabled: true,
    user: "",
    proxyPort: 8080,
    uiPort: 9090,
    defaultAuthOutcome: "SomethingNew",
  };
  await mount("admin");
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "Current default is unavailable or unrecognized",
    );
  });
  expect(hasButton((t) => t.includes("Open unmatched traffic…"))).toBe(false);
  expect(hasButton((t) => t.includes("Require authentication…"))).toBe(false);
});

// ── SSORequired provider display (§13) ──────────────────────────────────────

it("SSORequired provider refs: resolved refs render; a dangling ref is marked unresolved, never dropped", async () => {
  authBody = authPolicyBody(
    [
      {
        ...RULE_B,
        auth: {
          ...RULE_B.auth,
          providerRefs: ["corp-oidc", "deleted-idp"],
        },
      },
    ],
    7,
  );
  await mount("admin", "SSO for finance");
  await click(findButtonByLabel("Details for rule SSO for finance"));
  await flushUntil(() => {
    expect(container.textContent).toContain("corp-oidc");
  });
  expect(container.textContent).toContain("deleted-idp");
  expect(container.textContent).toContain("unresolved");
});
