// 2E-C — CDR page proofs: RBAC-exact mounting (viewer mounts ZERO mutation
// controls on every tab, incl. the admin-only Test harness), the T2 runtime
// toggle ceremony, the T3 typed DELETE ceremony with the orphaned-trust
// fingerprint carried into the completion notice, the revoke 503
// (second-instance requirement) rendered as server truth, the enrollment
// unknown-outcome latch (single-use token cleared, no blind retry), and the
// duplicate policy-name 409.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { CDRPage } from "../features/security/CDRPage";

function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

function plainError(text: string, status: number): Promise<Response> {
  return Promise.resolve(
    new Response(text, {
      status,
      headers: { "Content-Type": "text/plain" },
    }),
  );
}

let container: HTMLDivElement;
let root: Root;
let mutations: Array<{ method: string; url: string; body: unknown }>;
let onMutate: (method: string, url: string) => Promise<Response>;

const CONFIG = {
  enabled: true,
  endpoint: "sluice:8443",
  failMode: "open",
  defaultProfile: "default",
  defaultMode: "ENFORCE",
  timeoutSec: 35,
  maxFileSizeMB: 50,
  chunkSizeKB: 64,
  serverFingerprint: "ab".repeat(32),
  certsDir: "",
  clientActive: true,
  failOpen: true,
};

const HEALTH = {
  healthy: true,
  version: "v0.2.0",
  supportedTypes: ["pdf", "docx"],
  activeWorkers: 1,
  maxWorkers: 4,
  queueDepth: 0,
  filesProcessed: 12,
  threatsRemoved: 3,
  profiles: [{ name: "default", description: "baseline", maxFileSizeBytes: 0 }],
  lastSeen: "2026-08-30T10:00:00Z",
  consecutiveFailures: 0,
  liveHealthy: true,
};

const INSTANCES = {
  instances: [
    {
      name: "sluice-a",
      endpoint: "10.0.0.5:8443",
      serverFingerprint: "cd".repeat(32),
      clientCertFingerprint: "sha256:" + "ee".repeat(32),
      enrolledAt: "2026-08-01T00:00:00Z",
      clientCertDaysRemaining: 200,
      cbState: "closed",
      poolHealthy: true,
    },
  ],
  count: 1,
  version: 4,
  updatedAt: "2026-08-30T09:00:00Z",
};

const POLICIES = {
  rules: [
    {
      priority: 10,
      name: "finance-enforce",
      mode: "ENFORCE",
      profileName: "default",
      sourceGroup: "finance",
    },
  ],
  count: 1,
  version: 2,
  epoch: 5,
  updatedAt: "2026-08-30T08:00:00Z",
  integrity: { ok: true, issues: [] },
};

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
      if (url.includes("/api/cdr/config")) return okJSON(CONFIG);
      if (url.includes("/api/cdr/health")) return okJSON(HEALTH);
      if (url.includes("/api/cdr/instances")) return okJSON(INSTANCES);
      if (url.includes("/api/cdr/policies")) return okJSON(POLICIES);
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

function machineFor(role: "viewer" | "admin", qc: QueryClient): AuthMachine {
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

async function mountPage(role: "viewer" | "admin"): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/security/cdr", element: <CDRPage /> }],
    { initialEntries: ["/security/cdr"] },
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
    expect(container.textContent).toContain("Runtime state");
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

function buttons(): string[] {
  return Array.from(container.querySelectorAll("button")).map(
    (b) => b.textContent ?? "",
  );
}

function clickButton(match: (t: string) => boolean): void {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    match(el.textContent ?? ""),
  );
  if (b === undefined) throw new Error("button not found");
  act(() => {
    b.click();
  });
}

async function openTab(name: string, readyText: string): Promise<void> {
  clickButton((t) => t === name);
  await flushUntil(() => {
    expect(container.textContent).toContain(readyText);
  });
}

function setInput(label: string, value: string): void {
  const labels = Array.from(container.querySelectorAll("label"));
  const lab = labels.find((l) => (l.textContent ?? "").includes(label));
  if (lab === undefined) throw new Error(`label ${label} not found`);
  const id = lab.getAttribute("for");
  const input = container.querySelector(`#${id ?? ""}`);
  if (!(input instanceof HTMLInputElement)) {
    throw new Error(`input for ${label} not found`);
  }
  act(() => {
    const desc = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    );
    desc?.set?.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

// ── RBAC exact-mount ────────────────────────────────────────────────────────

it("viewer mounts ZERO mutation controls on every tab", async () => {
  await mountPage("viewer");
  expect(buttons().some((t) => t.includes("Disable CDR"))).toBe(false);
  expect(buttons().some((t) => t.includes("Enable CDR"))).toBe(false);

  await openTab("Instances", "Enrolled instances");
  expect(container.textContent).toContain("sluice-a");
  expect(buttons().some((t) => t.includes("Revoke"))).toBe(false);
  expect(buttons().some((t) => t.includes("Delete"))).toBe(false);
  expect(container.textContent).not.toContain("Enroll a new instance");

  await openTab("Policies", "finance-enforce");
  expect(buttons().some((t) => t.includes("Delete"))).toBe(false);
  expect(container.textContent).not.toContain("Add a rule");

  await openTab("Test", "Admin only");
  expect(buttons().some((t) => t.includes("Run test"))).toBe(false);
  expect(mutations).toHaveLength(0);
});

// ── Runtime toggle (T2) ─────────────────────────────────────────────────────

it("admin disable ceremony issues the absolute-state PUT after confirm", async () => {
  await mountPage("admin");
  clickButton((t) => t.includes("Disable CDR processing"));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "NO file sanitization, detection, or reporting",
    );
  });
  expect(mutations).toHaveLength(0); // opening the ceremony mutates nothing
  clickButton((t) => t === "Disable CDR");
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  expect(mutations[0]).toMatchObject({
    method: "PUT",
    url: "/api/cdr/config",
    body: { enabled: false },
  });
});

// ── Delete (T3, local-only, orphaned-trust visibility) ─────────────────────

it("delete is a typed T3 ceremony and the notice carries the orphaned fingerprint", async () => {
  onMutate = () =>
    okJSON({
      removed: "sluice-a",
      clientCertFingerprint: "sha256:" + "ee".repeat(32),
      clientCertFingerprints: ["sha256:" + "ee".repeat(32)],
    });
  await mountPage("admin");
  await openTab("Instances", "Enrolled instances");
  clickButton((t) => t.includes("Delete…"));
  await flushUntil(() => {
    expect(container.textContent).toContain("does NOT revoke anything");
  });
  // Confirm without the typed name must be inert.
  clickButton((t) => t === "Delete locally");
  expect(mutations).toHaveLength(0);
  setInput("Type sluice-a to confirm", "sluice-a");
  clickButton((t) => t === "Delete locally");
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  expect(mutations[0]?.url).toBe("/api/cdr/instances?name=sluice-a");
  await flushUntil(() => {
    expect(container.textContent).toContain("Deleted sluice-a (locally)");
    expect(container.textContent).toContain("ee".repeat(32));
    expect(container.textContent).toContain("until it expires or is revoked");
  });
});

// ── Revoke 503 (second-instance requirement is server truth) ───────────────

it("revoke failure surfaces the server's second-instance requirement verbatim", async () => {
  onMutate = () =>
    plainError(
      "no other active Sluice instance to issue revoke; enroll a second instance first",
      503,
    );
  await mountPage("admin");
  await openTab("Instances", "Enrolled instances");
  clickButton((t) => t.includes("Revoke…"));
  await flushUntil(() => {
    expect(container.textContent).toContain("refuses self-revocation");
  });
  setInput("Type sluice-a to confirm", "sluice-a");
  clickButton((t) => t === "Revoke credential");
  await flushUntil(() => {
    expect(container.textContent).toContain("enroll a second instance first");
  });
  expect(mutations).toHaveLength(1); // no auto-retry
});

// ── Enrollment unknown outcome ──────────────────────────────────────────────

it("an unknown enrollment outcome latches, clears the single-use token, and never retries", async () => {
  onMutate = () => Promise.reject(new TypeError("network down"));
  await mountPage("admin");
  await openTab("Instances", "Enroll a new instance");
  setInput("Instance name", "sluice-b");
  setInput("Endpoint (host:port)", "10.0.0.6:8443");
  setInput("Server certificate fingerprint (TOFU pin)", "ff".repeat(32));
  setInput("Enrollment token (single-use)", "tok-secret-1");
  clickButton((t) => t.includes("Enroll instance…"));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "consumed by a successful exchange",
    );
  });
  clickButton((t) => t === "Enroll instance");
  await flushUntil(() => {
    expect(container.textContent).toContain("Enrollment outcome unknown");
  });
  expect(mutations).toHaveLength(1);
  expect(container.textContent).toContain("Do NOT retry with the same token");
  // The single-use token is cleared from the form; other fields survive.
  const tokenInput = Array.from(
    container.querySelectorAll('input[type="password"]'),
  )[0];
  expect(tokenInput instanceof HTMLInputElement && tokenInput.value).toBe("");
  expect(container.textContent).toContain("Last change unconfirmed");
  // The latch blocks further mutations until a fresh refresh succeeds.
  const enrollBtn = Array.from(container.querySelectorAll("button")).find((b) =>
    (b.textContent ?? "").includes("Enroll instance…"),
  );
  expect(enrollBtn?.disabled).toBe(true);
});

// ── Policies: duplicate name 409 + delete ceremony ─────────────────────────

it("a duplicate policy name renders the 409 conflict; delete is a T2 ceremony", async () => {
  onMutate = (method) =>
    method === "POST"
      ? plainError(
          'a CDR policy rule with that name already exists: "finance-enforce"',
          409,
        )
      : okJSON({ removed: "finance-enforce" });
  await mountPage("admin");
  await openTab("Policies", "finance-enforce");
  setInput("Name (unique — this is the rule's identity)", "finance-enforce");
  clickButton((t) => t === "Add rule");
  await flushUntil(() => {
    expect(container.textContent).toContain("already exists");
  });
  expect(mutations).toHaveLength(1);

  clickButton((t) => t.includes("Delete…"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Enforcement changes immediately");
  });
  clickButton((t) => t === "Delete rule");
  await flushUntil(() => {
    expect(mutations).toHaveLength(2);
  });
  expect(mutations[1]?.method).toBe("DELETE");
  expect(mutations[1]?.url).toBe("/api/cdr/policies?name=finance-enforce");
});
