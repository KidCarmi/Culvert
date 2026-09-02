// 2E-C trust-lifecycle correction — page proofs for the corrected contract:
//   R6  an unproven revocation (502) is rendered verbatim and produces NO
//       success notice; a proven one lists every generation + outcome.
//   R7  the credential lineage is visible on the row and listed in full on
//       the delete ceremony; the delete notice carries every orphaned
//       fingerprint.
//   R8  recovery classification: LANDED (marker cleared, enrolled notice),
//       NOT_ISSUED (cleared), AMBIGUOUS (kept), ISSUED_BUT_NOT_STORED with
//       the orphan-revocation ceremony (proof required) and with the CLI
//       fallback; a server refusal that NAMES the operation keeps the marker.
//   R10 a degraded policy store blocks adds and repairs by fenced position.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { CDRPage } from "../features/security/CDRPage";

const MARKER_KEY = "culvert.cdr.enroll-recovery.v1";
const OP = "0123456789abcdef0123456789abcdef";
const FP_A = "sha256:" + "aa".repeat(32);
const FP_B = "sha256:" + "bb".repeat(32);
const ORPHAN = "sha256:" + "0c".repeat(32);

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
    new Response(text, { status, headers: { "Content-Type": "text/plain" } }),
  );
}

let container: HTMLDivElement;
let root: Root;
let mutations: Array<{ method: string; url: string; body: unknown }>;
let onMutate: (method: string, url: string, body: unknown) => Promise<Response>;
let policies: unknown;

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

const INSTANCES = {
  instances: [
    {
      name: "sluice-a",
      endpoint: "10.0.0.5:8443",
      serverFingerprint: "cd".repeat(32),
      clientCertFingerprint: FP_B,
      enrolledAt: "2026-08-01T00:00:00Z",
      credentials: [
        { seq: 1, fingerprint: FP_A, state: "superseded", source: "enroll" },
        { seq: 2, fingerprint: FP_B, state: "active", source: "renewal" },
      ],
      liveFingerprints: [FP_B, FP_A],
    },
  ],
  count: 1,
  version: 4,
  updatedAt: "2026-08-30T09:00:00Z",
};

const HEALTHY_POLICIES = {
  rules: [{ priority: 10, name: "r-ok", mode: "ENFORCE" }],
  count: 1,
  version: 2,
  epoch: 5,
  integrity: { ok: true, issues: [] },
};

const DEGRADED_POLICIES = {
  rules: [
    { priority: 10, name: "dup", mode: "ENFORCE" },
    { priority: 5, name: "dup", mode: "REPORT_ONLY" },
    { priority: 1, name: "fine", mode: "ENFORCE" },
  ],
  count: 3,
  version: 2,
  epoch: 5,
  integrity: {
    ok: false,
    issues: [{ kind: "duplicate_name", name: "dup", positions: [0, 1] }],
  },
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
  sessionStorage.clear();
  mutations = [];
  policies = HEALTHY_POLICIES;
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
      if (url.includes("/api/cdr/config")) return okJSON(CONFIG);
      if (url.includes("/api/cdr/health"))
        return plainError("no active CDR client", 503);
      if (url.includes("/api/cdr/instances")) return okJSON(INSTANCES);
      if (url.includes("/api/cdr/policies")) return okJSON(policies);
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

function machineFor(qc: QueryClient): AuthMachine {
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
        user: "admin-user",
        role: "admin",
        bootstrap: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout: () => Promise.resolve({ ok: true }),
  });
}

async function mount(tab: "Instances" | "Policies"): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/security/cdr", element: <CDRPage /> }],
    { initialEntries: ["/security/cdr"] },
  );
  const qc = new QueryClient();
  const machine = machineFor(qc);
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
  clickButton((t) => t === tab);
  await flushUntil(() => {
    expect(container.textContent).toContain(
      tab === "Instances" ? "Enrolled instances" : "first match by priority",
    );
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

function clickButton(match: (t: string) => boolean): void {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    match(el.textContent ?? ""),
  );
  if (b === undefined) throw new Error("button not found");
  act(() => {
    b.click();
  });
}

function findButton(match: (t: string) => boolean): HTMLButtonElement | null {
  return (
    Array.from(container.querySelectorAll("button")).find((el) =>
      match(el.textContent ?? ""),
    ) ?? null
  );
}

function setInput(label: string, value: string): void {
  const lab = Array.from(container.querySelectorAll("label")).find((l) =>
    (l.textContent ?? "").includes(label),
  );
  if (lab === undefined) throw new Error(`label ${label} not found`);
  const input = container.querySelector(`#${lab.getAttribute("for") ?? ""}`);
  if (!(input instanceof HTMLInputElement)) throw new Error("input missing");
  act(() => {
    const desc = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    );
    desc?.set?.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

function seedMarker(): void {
  sessionStorage.setItem(
    MARKER_KEY,
    JSON.stringify({
      version: 1,
      operationId: OP,
      name: "sluice-pending",
      endpoint: "10.0.0.9:8443",
      serverFingerprint: "ab".repeat(32),
      startedAt: 1,
      subject: "admin-user",
    }),
  );
}

function recovery(extra: Record<string, unknown>): Record<string, unknown> {
  return {
    operationId: OP,
    revoked: false,
    hasReceipt: true,
    retryable: false,
    name: "sluice-pending",
    endpoint: "10.0.0.9:8443",
    receiptState: "dispatched",
    ...extra,
  };
}

// ── R8: recovery classification ─────────────────────────────────────────────

it("LANDED_AND_STORED clears the marker and reports the enrolled credential", async () => {
  seedMarker();
  onMutate = () =>
    okJSON(
      recovery({
        classification: "LANDED_AND_STORED",
        fingerprint: FP_B,
        receiptState: "stored",
      }),
    );
  await mount("Instances");
  clickButton((t) => t === "Resolve enrollment");
  await flushUntil(() => {
    expect(container.textContent).toContain("Enrolled sluice-pending");
  });
  expect(mutations[0]).toMatchObject({
    method: "POST",
    url: "/api/cdr/instances/enroll/recover",
    body: { operationId: OP, endpoint: "10.0.0.9:8443" },
  });
  expect(sessionStorage.getItem(MARKER_KEY)).toBeNull();
  expect(container.textContent).not.toContain("Enrollment outcome unknown");
});

it("NOT_ISSUED clears the marker; AMBIGUOUS keeps it for a later retry", async () => {
  seedMarker();
  onMutate = () =>
    okJSON(
      recovery({
        classification: "AMBIGUOUS",
        retryable: true,
        error: "dial tcp: connection refused",
      }),
    );
  await mount("Instances");
  clickButton((t) => t === "Resolve enrollment");
  await flushUntil(() => {
    expect(container.textContent).toContain("AMBIGUOUS");
  });
  expect(container.textContent).toContain("connection refused");
  expect(sessionStorage.getItem(MARKER_KEY)).not.toBeNull();
  expect(findButton((t) => t === "Resolve enrollment")?.disabled).toBe(false);

  onMutate = () =>
    okJSON(
      recovery({ classification: "NOT_ISSUED", receiptState: "not_issued" }),
    );
  clickButton((t) => t === "Resolve enrollment");
  await flushUntil(() => {
    expect(container.textContent).toContain("NOT ISSUED");
  });
  expect(sessionStorage.getItem(MARKER_KEY)).toBeNull();
});

it("ISSUED_BUT_NOT_STORED offers the orphan-revocation ceremony and accepts only a proven deny", async () => {
  seedMarker();
  onMutate = (_m, url) =>
    url.includes("/recover")
      ? okJSON(
          recovery({
            classification: "ISSUED_BUT_NOT_STORED",
            fingerprint: ORPHAN,
            receiptState: "issued_not_stored",
            revocation: {
              fingerprint: ORPHAN,
              apiAvailable: true,
              cli: "sluice node revoke " + ORPHAN,
            },
          }),
        )
      : okJSON({
          revoked: "",
          fingerprint: ORPHAN,
          fingerprints: [ORPHAN],
          outcomes: { [ORPHAN]: "tombstoned" },
          localPruned: true,
        });
  await mount("Instances");
  clickButton((t) => t === "Resolve enrollment");
  await flushUntil(() => {
    expect(container.textContent).toContain("ISSUED BUT NOT STORED");
  });
  expect(container.textContent).toContain(ORPHAN);
  expect(sessionStorage.getItem(MARKER_KEY)).not.toBeNull();
  clickButton((t) => t.includes("Revoke orphaned credential…"));
  await flushUntil(() => {
    expect(container.textContent).toContain("holds no key material");
  });
  // Confirm without the typed fence must be inert.
  clickButton((t) => t === "Revoke orphaned credential");
  expect(mutations).toHaveLength(1);
  setInput("Type 0c0c0c0c to confirm", "0c0c0c0c");
  clickButton((t) => t === "Revoke orphaned credential");
  await flushUntil(() => {
    expect(mutations).toHaveLength(2);
  });
  expect(mutations[1]).toMatchObject({
    method: "POST",
    url: "/api/cdr/instances/revoke",
    body: { fingerprint: ORPHAN },
  });
  await flushUntil(() => {
    expect(container.textContent).toContain("Revocation proven (tombstoned)");
  });
  expect(sessionStorage.getItem(MARKER_KEY)).toBeNull();
});

it("ISSUED_BUT_NOT_STORED without a pooled caller shows the exact Sluice-host command", async () => {
  seedMarker();
  onMutate = () =>
    okJSON(
      recovery({
        classification: "ISSUED_BUT_NOT_STORED",
        fingerprint: ORPHAN,
        revocation: {
          fingerprint: ORPHAN,
          apiAvailable: false,
          cli: "sluice node revoke --reason orphaned-enrollment " + ORPHAN,
        },
      }),
    );
  await mount("Instances");
  clickButton((t) => t === "Resolve enrollment");
  await flushUntil(() => {
    expect(container.textContent).toContain("Run on the Sluice host");
  });
  expect(container.textContent).toContain(
    "sluice node revoke --reason orphaned-enrollment " + ORPHAN,
  );
  expect(findButton((t) => t.includes("Revoke orphaned credential…"))).toBe(
    null,
  );
});

it("a server refusal that NAMES the operation keeps the marker for resolution", async () => {
  await mount("Instances");
  setInput("Instance name", "sluice-r8");
  setInput("Endpoint (host:port)", "10.0.0.9:8443");
  setInput("Server certificate fingerprint (TOFU pin)", "ab".repeat(32));
  setInput("Enrollment token (single-use)", "tok");
  onMutate = (_m, _u, body) => {
    const op =
      typeof body === "object" &&
      body !== null &&
      "operationId" in body &&
      typeof body.operationId === "string"
        ? body.operationId
        : "";
    return plainError(
      `enrollment outcome unknown (operation ${op}): rpc error: code = Unavailable — resolve via /api/cdr/instances/enroll/recover before retrying`,
      502,
    );
  };
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
  expect(container.textContent).toContain("could not settle its outcome");
  expect(sessionStorage.getItem(MARKER_KEY)).not.toBeNull();
  // The outcome is KNOWN-unresolved, not transport-unknown: no page latch,
  // but a second enrollment is blocked until this one is resolved.
  expect(container.textContent).not.toContain("Last change unconfirmed");
  expect(findButton((t) => t.includes("Enroll instance…"))?.disabled).toBe(
    true,
  );
});

// ── R6 + R7: revocation proof + lineage ─────────────────────────────────────

it("the lineage is visible on the row and every generation is listed on the delete ceremony", async () => {
  onMutate = () =>
    okJSON({
      removed: "sluice-a",
      clientCertFingerprint: FP_B,
      clientCertFingerprints: [FP_B, FP_A],
    });
  await mount("Instances");
  expect(container.textContent).toContain("2 live (superseded, active)");
  clickButton((t) => t.includes("Delete…"));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "every still-valid generation of this credential",
    );
  });
  expect(container.textContent).toContain(FP_A);
  expect(container.textContent).toContain(FP_B);
  setInput("Type sluice-a to confirm", "sluice-a");
  clickButton((t) => t === "Delete locally");
  await flushUntil(() => {
    expect(container.textContent).toContain("Deleted sluice-a (locally)");
  });
  expect(container.textContent).toContain("2 client certificates");
  expect(container.textContent).toContain(FP_A);
});

it("an unproven revocation (502) is rendered verbatim and produces no success; a proven one lists every outcome", async () => {
  onMutate = () =>
    plainError(
      `revocation outcome unproven for ${FP_B}: the Sluice server did not report a durable deny (outcome=REVOKE_OUTCOME_UNSPECIFIED revoked=false); nothing was pruned locally`,
      502,
    );
  await mount("Instances");
  clickButton((t) => t.includes("Revoke…"));
  await flushUntil(() => {
    expect(container.textContent).toContain("EVERY still-valid generation");
  });
  expect(container.textContent).toContain(FP_A);
  setInput("Type sluice-a to confirm", "sluice-a");
  clickButton((t) => t === "Revoke credential");
  await flushUntil(() => {
    expect(container.textContent).toContain("revocation outcome unproven");
  });
  expect(container.textContent).not.toContain("Revoked the credentials");
  expect(mutations).toHaveLength(1);

  onMutate = () =>
    okJSON({
      revoked: "sluice-a",
      fingerprint: FP_B,
      fingerprints: [FP_B, FP_A],
      outcomes: { [FP_B]: "revoked", [FP_A]: "already_revoked" },
      localPruned: true,
    });
  clickButton((t) => t === "Revoke credential");
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "Revoked the credentials of sluice-a",
    );
  });
  expect(container.textContent).toContain("already_revoked");
  expect(container.textContent).toContain("Local key material was destroyed");
});

// ── R10: degraded policy store ──────────────────────────────────────────────

it("a degraded policy store blocks adds and repairs by fenced position", async () => {
  policies = DEGRADED_POLICIES;
  onMutate = () =>
    okJSON({
      removed: "dup",
      position: 1,
      integrity: { ok: true, issues: [] },
    });
  await mount("Policies");
  expect(container.textContent).toContain("Policy store degraded");
  expect(container.textContent).toContain('duplicate name "dup"');
  expect(container.textContent).toContain("position(s) 0, 1");
  expect(findButton((t) => t === "Add rule")?.disabled).toBe(true);
  expect(findButton((t) => t === "Delete…")).toBe(null);
  clickButton((t) => t === "Delete at position 1…");
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "Repairs the degraded policy store",
    );
  });
  clickButton((t) => t === "Delete at position");
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  expect(mutations[0]).toMatchObject({
    method: "DELETE",
    url: "/api/cdr/policies?name=dup&position=1",
  });
});
