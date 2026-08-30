// 2E-B FINAL CORRECTION — rotation operation-identity recovery proofs,
// written in final (green) form and executed against the reviewed candidate
// (56c23e64) for RED evidence:
//
//   BLOCKER A (frontend half): after a lost rotation response the UI must
//   classify ITS OWN operation from fresh truth — LANDED only when the
//   appliance holds a receipt for this operation's id; NOT-LANDED only when
//   the rotation sequence is unchanged; otherwise AMBIGUOUS (another admin
//   may have rotated) — never "landed because key_id changed".
//
//   MANDATORY MINOR C: an authoritative LANDED / NOT-LANDED resolution must
//   CLEAR the unresolved-operation latch (converting it into a durable local
//   notice) so the admin can intentionally start a NEW rotation with a NEW
//   operation id; AMBIGUOUS stays latched. Nothing is ever re-dispatched
//   automatically, and an old operation id is never reused.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { DecryptionPage } from "../features/security/DecryptionPage";
import { isRecord } from "../api/decode";

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
let mutations: Array<{ method: string; url: string; body: unknown }>;
let onMutate: (body: unknown) => Promise<Response>;
// Mutable privacy truth (the resolution tests move it under a lost response).
let privacyKeyId: string;
let privacySeq: number;
let privacyReceipts: Array<{
  operation_id: string;
  key_id: string;
  seq: number;
  ts: string;
}>;

const HEALTH = {
  sessions: {
    total: 1,
    by_outcome: { inspected: 1 },
    by_decision_source: { policy_inspect: 1 },
    by_tls_version: { "1.3": 1 },
  },
  failures: { total: 0, by_category: {}, by_stage: {}, top: [] },
  coverage: { inspected: 1, bypassed: 0, failed: 0, inspected_ratio: 1 },
  trend: [],
  autoexclude: {
    active: 0,
    pending: 0,
    hit_total: 0,
    rescue_total: 0,
    surge_total: 0,
    fail_open_profiles: 0,
    fail_open_rules: 0,
  },
};

function privacyTruth(): unknown {
  return {
    redact_hosts: true,
    scope: "traffic_destination",
    scope_fields: ["host", "uri"],
    key_provisioned: true,
    key_id: privacyKeyId,
    rotation_seq: privacySeq,
    rotation_receipts: privacyReceipts,
    revision: `sha256:rev-${privacyKeyId}-${String(privacySeq)}`,
  };
}

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
  privacyKeyId = "gen-aaaa";
  privacySeq = 4;
  privacyReceipts = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method !== "GET") {
        const body: unknown =
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        mutations.push({ method, url, body });
        return onMutate(body);
      }
      if (url.includes("/api/decryption/health")) return okJSON(HEALTH);
      if (url.includes("/api/decryption/redaction"))
        return okJSON(privacyTruth());
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

async function mountPrivacyTab(): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/security/decryption", element: <DecryptionPage /> }],
    { initialEntries: ["/security/decryption"] },
  );
  const qc = new QueryClient();
  const machine = new AuthMachine(qc, {
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
    expect(container.textContent).toContain("Coverage — since process start");
  });
  clickButton((t) => t === "Destination Privacy");
  await flushUntil(() => {
    expect(container.textContent).toContain("Destination privacy");
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

function rotateButton(): HTMLButtonElement {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    (el.textContent ?? "").includes("Rotate pseudonym key…"),
  );
  if (b === undefined) throw new Error("rotate button not mounted");
  return b;
}

async function openRotateCeremonyAndType(): Promise<void> {
  clickButton((t) => t.includes("Rotate pseudonym key…"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Type ROTATE");
  });
  const input = Array.from(container.querySelectorAll("input")).find((i) =>
    (i.labels?.[0]?.textContent ?? "").includes("Type ROTATE"),
  );
  if (input === undefined) throw new Error("typed input not found");
  act(() => {
    const proto = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    );
    proto?.set?.call(input, "ROTATE");
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

function sentOperationId(index: number): string {
  const m = mutations[index];
  if (m === undefined || !isRecord(m.body)) throw new Error("no mutation body");
  const op = m.body["operation_id"];
  if (typeof op !== "string" || op === "") {
    throw new Error("rotation was dispatched without an operation identity");
  }
  return op;
}

// ── BLOCKER A: another admin's rotation must never read as ours ─────────────

it("a concurrent rotation is AMBIGUOUS for our lost operation — never 'landed', still latched", async () => {
  await mountPrivacyTab();
  await openRotateCeremonyAndType();
  // Our request dies in transport; meanwhile ANOTHER ADMIN's rotation lands
  // (generation + sequence move, a receipt for THEIR operation appears).
  onMutate = () => {
    privacyKeyId = "gen-other";
    privacySeq += 1;
    privacyReceipts = [
      {
        operation_id: "op-of-someone-else",
        key_id: "gen-other",
        seq: privacySeq,
        ts: "2026-08-30T10:00:00Z",
      },
    ];
    return Promise.reject(new TypeError("network down"));
  };
  clickButton((t) => t === "Rotate pseudonym key");
  await flushUntil(() => {
    expect(container.textContent).toContain("Outcome unconfirmed");
  });
  clickButton((t) => t === "Refresh state");
  await flushUntil(() => {
    expect(container.textContent).toContain("cannot yet be proven");
  });
  // The generation changed, but NOT provably by OUR operation: no landed /
  // not-landed claim, the rotate action stays withheld, nothing re-dispatched.
  expect(container.textContent).not.toContain("exactly once");
  expect(container.textContent).not.toContain("did not occur");
  expect(rotateButton().disabled).toBe(true);
  expect(mutations).toHaveLength(1);
});

// ── MANDATORY MINOR C: authoritative resolution unlatches ───────────────────

it("NOT-LANDED resolution clears the latch and allows a NEW rotation with a NEW operation id", async () => {
  await mountPrivacyTab();
  await openRotateCeremonyAndType();
  // The request never reached the appliance: truth is completely unchanged.
  onMutate = () => Promise.reject(new TypeError("network down"));
  clickButton((t) => t === "Rotate pseudonym key");
  await flushUntil(() => {
    expect(container.textContent).toContain("Outcome unconfirmed");
  });
  const firstOp = sentOperationId(0);
  clickButton((t) => t === "Refresh state");
  await flushUntil(() => {
    expect(container.textContent).toContain("did not occur");
  });
  // Authoritative NOT-LANDED: the latch converts into a notice and the admin
  // may deliberately start a fresh ceremony (nothing starts automatically).
  expect(rotateButton().disabled).toBe(false);
  expect(mutations).toHaveLength(1);

  await openRotateCeremonyAndType();
  onMutate = (body) => {
    if (!isRecord(body)) throw new Error("no body");
    return okJSON({
      redact_hosts: true,
      key_rotated: true,
      already_applied: false,
      operation_id: body["operation_id"],
      key_id: "gen-bbbb",
      rotation_seq: privacySeq + 1,
      revision: "sha256:after",
    });
  };
  clickButton((t) => t === "Rotate pseudonym key");
  await flushUntil(() => {
    expect(mutations).toHaveLength(2);
  });
  // A fresh operation identity — the failed operation's id is never reused.
  expect(sentOperationId(1)).not.toBe(firstOp);
});

it("LANDED resolution (our receipt exists) becomes a durable notice, unlatches, and never re-rotates", async () => {
  await mountPrivacyTab();
  await openRotateCeremonyAndType();
  // The rotation LANDED (the appliance recorded OUR receipt) but the
  // response was lost in transport.
  onMutate = (body) => {
    if (!isRecord(body)) throw new Error("no body");
    const op = body["operation_id"];
    privacyKeyId = "gen-cccc";
    privacySeq += 1;
    privacyReceipts = [
      {
        operation_id: typeof op === "string" ? op : "",
        key_id: "gen-cccc",
        seq: privacySeq,
        ts: "2026-08-30T10:00:00Z",
      },
    ];
    return Promise.reject(new TypeError("network down"));
  };
  clickButton((t) => t === "Rotate pseudonym key");
  await flushUntil(() => {
    expect(container.textContent).toContain("Outcome unconfirmed");
  });
  const firstOp = sentOperationId(0);
  clickButton((t) => t === "Refresh state");
  await flushUntil(() => {
    expect(container.textContent).toContain("landed exactly once");
  });
  // Proof came from OUR receipt — and the latch clears so a deliberate later
  // rotation is possible; nothing is dispatched automatically.
  expect(mutations).toHaveLength(1);
  expect(rotateButton().disabled).toBe(false);

  await openRotateCeremonyAndType();
  onMutate = (body) => {
    if (!isRecord(body)) throw new Error("no body");
    return okJSON({
      redact_hosts: true,
      key_rotated: true,
      already_applied: false,
      operation_id: body["operation_id"],
      key_id: "gen-dddd",
      rotation_seq: privacySeq + 1,
      revision: "sha256:after2",
    });
  };
  clickButton((t) => t === "Rotate pseudonym key");
  await flushUntil(() => {
    expect(mutations).toHaveLength(2);
  });
  expect(sentOperationId(1)).not.toBe(firstOp);
});
