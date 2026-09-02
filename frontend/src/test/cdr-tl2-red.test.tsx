// 2E-C trust-lifecycle correction ROUND 2 — browser-side RED matrix,
// written against d567f4d5:
//   R13.4/5  the recovery marker read-back verified only operationId + name
//            (a lying storage could corrupt the endpoint, pin, timestamp or
//            subject unnoticed) and the marker grammar was not validated.
//   R13.1–3  the enrollment result did not carry the post-operation facts,
//            so a failed auto-enable rendered "CDR was auto-enabled".
//   R12.10   browser Abandon clears only the marker (no appliance DELETE).
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { isRecord } from "../api/decode";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { CDRPage } from "../features/security/CDRPage";
import {
  ENROLL_RECOVERY_KEY,
  readEnrollRecovery,
  writeEnrollRecovery,
} from "../features/security/enrollRecovery";

const OP = "0123456789abcdef0123456789abcdef";
const FP = "ab".repeat(32);
const MARKER = {
  operationId: OP,
  name: "sluice-r13",
  endpoint: "10.0.0.9:8443",
  serverFingerprint: FP,
  startedAt: 1_700_000_000_000,
};

afterEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
});

describe("marker read-back verification (R13.4)", () => {
  for (const field of [
    "operationId",
    "name",
    "endpoint",
    "serverFingerprint",
    "startedAt",
    "subject",
  ] as const) {
    it(`a storage that corrupts ${field} fails the verified write`, () => {
      // eslint-disable-next-line @typescript-eslint/unbound-method -- captured original, invoked with the storage receiver below
      const original = Storage.prototype.setItem;
      vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (
        this: Storage,
        k: string,
        v: string,
      ) {
        if (k !== ENROLL_RECOVERY_KEY) {
          original.call(this, k, v);
          return;
        }
        const parsed: unknown = JSON.parse(v);
        if (!isRecord(parsed)) throw new Error("unexpected marker");
        const mutated: Record<string, unknown> = { ...parsed };
        switch (field) {
          case "operationId":
            mutated["operationId"] = "fedcba9876543210fedcba9876543210";
            break;
          case "name":
            mutated["name"] = "other-name";
            break;
          case "endpoint":
            mutated["endpoint"] = "attacker:8443";
            break;
          case "serverFingerprint":
            mutated["serverFingerprint"] = "cd".repeat(32);
            break;
          case "startedAt":
            mutated["startedAt"] = 1;
            break;
          case "subject":
            mutated["subject"] = "someone-else";
            break;
        }
        original.call(this, k, JSON.stringify(mutated));
      });
      expect(writeEnrollRecovery("admin-user", MARKER)).toBe(false);
    });
  }
});

describe("marker grammar (R13.5)", () => {
  function seed(overrides: Record<string, unknown>): void {
    sessionStorage.setItem(
      ENROLL_RECOVERY_KEY,
      JSON.stringify({
        version: 1,
        ...MARKER,
        subject: "admin-user",
        ...overrides,
      }),
    );
  }
  it.each([
    ["invalid operation id", { operationId: "short" }],
    ["empty name", { name: "" }],
    ["empty endpoint", { endpoint: "" }],
    ["malformed fingerprint", { serverFingerprint: "zz" }],
    ["non-finite timestamp", { startedAt: Number.POSITIVE_INFINITY }],
  ])("%s reads as unreadable, never valid", (_label, overrides) => {
    seed(overrides);
    expect(readEnrollRecovery("admin-user").kind).toBe("unreadable");
  });
});

// ── R13.1–3 + R12.10: page truth ────────────────────────────────────────────

function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

let container: HTMLDivElement;
let root: Root | null = null;
let posts: Array<{ method: string; url: string }>;
let onEnroll: () => Promise<Response>;

const CONFIG = {
  enabled: false,
  endpoint: "",
  failMode: "open",
  defaultProfile: "default",
  defaultMode: "ENFORCE",
  timeoutSec: 35,
  maxFileSizeMB: 50,
  chunkSizeKB: 64,
  serverFingerprint: "",
  certsDir: "",
  clientActive: false,
  failOpen: true,
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
  posts = [];
  onEnroll = () => okJSON({});
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method !== "GET") {
        posts.push({ method, url });
        if (url.includes("/api/cdr/instances/enroll")) return onEnroll();
        return okJSON({ ok: true });
      }
      if (url.includes("/api/cdr/config")) return okJSON(CONFIG);
      if (url.includes("/api/cdr/health"))
        return Promise.resolve(
          new Response("no active CDR client", {
            status: 503,
            headers: { "Content-Type": "text/plain" },
          }),
        );
      if (url.includes("/api/cdr/instances"))
        return okJSON({ instances: [], count: 0, version: 1 });
      if (url.includes("/api/cdr/policies"))
        return okJSON({
          rules: [],
          count: 0,
          version: 1,
          epoch: 1,
          integrity: { ok: true, issues: [] },
        });
      return Promise.reject(new TypeError(`unexpected ${method} ${url}`));
    }),
  );
});

afterEach(() => {
  if (root !== null) {
    const r = root;
    act(() => {
      r.unmount();
    });
    root = null;
  }
  container.remove();
  vi.unstubAllGlobals();
});

async function mountInstances(): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/security/cdr", element: <CDRPage /> }],
    { initialEntries: ["/security/cdr"] },
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
    expect(container.textContent).toContain("Runtime state");
  });
  clickButton((t) => t === "Instances");
  await flushUntil(() => {
    expect(container.textContent).toContain("Enrolled instances");
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

async function dispatchEnroll(): Promise<void> {
  setInput("Instance name", "sluice-r13");
  setInput("Endpoint (host:port)", "10.0.0.9:8443");
  setInput("Server certificate fingerprint (TOFU pin)", FP);
  setInput("Enrollment token (single-use)", "tok");
  clickButton((t) => t.includes("Enroll instance…"));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "consumed by a successful exchange",
    );
  });
  clickButton((t) => t === "Enroll instance");
}

it("a failed auto-enable is rendered from the returned facts, never as 'auto-enabled', and never invites re-enrollment", async () => {
  onEnroll = () =>
    okJSON({
      instance: {
        name: "sluice-r13",
        endpoint: "10.0.0.9:8443",
        serverFingerprint: FP,
        clientCertFingerprint: "sha256:" + "ee".repeat(32),
        enrolledAt: "2026-09-02T00:00:00Z",
      },
      stored: true,
      cdrEnabled: false,
      clientActive: false,
      autoEnable: {
        attempted: true,
        succeeded: false,
        error: "cdr toggle: mkdir: not a directory",
      },
      receiptState: "stored",
    });
  await mountInstances();
  await dispatchEnroll();
  await flushUntil(() => {
    expect(container.textContent).toContain("Enrolled sluice-r13");
  });
  expect(container.textContent).toContain("CDR is still disabled");
  expect(container.textContent).toContain("Do not re-enroll");
  expect(container.textContent).not.toContain("auto-enabled");
});

it("Abandon clears only the browser marker; no appliance receipt is deleted", async () => {
  sessionStorage.setItem(
    ENROLL_RECOVERY_KEY,
    JSON.stringify({ version: 1, ...MARKER, subject: "admin-user" }),
  );
  await mountInstances();
  clickButton((t) => t === "Abandon recovery…");
  await flushUntil(() => {
    expect(container.textContent).toContain("keeps its durable receipt");
  });
  clickButton((t) => t === "Abandon recovery");
  await flushUntil(() => {
    expect(sessionStorage.getItem(ENROLL_RECOVERY_KEY)).toBeNull();
  });
  expect(posts.filter((p) => p.method === "DELETE")).toHaveLength(0);
});
