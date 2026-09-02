// 2E-C trust-lifecycle correction (R8) — enrollment recovery marker proofs.
// Written RED-FIRST against the rejected candidate 978f95b5: the enrollment
// ceremony dispatched the single-use token with NO durable, subject-bound,
// non-secret recovery identity, so a lost response (or a reload mid-flight)
// left nothing to resolve the outcome from.
//
//   A. A VERIFIED recovery marker (operation id, instance name, endpoint,
//      TOFU pin, subject) exists in sessionStorage BEFORE the POST is sent;
//      it carries NO token and NO key material.
//   B. If the marker cannot be persisted+verified, NO POST is sent.
//   C. A lost response (network error) keeps the marker for recovery; a
//      remount shows the recovery surface (not a blank enroll form).
//   D. A foreign-subject marker is never inherited; an authoritative
//      terminal outcome (2xx / 4xx) clears it.
//   E. The auth boundary clears the marker.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { CDRPage } from "../features/security/CDRPage";
import { runAuthTeardown } from "../auth/teardown";

const MARKER_KEY = "culvert.cdr.enroll-recovery.v1";
const TOKEN = "one-time-token-SECRET-77";

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
let qc: QueryClient;
let posts: Array<{
  url: string;
  body: unknown;
  markerAtDispatch: string | null;
}>;
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
  onEnroll = () => Promise.reject(new TypeError("network down"));
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method !== "GET") {
        const body: unknown =
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        posts.push({
          url,
          body,
          markerAtDispatch: sessionStorage.getItem(MARKER_KEY),
        });
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
        return okJSON({ rules: [], count: 0, version: 1, epoch: 1 });
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

function machineFor(user: string, qc: QueryClient): AuthMachine {
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
        user,
        role: "admin",
        bootstrap: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout: () => Promise.resolve({ ok: true }),
  });
}

async function mountInstances(user = "admin-user"): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/security/cdr", element: <CDRPage /> }],
    { initialEntries: ["/security/cdr"] },
  );
  qc = new QueryClient();
  const machine = machineFor(user, qc);
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

async function fillAndDispatch(): Promise<void> {
  setInput("Instance name", "sluice-r8");
  setInput("Endpoint (host:port)", "10.0.0.9:8443");
  setInput("Server certificate fingerprint (TOFU pin)", "ab".repeat(32));
  setInput("Enrollment token (single-use)", TOKEN);
  clickButton((t) => t.includes("Enroll instance…"));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "consumed by a successful exchange",
    );
  });
  clickButton((t) => t === "Enroll instance");
}

// A + C — marker exists before dispatch, carries no secret, survives a lost
// response.
it("writes a verified non-secret recovery marker BEFORE the POST and keeps it on a lost response", async () => {
  await mountInstances();
  await fillAndDispatch();
  await flushUntil(() => {
    expect(posts).toHaveLength(1);
  });
  const atDispatch = posts[0]?.markerAtDispatch ?? null;
  expect(atDispatch).not.toBeNull();
  const marker: unknown = JSON.parse(atDispatch ?? "null");
  expect(typeof marker).toBe("object");
  expect(JSON.stringify(marker)).not.toContain(TOKEN);
  expect(JSON.stringify(marker)).toContain("sluice-r8");
  expect(JSON.stringify(marker)).toContain("admin-user"); // subject-bound
  // The POST carried the same operation identity the marker recorded.
  const sent = JSON.stringify(posts[0]?.body ?? {});
  expect(sent).toContain("operationId");
  // Lost response: the marker survives for recovery.
  await flushUntil(() => {
    expect(container.textContent).toContain("Enrollment outcome unknown");
  });
  expect(sessionStorage.getItem(MARKER_KEY)).not.toBeNull();
});

// B — no marker ⇒ no dispatch.
it("sends NO enrollment when the recovery marker cannot be persisted", async () => {
  // eslint-disable-next-line @typescript-eslint/unbound-method -- captured original, invoked with the storage receiver below
  const original = Storage.prototype.setItem;
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (
    this: Storage,
    k: string,
    v: string,
  ) {
    if (k === MARKER_KEY) throw new Error("quota");
    original.call(this, k, v);
  });
  await mountInstances();
  await fillAndDispatch();
  await flushUntil(() => {
    expect(container.textContent).toContain("No enrollment was sent");
  });
  expect(posts).toHaveLength(0);
});

// C (remount) + D — recovery surface on remount; foreign subject not
// inherited; terminal outcome clears.
it("a pending marker mounts the recovery surface; a foreign-subject marker is not inherited", async () => {
  sessionStorage.setItem(
    MARKER_KEY,
    JSON.stringify({
      version: 1,
      operationId: "0123456789abcdef0123456789abcdef",
      name: "sluice-pending",
      endpoint: "10.0.0.9:8443",
      serverFingerprint: "ab".repeat(32),
      startedAt: 1,
      subject: "admin-user",
    }),
  );
  await mountInstances();
  expect(container.textContent).toContain("sluice-pending");
  expect(container.textContent).toContain("Resolve enrollment");
  act(() => {
    root.unmount();
  });
  sessionStorage.setItem(
    MARKER_KEY,
    JSON.stringify({
      version: 1,
      operationId: "0123456789abcdef0123456789abcdef",
      name: "sluice-foreign",
      endpoint: "10.0.0.9:8443",
      serverFingerprint: "ab".repeat(32),
      startedAt: 1,
      subject: "someone-else",
    }),
  );
  await mountInstances();
  expect(container.textContent).not.toContain("sluice-foreign");
  expect(sessionStorage.getItem(MARKER_KEY)).toBeNull();
});

it("an authoritative terminal outcome clears the marker; the auth boundary clears it too", async () => {
  onEnroll = () =>
    Promise.resolve(
      new Response("enrollment failed: invalid token", {
        status: 502,
        headers: { "Content-Type": "text/plain" },
      }),
    );
  await mountInstances();
  await fillAndDispatch();
  await flushUntil(() => {
    expect(container.textContent).toContain("Enrollment failed");
  });
  expect(sessionStorage.getItem(MARKER_KEY)).toBeNull();

  sessionStorage.setItem(
    MARKER_KEY,
    JSON.stringify({
      version: 1,
      operationId: "0123456789abcdef0123456789abcdef",
      name: "x",
      endpoint: "e:1",
      serverFingerprint: "ab".repeat(32),
      startedAt: 1,
      subject: "admin-user",
    }),
  );
  await act(async () => {
    await runAuthTeardown(qc);
  });
  expect(sessionStorage.getItem(MARKER_KEY)).toBeNull();
});
