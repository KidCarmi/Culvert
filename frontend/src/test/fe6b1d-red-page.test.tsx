// FE-6B.1 CORRECTION ROUND 2 — RED matrix (page), committed on the reviewed
// candidate 8960ab53 BEFORE any product change (blocker B2): a lookup answer
// whose action-bound result contradicts the frozen contract in ONE fact must
// render as an UNVERIFIED lookup response — never "Committed".
//
//   R01 ca.rotate  persisted:false
//   R02 ca.import  target:"ui"
//   R03 replace    persisted:false
//   R04 delete     cleanup:"partial"
//   R05 CONTROL    the builders' rotate and replace records render Committed
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { CertificatesPage } from "../features/security/CertificatesPage";
import { ToastProvider } from "../design-system/toast";
import {
  CA_STATUS_HEALTHY,
  INVENTORY_HEALTHY,
  LISTENER_NET,
  LISTENER_SELF_SIGNED,
  OCSP_STATUS_DEFAULT,
  OP_COMMITTED,
  OP_ID,
  OP_ROTATE_COMMITTED,
  OP_UI_DELETE_COMMITTED,
  OP_UI_REPLACE_COMMITTED,
  okJSON,
} from "./fe6b1-fixtures";

let container: HTMLDivElement;
let root: Root;
let lookup: () => Promise<Response>;

function route(url: string): Promise<Response> {
  if (url.startsWith("/api/certificates")) return okJSON(INVENTORY_HEALTHY);
  if (url.startsWith("/api/ca/status")) return okJSON(CA_STATUS_HEALTHY);
  if (url.startsWith("/api/ocsp")) return okJSON(OCSP_STATUS_DEFAULT);
  if (url.startsWith("/api/settings/network"))
    return okJSON(LISTENER_NET(LISTENER_SELF_SIGNED, true, false));
  if (url.startsWith("/api/ca/operations/")) return lookup();
  return Promise.reject(new TypeError(`unexpected ${url}`));
}

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown) => route(String(input))),
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

async function mount(): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/security/certificates", element: <CertificatesPage /> }],
    { initialEntries: ["/security/certificates"] },
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
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
            <ToastProvider>
              <RouterProvider router={router} />
            </ToastProvider>
          </AuthProvider>
        </QueryClientProvider>
      </StrictMode>,
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

function text(): string {
  return container.textContent ?? "";
}
function record(): string {
  return (
    container.querySelector('[data-testid="operation-record"]')?.textContent ??
    ""
  );
}

async function click(name: string): Promise<void> {
  const btn = Array.from(container.querySelectorAll("button")).find(
    (b) => (b.textContent ?? "").trim() === name,
  );
  if (btn === undefined) throw new Error(`no button ${name}`);
  await act(async () => {
    btn.click();
    await Promise.resolve();
  });
}

async function typeInto(label: string, value: string): Promise<void> {
  const input = Array.from(container.querySelectorAll("input")).find((i) => {
    const id = i.getAttribute("id");
    const lab =
      id !== null ? container.querySelector(`label[for="${id}"]`) : null;
    return (lab?.textContent ?? "").trim() === label;
  });
  if (input === undefined) throw new Error(`no input ${label}`);
  await act(async () => {
    Reflect.set(HTMLInputElement.prototype, "value", value, input);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await Promise.resolve();
  });
}

type Rec = Record<string, unknown>;
function withResult(base: { result: Rec }, patch: Rec): Rec {
  return { ...base, result: { ...base.result, ...patch } };
}

const CONTRADICTORY: Array<[string, Rec]> = [
  [
    "R01 rotate persisted:false",
    withResult(OP_ROTATE_COMMITTED, { persisted: false }),
  ],
  ["R02 import target:ui", withResult(OP_COMMITTED, { target: "ui" })],
  [
    "R03 replace persisted:false",
    withResult(OP_UI_REPLACE_COMMITTED, { persisted: false }),
  ],
  [
    "R04 delete cleanup:partial",
    withResult(OP_UI_DELETE_COMMITTED, { cleanup: "partial" }),
  ],
];

for (const [name, rec] of CONTRADICTORY) {
  it(`${name}: the lookup renders unverified, never Committed`, async () => {
    lookup = () => okJSON(rec);
    await mount();
    await flushUntil(() => {
      expect(text()).toContain("CULVERT Root CA");
    });
    await typeInto("Operation ID", OP_ID);
    await click("Look up");
    await flushUntil(() => {
      expect(record()).toContain("could not be verified");
    });
    expect(record()).not.toContain("Committed");
    expect(record()).not.toContain("Audited");
  });
}

it("R05 control: the builders' rotate and replace records render Committed", async () => {
  lookup = () => okJSON(OP_ROTATE_COMMITTED);
  await mount();
  await flushUntil(() => {
    expect(text()).toContain("CULVERT Root CA");
  });
  await typeInto("Operation ID", OP_ID);
  await click("Look up");
  await flushUntil(() => {
    expect(record()).toContain("Committed");
  });
  lookup = () => okJSON(OP_UI_REPLACE_COMMITTED);
  await click("Look up");
  await flushUntil(() => {
    expect(record()).toContain("Committed");
  });
  expect(record()).not.toContain("could not be verified");
});
