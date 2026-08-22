// SEC-TLSFB-1 (v2 half): the server no longer publishes the TLS self-sign
// CAUSE on the unauthenticated endpoints (/api/setup/status,
// /api/auth/status) — the raw error can embed an operator-configured SAN or
// the appliance host name. See preAuthTLSFallbackReason in ui_auth.go.
//
// Both v2 banners render the cause conditionally, so with the reason now
// always empty they would silently drop their detail clause and leave the
// operator with nothing: no cause and no idea where to find one. These tests
// pin the empty-reason branch of each banner — the warning itself must still
// be prominent, and it must say where the cause actually lives.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createQueryClient } from "../api/query";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { AppShell } from "../layouts/AppShell";
import { TLSFallbackWarning } from "../features/auth/AuthScreen";
import { ToastProvider } from "../design-system/toast";

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(
      new Response("{}", {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    ),
  );
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => {
    root.unmount();
    await Promise.resolve();
  });
  container.remove();
  globalThis.IS_REACT_ACT_ENVIRONMENT = undefined;
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function render(node: React.ReactNode): Promise<void> {
  await act(async () => {
    root.render(<StrictMode>{node}</StrictMode>);
    await Promise.resolve();
  });
}

// ── Pre-auth banner (setup + login) ────────────────────────────────────────

it("pre-auth banner points at the authenticated diagnostic when the cause is withheld", async () => {
  await render(<TLSFallbackWarning active={true} reason="" />);
  const text = container.textContent ?? "";
  // The warning itself is the load-bearing half and must survive.
  expect(text).toContain("This connection is NOT encrypted");
  expect(text).toContain("may travel");
  // …and the operator is told where the cause is, not left with nothing.
  expect(text).toContain("Settings → Network & TLS");
  expect(text).toContain("not published on this unauthenticated page");
  // No orphaned detail clause.
  expect(text).not.toContain("Server detail:");
});

it("pre-auth banner still renders a server-supplied cause when one is present", async () => {
  await render(<TLSFallbackWarning active={true} reason="self-sign failed" />);
  const text = container.textContent ?? "";
  expect(text).toContain("Server detail: self-sign failed.");
  // The pointer is the empty-case substitute, not an addition.
  expect(text).not.toContain("not published on this unauthenticated page");
});

it("pre-auth banner stays absent when TLS is healthy", async () => {
  await render(<TLSFallbackWarning active={false} reason="" />);
  expect(container.textContent ?? "").not.toContain("NOT encrypted");
});

// ── Authenticated shell banner ─────────────────────────────────────────────

function shellMachine(
  qc: ReturnType<typeof createQueryClient>,
  tls: { tlsFallback: boolean; tlsFallbackReason: string },
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
        user: "admin",
        role: "admin",
        bootstrap: false,
        ...tls,
      }),
    postLogout: () => Promise.resolve({ ok: true }),
  });
}

async function renderShell(tls: {
  tlsFallback: boolean;
  tlsFallbackReason: string;
}): Promise<string> {
  const qc = createQueryClient();
  const machine = shellMachine(qc, tls);
  await machine.boot();
  const router = createMemoryRouter(
    [{ path: "/", element: <AppShell />, children: [] }],
    { initialEntries: ["/"] },
  );
  await render(
    <QueryClientProvider client={qc}>
      <ToastProvider>
        <AuthProvider machine={machine}>
          <RouterProvider router={router} />
        </AuthProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
  return container.textContent ?? "";
}

it("shell banner points at the settings surface when the cause is withheld", async () => {
  const text = await renderShell({
    tlsFallback: true,
    tlsFallbackReason: "",
  });
  expect(text).toContain("Management traffic is NOT encrypted");
  // This session IS authenticated, so the cause is genuinely reachable.
  expect(text).toContain("Settings → Network & TLS");
  expect(text).toContain("Restart the appliance to retry TLS.");
});

it("shell banner keeps a server-supplied cause inline", async () => {
  const text = await renderShell({
    tlsFallback: true,
    tlsFallbackReason: "self-sign failed",
  });
  expect(text).toContain("(self-sign failed)");
  expect(text).not.toContain("Settings → Network & TLS");
});

it("shell banner stays absent when TLS is healthy", async () => {
  const text = await renderShell({
    tlsFallback: false,
    tlsFallbackReason: "",
  });
  expect(text).not.toContain("Management traffic is NOT encrypted");
});
