import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createQueryClient } from "../api/query";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { AppShell } from "../layouts/AppShell";
import { OverviewPage } from "../features/overview/OverviewPage";
import { ToastProvider } from "../design-system/toast";

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  // The shell's session probe (an authenticated /api/stats query) gets a
  // stubbed OK response — network behavior is proven in api tests.
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(
      new Response("{}", {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    ),
  );
});
afterEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = undefined;
  vi.unstubAllGlobals();
});

// An authenticated machine with a stubbed API: the FE-3 gate renders the
// shell only in the authenticated phase.
function authedMachine(qc: ReturnType<typeof createQueryClient>): AuthMachine {
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
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout: () => Promise.resolve({ ok: true }),
  });
}

it("mounts the application shell with navigation and overview", async () => {
  const qc = createQueryClient();
  const machine = authedMachine(qc);
  await machine.boot();
  const router = createMemoryRouter(
    [
      {
        path: "/",
        element: <AppShell />,
        children: [{ index: true, element: <OverviewPage /> }],
      },
    ],
    { initialEntries: ["/"] },
  );
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);
  await act(async () => {
    root.render(
      <StrictMode>
        <QueryClientProvider client={qc}>
          <ToastProvider>
            <AuthProvider machine={machine}>
              <RouterProvider router={router} />
            </AuthProvider>
          </ToastProvider>
        </QueryClientProvider>
      </StrictMode>,
    );
    await Promise.resolve();
  });
  expect(container.textContent).toContain("CULVERT");
  expect(container.textContent).toContain("Secure Web Gateway");
  expect(container.textContent).toContain("Overview");
  expect(container.textContent).toContain("Design System");
  // FE-3: identity + role + sign-out are visible in the shell.
  expect(container.textContent).toContain("admin");
  expect(container.textContent).toContain("Sign out");
  // Skip link present and first in DOM order.
  const skip = container.querySelector("a.skip-link");
  expect(skip?.getAttribute("href")).toBe("#main");
  await act(async () => {
    root.unmount();
    await Promise.resolve();
  });
  container.remove();
});
