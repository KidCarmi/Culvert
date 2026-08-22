import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it } from "vitest";
import { createQueryClient } from "../api/query";
import { AppShell } from "../layouts/AppShell";
import { OverviewPage } from "../features/overview/OverviewPage";
import { ToastProvider } from "../design-system/toast";

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
});
afterEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = undefined;
});

it("mounts the application shell with navigation and overview", () => {
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
  act(() => {
    root.render(
      <StrictMode>
        <QueryClientProvider client={createQueryClient()}>
          <ToastProvider>
            <RouterProvider router={router} />
          </ToastProvider>
        </QueryClientProvider>
      </StrictMode>,
    );
  });
  expect(container.textContent).toContain("CULVERT");
  expect(container.textContent).toContain("Secure Web Gateway");
  expect(container.textContent).toContain("Overview");
  expect(container.textContent).toContain("Design System");
  // Skip link present and first in DOM order.
  const skip = container.querySelector("a.skip-link");
  expect(skip?.getAttribute("href")).toBe("#main");
  act(() => {
    root.unmount();
  });
  container.remove();
});
