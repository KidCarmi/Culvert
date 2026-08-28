// Slice 2A §17/§27: the server's referencedBy[].view value is DATA, never a
// client route. This component test renders WhereUsed against stubbed
// reference responses and proves: (1) an access-rule/policy consumer links to
// the REAL migrated route by its stable ID; (2) an auth-rule consumer renders
// as information only (no link — its surface is not migrated); (3) a
// malicious/arbitrary server view string can never mint a route or a link;
// (4) references are fetched only on explicit operator interest.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { WhereUsed } from "../features/policy/WhereUsed";
import type { ObjectRefConsumer } from "../api/policy";

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  container.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function stubReferences(
  referencedBy: ObjectRefConsumer[],
): ReturnType<typeof vi.fn> {
  const fn = vi.fn(() =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          object: { type: "category", name: "News" },
          referencedBy,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    ),
  );
  vi.stubGlobal("fetch", fn);
  return fn;
}

async function mount(
  referencedBy: ObjectRefConsumer[],
): Promise<ReturnType<typeof vi.fn>> {
  const fetchStub = stubReferences(referencedBy);
  const router = createMemoryRouter(
    [
      {
        path: "/*",
        element: <WhereUsed type="category" name="News" />,
      },
    ],
    { initialEntries: ["/detail"] },
  );
  act(() => {
    root = createRoot(container);
    root.render(
      <StrictMode>
        <QueryClientProvider client={new QueryClient()}>
          <RouterProvider router={router} />
        </QueryClientProvider>
      </StrictMode>,
    );
  });
  return Promise.resolve(fetchStub);
}

async function openPanel(expectText: string): Promise<void> {
  const btn = container.querySelector("button");
  expect(btn?.textContent).toContain("Where used");
  act(() => {
    btn?.click();
  });
  // Flush the fetch → json → TanStack propagation deterministically, until
  // the panel content THIS test expects has rendered.
  await vi.waitFor(async () => {
    await act(async () => {
      await new Promise((r) => {
        setTimeout(r, 0);
      });
    });
    expect(container.textContent).toContain(expectText);
  });
}

it("fetches only on explicit operator interest", async () => {
  const fetchStub = await mount([]);
  expect(fetchStub).not.toHaveBeenCalled(); // §18: no fetch on render
  await openPanel("is not referenced");
  expect(fetchStub).toHaveBeenCalledTimes(1);
  const url = String(fetchStub.mock.calls[0]?.[0]);
  expect(url).toContain("/api/objects/references?");
});

it("access-rule/policy consumers deep-link by stable ID to the migrated route", async () => {
  await mount([
    {
      consumerType: "access-rule",
      id: "01J3ZV9E3JD0AAAABBBBCCCCDD",
      name: "Allow news",
      detail: "destCategory",
      view: "policy",
    },
  ]);
  await openPanel("Allow news");
  const link = container.querySelector("a");
  expect(link).not.toBeNull();
  expect(link?.getAttribute("href")).toBe(
    "/policies/access-rules?rule=01J3ZV9E3JD0AAAABBBBCCCCDD",
  );
});

it("auth-rule and category-group consumers deep-link by stable ID (2D-A §19)", async () => {
  await mount([
    {
      consumerType: "auth-rule",
      id: "01XAUTH",
      name: "printer waiver",
      detail: "destCategory",
      view: "authpolicy",
    },
    {
      consumerType: "category-group",
      id: "abc123def456",
      name: "Prod Allowed",
      detail: "categories",
      view: "catgroups",
    },
  ]);
  await openPanel("printer waiver");
  const hrefs = Array.from(container.querySelectorAll("a")).map((a) =>
    a.getAttribute("href"),
  );
  expect(hrefs).toContain("/policies/authentication-rules?rule=01XAUTH");
  expect(hrefs).toContain("/objects/category-groups?id=abc123def456");
});

it("an auth-rule consumer with an unreviewed view string renders info-only", async () => {
  await mount([
    {
      consumerType: "auth-rule",
      id: "01XAUTH",
      name: "printer waiver",
      detail: "destCategory",
      view: "not-the-reviewed-view",
    },
  ]);
  await openPanel("printer waiver");
  expect(container.querySelector("a")).toBeNull();
  expect(container.textContent).toContain("Authentication rule");
});

it("an arbitrary/malicious server view string can never mint a route", async () => {
  await mount([
    {
      consumerType: "access-rule",
      id: "01J3ZV9E3JD0AAAABBBBCCCCDD",
      name: "evil",
      detail: "destCategory",
      // NOT the reviewed (consumerType, view) pair — must not navigate.
      view: "../../auth/logout",
    },
    {
      consumerType: "future-thing",
      id: "01Y",
      name: "mystery",
      detail: "x",
      view: "javascript:alert(1)",
    },
  ]);
  await openPanel("mystery");
  // No anchor at all: the unreviewed pairs render as text; the raw view
  // string appears nowhere as a navigation target.
  expect(container.querySelector("a")).toBeNull();
  const html = container.innerHTML;
  expect(html).not.toContain('href="../../auth/logout"');
  expect(html).not.toContain("javascript:alert");
});
