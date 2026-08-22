// Router foundation (FE-2 §5): client-side library mode, basename /app
// (matching the FE-1B serving contract: every GET/HEAD deep link under /app
// receives the SPA shell). Infrastructure routes only — future product URLs
// are NOT faked here. /design-system is DELIBERATELY lazy-loaded so the real
// production bundle exercises dynamicImports → manifest → the Go validator.
import { createBrowserRouter } from "react-router";
import type { JSX } from "react";
import { AppShell, PageHeader } from "../layouts/AppShell";
import { ErrorState } from "../design-system/primitives";
import { OverviewPage } from "../features/overview/OverviewPage";

function NotFoundPage(): JSX.Element {
  return (
    <>
      <PageHeader title="Not found" />
      <ErrorState title="This page does not exist">
        The address is not part of the experimental CULVERT preview. Use the
        navigation to return to a known page.
      </ErrorState>
    </>
  );
}

export function createAppRouter(): ReturnType<typeof createBrowserRouter> {
  return createBrowserRouter(
    [
      {
        path: "/",
        element: <AppShell />,
        children: [
          { index: true, element: <OverviewPage /> },
          {
            path: "design-system",
            lazy: async () => {
              const mod = await import("../features/gallery/GalleryPage");
              return { Component: mod.GalleryPage };
            },
          },
          { path: "*", element: <NotFoundPage /> },
        ],
      },
    ],
    { basename: "/app" },
  );
}
