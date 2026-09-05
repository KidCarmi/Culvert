// Router foundation (FE-2 §5 + FE-3 §17): client-side library mode,
// basename /app (matching the FE-1B serving contract: every GET/HEAD deep
// link under /app receives the SPA shell). The layout element is the FE-3
// AuthGate — every route, /design-system included, renders only through the
// authoritative auth phase (setup → login → shell); pre-setup exposes only
// the Setup UI. Infrastructure routes only — future product URLs are NOT
// faked here. /design-system is DELIBERATELY lazy-loaded so the real
// production bundle exercises dynamicImports → manifest → the Go validator.
import { createBrowserRouter } from "react-router";
import type { JSX } from "react";
import { PageHeader } from "../layouts/AppShell";
import { ErrorState } from "../design-system/primitives";
import { AuthGate } from "../features/auth/AuthGate";
import { OverviewPage } from "../features/overview/OverviewPage";
import { TrafficPage } from "../features/monitor/TrafficPage";
import { AuditPage } from "../features/monitor/AuditPage";
import { HistoryPage } from "../features/monitor/HistoryPage";
import { DiagnosticsPage } from "../features/diagnostics/DiagnosticsPage";
import { GovernancePage } from "../features/governance/GovernancePage";
import { AccessRulesPage } from "../features/policy/AccessRulesPage";
import { AuthRulesPage } from "../features/policy/AuthRulesPage";
import { TesterPage } from "../features/policy/TesterPage";
import { PolicyLearningPage } from "../features/learning/PolicyLearningPage";
import { HeaderRewritePage } from "../features/policy/HeaderRewritePage";
import { CategoryGroupsPage } from "../features/objects/CategoryGroupsPage";
import { UrlCategoriesPage } from "../features/objects/UrlCategoriesPage";
import { DecryptionProfilesPage } from "../features/objects/DecryptionProfilesPage";
import { FileProfilesPage } from "../features/objects/FileProfilesPage";
import { ContentSecurityPage } from "../features/security/ContentSecurityPage";
import { DecryptionPage } from "../features/security/DecryptionPage";
import { CDRPage } from "../features/security/CDRPage";
import { PACPage } from "../features/network/pac/PACPage";

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
        element: <AuthGate />,
        children: [
          { index: true, element: <OverviewPage /> },
          { path: "monitor/traffic", element: <TrafficPage /> },
          { path: "monitor/audit", element: <AuditPage /> },
          { path: "monitor/history", element: <HistoryPage /> },
          { path: "policies/access-rules", element: <AccessRulesPage /> },
          {
            path: "policies/authentication-rules",
            element: <AuthRulesPage />,
          },
          { path: "policies/tester", element: <TesterPage /> },
          {
            path: "policies/header-rewrite",
            element: <HeaderRewritePage />,
          },
          {
            path: "objects/url-categories",
            element: <UrlCategoriesPage />,
          },
          {
            path: "objects/category-groups",
            element: <CategoryGroupsPage />,
          },
          {
            path: "objects/decryption-profiles",
            element: <DecryptionProfilesPage />,
          },
          {
            path: "objects/file-profiles",
            element: <FileProfilesPage />,
          },
          { path: "policies/learning", element: <PolicyLearningPage /> },
          {
            path: "security/content-security",
            element: <ContentSecurityPage />,
          },
          {
            path: "security/decryption",
            element: <DecryptionPage />,
          },
          {
            path: "security/cdr",
            element: <CDRPage />,
          },
          {
            path: "network/pac",
            element: <PACPage />,
          },
          { path: "diagnostics", element: <DiagnosticsPage /> },
          { path: "governance", element: <GovernancePage /> },
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
