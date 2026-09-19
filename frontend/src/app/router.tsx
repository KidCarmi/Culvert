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
import { IdentityProvidersPage } from "../features/objects/IdentityProvidersPage";
import { AdministratorsPage } from "../features/administration/AdministratorsPage";
import { ContentSecurityPage } from "../features/security/ContentSecurityPage";
import { DecryptionPage } from "../features/security/DecryptionPage";
import { CDRPage } from "../features/security/CDRPage";
import { CertificatesPage } from "../features/security/CertificatesPage";
import { PACPage } from "../features/network/pac/PACPage";
import { UpstreamPage } from "../features/network/upstream/UpstreamPage";

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
          {
            // FE-6A.1 (FE-V27 read): viewer floor — uiRoutes GET /api/idp.
            path: "objects/identity-providers",
            element: <IdentityProvidersPage />,
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
            // FE-6B.1 (FE-V28/FE-V29 read): viewer floor — uiRoutes GET
            // /api/certificates, /api/ca/status, /api/ocsp; the admin-only
            // operation lookup is gated inside the page.
            path: "security/certificates",
            element: <CertificatesPage />,
          },
          {
            path: "network/pac",
            element: <PACPage />,
          },
          {
            path: "network/upstream",
            element: <UpstreamPage />,
          },
          { path: "diagnostics", element: <DiagnosticsPage /> },
          { path: "governance", element: <GovernancePage /> },
          // FE-6A.1 (FE-V37 read): admin — uiRoutes GET /api/auth/users.
          { path: "administrators", element: <AdministratorsPage /> },
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
