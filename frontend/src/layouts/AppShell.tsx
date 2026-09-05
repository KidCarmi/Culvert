// CULVERT application shell (FE-2 §4 + FE-3 §16): session-aware sidebar
// navigation, topbar identity/account area, skip link, main region. The
// shell mounts ONLY inside the authenticated phase (AuthGate). Navigation
// is filtered by the session role through capability metadata — hidden nav
// is UX, never security: the backend (requireRole + C2 metadata middleware)
// remains the authorization boundary. Planned entries are visible IA only,
// never routes; their minRole comes from uiRoutes evidence
// (ui_routes_meta.go), not invention: read surfaces carry viewer GETs
// (/api/logs, /api/audit, /api/policy, /api/ca/status, /api/cluster/status,
// /api/releases), while Administrators (/api/auth/users, GET=admin) and
// Settings (/api/config/export, GET=admin) are admin governance surfaces.
import { useEffect, useState } from "react";
import type { JSX, ReactNode } from "react";
import { NavLink, Outlet, useLocation } from "react-router";
import type { Role } from "../api/auth";
import { useAuth } from "../auth/AuthProvider";
import { hasRole } from "../auth/rbac";
import {
  CulvertMark,
  IconActivity,
  IconGauge,
  IconMenu,
  IconMonitor,
  IconMoon,
  IconPolicy,
  IconServer,
  IconShield,
  IconSun,
  IconUsers,
} from "../design-system/icons";
import { Button, Callout, IconButton } from "../design-system/primitives";
import { readThemePreference, setTheme } from "../design-system/theme";
import type { ThemePreference } from "../design-system/theme";
import styles from "./AppShell.module.css";

interface NavEntry {
  label: string;
  minRole: Role;
  to?: string; // real route; absent = planned (not yet migrated)
}

interface NavSection {
  heading: string;
  icon: JSX.Element;
  entries: readonly NavEntry[];
}

// Representative IA subset (docs/design/INFORMATION-ARCHITECTURE rationale;
// the full 38-view taxonomy migrates feature-round by feature-round).
const NAV: readonly NavSection[] = [
  {
    heading: "Overview",
    icon: <IconGauge />,
    entries: [{ label: "Dashboard", to: "/", minRole: "viewer" }],
  },
  {
    heading: "Monitor",
    icon: <IconActivity />,
    entries: [
      { label: "Traffic", to: "/monitor/traffic", minRole: "viewer" },
      { label: "Audit Log", to: "/monitor/audit", minRole: "viewer" },
      { label: "History & Storage", to: "/monitor/history", minRole: "viewer" },
      { label: "Diagnostics", to: "/diagnostics", minRole: "viewer" },
    ],
  },
  {
    heading: "Policies",
    icon: <IconPolicy />,
    entries: [
      {
        label: "Access Rules",
        to: "/policies/access-rules",
        minRole: "viewer",
      },
      {
        label: "Authentication Rules",
        to: "/policies/authentication-rules",
        minRole: "viewer",
      },
      { label: "Policy Tester", to: "/policies/tester", minRole: "viewer" },
      {
        label: "Header Rewrite",
        to: "/policies/header-rewrite",
        minRole: "viewer",
      },
      {
        label: "Policy Learning",
        to: "/policies/learning",
        minRole: "viewer",
      },
    ],
  },
  {
    heading: "Objects",
    icon: <IconPolicy />,
    entries: [
      {
        label: "URL Categories",
        to: "/objects/url-categories",
        minRole: "viewer",
      },
      {
        label: "Category Groups",
        to: "/objects/category-groups",
        minRole: "viewer",
      },
      {
        label: "Decryption Profiles",
        to: "/objects/decryption-profiles",
        minRole: "viewer",
      },
      {
        label: "File Profiles",
        to: "/objects/file-profiles",
        minRole: "viewer",
      },
    ],
  },
  {
    heading: "Security",
    icon: <IconShield />,
    entries: [
      {
        label: "Content Security",
        to: "/security/content-security",
        minRole: "viewer",
      },
      {
        label: "Decryption",
        to: "/security/decryption",
        minRole: "viewer",
      },
      {
        label: "CDR Integration",
        to: "/security/cdr",
        minRole: "viewer",
      },
      { label: "Certificates", minRole: "viewer" },
    ],
  },
  {
    heading: "Network",
    icon: <IconActivity />,
    entries: [
      { label: "PAC", to: "/network/pac", minRole: "viewer" },
      { label: "Upstream Proxies", minRole: "viewer" },
    ],
  },
  {
    heading: "Platform",
    icon: <IconServer />,
    entries: [
      { label: "Cluster", minRole: "viewer" },
      { label: "Release Management", minRole: "viewer" },
    ],
  },
  {
    heading: "Administration",
    icon: <IconUsers />,
    entries: [
      { label: "Administrators", minRole: "admin" },
      { label: "Settings", minRole: "admin" },
      { label: "Governance", to: "/governance", minRole: "admin" },
    ],
  },
  {
    heading: "Experimental",
    icon: <IconMonitor />,
    entries: [
      { label: "Design System", to: "/design-system", minRole: "viewer" },
    ],
  },
];

export function ThemeSwitcher(): JSX.Element {
  const [pref, setPref] = useState<ThemePreference>(readThemePreference());
  const choose = (p: ThemePreference): void => {
    setTheme(p);
    setPref(p);
  };
  const options: ReadonlyArray<{
    p: ThemePreference;
    label: string;
    icon: JSX.Element;
  }> = [
    { p: "system", label: "System theme", icon: <IconMonitor size={14} /> },
    { p: "dark", label: "Dark theme", icon: <IconMoon size={14} /> },
    { p: "light", label: "Light theme", icon: <IconSun size={14} /> },
  ];
  return (
    <div className={styles.themeGroup} role="group" aria-label="Theme">
      {options.map((o) => (
        <button
          key={o.p}
          type="button"
          className={styles.themeButton}
          aria-pressed={pref === o.p}
          aria-label={o.label}
          title={o.label}
          onClick={() => choose(o.p)}
        >
          {o.icon}
        </button>
      ))}
    </div>
  );
}

export function AppShell(): JSX.Element {
  const [navOpen, setNavOpen] = useState(false);
  const { state, machine } = useAuth();
  const [signingOut, setSigningOut] = useState(false);
  const location = useLocation();
  const role: Role = state.role ?? "viewer"; // defensive: gate guarantees non-null

  // Identity-continuity revalidation (no aggressive polling, and NOT
  // TanStack refetchOnWindowFocus — this is AUTH IDENTITY revalidation, not
  // data refetch): the session cookie is shared same-origin across tabs, so
  // the identity behind it can be replaced under this tab. Revalidate at
  // the operator boundaries — every v2 route transition, and the browser
  // returning to this tab (focus / visibility restoration). The machine
  // compares the fresh identity against what this tab renders and runs the
  // full collapsed teardown before any different identity/role may render.
  useEffect(() => {
    void machine.revalidateAuthenticatedSession();
  }, [machine, location.pathname]);
  useEffect(() => {
    const onFocus = (): void => {
      void machine.revalidateAuthenticatedSession();
    };
    const onVisibility = (): void => {
      if (document.visibilityState === "visible") onFocus();
    };
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [machine]);

  const signOut = (): void => {
    if (signingOut) return; // §12: no duplicate submission
    setSigningOut(true);
    void machine.logout(); // machine tears down + transitions; gate unmounts us
  };

  const visibleSections = NAV.map((s) => ({
    ...s,
    entries: s.entries.filter((e) => hasRole(role, e.minRole)),
  })).filter((s) => s.entries.length > 0);

  return (
    <div className={styles.shell}>
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <aside className={styles.sidebar} data-open={navOpen || undefined}>
        <div className={styles.brand}>
          <CulvertMark />
          <div>
            <div className={styles.brandName}>CULVERT</div>
            <div className={styles.brandTag}>Secure Web Gateway</div>
          </div>
        </div>
        <nav className={styles.nav} aria-label="Primary">
          {visibleSections.map((section) => (
            <div key={section.heading} className={styles.navSection}>
              <div className={styles.navHeading}>{section.heading}</div>
              {section.entries.map((e) =>
                e.to !== undefined ? (
                  <NavLink
                    key={e.label}
                    to={e.to}
                    end={e.to === "/"}
                    className={styles.navItem ?? ""}
                    onClick={() => setNavOpen(false)}
                  >
                    {section.icon}
                    {e.label}
                  </NavLink>
                ) : (
                  // Not yet migrated: visible IA, explicitly non-interactive.
                  <span
                    key={e.label}
                    className={styles.navPlanned}
                    aria-disabled="true"
                  >
                    {section.icon}
                    {e.label}
                    <span className={styles.plannedTag}>planned</span>
                  </span>
                ),
              )}
            </div>
          ))}
        </nav>
      </aside>
      <header className={styles.topbar}>
        <span className={styles.menuButton}>
          <IconButton
            label={navOpen ? "Close navigation" : "Open navigation"}
            aria-expanded={navOpen}
            onClick={() => setNavOpen((v) => !v)}
          >
            <IconMenu />
          </IconButton>
        </span>
        <span className={styles.previewBadge}>Experimental preview</span>
        <span className={styles.topbarSpacer} />
        <ThemeSwitcher />
        <span className={styles.account}>
          <span className={styles.accountUser}>{state.user}</span>
          <span className={styles.accountRole}>{role}</span>
          <Button
            size="sm"
            variant="ghost"
            onClick={signOut}
            disabled={signingOut}
          >
            {signingOut ? "Signing out…" : "Sign out"}
          </Button>
        </span>
      </header>
      <main id="main" className={styles.main} tabIndex={-1}>
        {state.tlsFallback && (
          <div className={styles.tlsBanner}>
            <Callout
              variant="critical"
              title="Management traffic is NOT encrypted"
              role="alert"
            >
              This admin session runs over plain HTTP because automatic TLS
              setup failed
              {/* The reason is empty on /api/auth/status by design — that
                  route is unauthenticated and the raw x509 error can quote an
                  operator-configured SAN (ui_auth.go jsonOKAuthStatus). It is
                  rendered here only if some future authenticated source
                  supplies it; otherwise point at where the cause lives. */}
              {state.tlsFallbackReason !== ""
                ? ` (${state.tlsFallbackReason})`
                : ""}
              . The cause is on Settings → Network &amp; TLS and in the server
              log. Restart the appliance to retry TLS.
            </Callout>
          </div>
        )}
        <Outlet />
      </main>
    </div>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}): JSX.Element {
  return (
    <header className={styles.pageHeader}>
      <div>
        <h1 className={styles.pageTitle}>{title}</h1>
        {subtitle !== undefined && (
          <p className={styles.pageSubtitle}>{subtitle}</p>
        )}
      </div>
      {actions}
    </header>
  );
}
