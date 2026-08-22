// CULVERT application shell (FE-2 §4): sidebar navigation, topbar context,
// skip link, main region, toast region. Auth/RBAC arrive in FE-3 — the nav
// below is static metadata proving the information architecture; entries not
// yet migrated render as non-interactive "planned" rows rather than fake
// routes.
import { useState } from "react";
import type { JSX, ReactNode } from "react";
import { NavLink, Outlet } from "react-router";
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
import { IconButton } from "../design-system/primitives";
import { readThemePreference, setTheme } from "../design-system/theme";
import type { ThemePreference } from "../design-system/theme";
import styles from "./AppShell.module.css";

interface NavEntry {
  label: string;
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
    entries: [{ label: "Overview", to: "/" }],
  },
  {
    heading: "Monitor",
    icon: <IconActivity />,
    entries: [{ label: "Traffic" }, { label: "Audit Log" }],
  },
  {
    heading: "Policies",
    icon: <IconPolicy />,
    entries: [{ label: "Access Rules" }, { label: "Authentication Rules" }],
  },
  {
    heading: "Security",
    icon: <IconShield />,
    entries: [{ label: "Content & Scanning" }, { label: "Certificates" }],
  },
  {
    heading: "Platform",
    icon: <IconServer />,
    entries: [{ label: "Cluster" }, { label: "Release Management" }],
  },
  {
    heading: "Administration",
    icon: <IconUsers />,
    entries: [{ label: "Administrators" }, { label: "Settings" }],
  },
  {
    heading: "Experimental",
    icon: <IconMonitor />,
    entries: [{ label: "Design System", to: "/design-system" }],
  },
];

function ThemeSwitcher(): JSX.Element {
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
          {NAV.map((section) => (
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
      </header>
      <main id="main" className={styles.main} tabIndex={-1}>
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
