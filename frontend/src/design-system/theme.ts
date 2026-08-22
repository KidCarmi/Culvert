// THE sanctioned theme-storage module (FE-2 §3; FRONTEND-SECURITY-CONTRACT
// §9.B1). This file is the ONLY place in the application allowed to touch
// localStorage — the ESLint ban is lifted for exactly this path in
// eslint.config.js. The single key `culvert-theme` (inherited from the legacy
// UI) is the only persistent browser state the product keeps.
//
// Theme model: "system" | "dark" | "light". "system" resolves against
// prefers-color-scheme live (no persisted duplication of the resolved value).
// The resolved theme is stamped as data-theme on <html> — never via style
// mutation.

export type ThemePreference = "system" | "dark" | "light";
export type ResolvedTheme = "dark" | "light";

const STORAGE_KEY = "culvert-theme";

function isThemePreference(v: unknown): v is ThemePreference {
  return v === "system" || v === "dark" || v === "light";
}

export function readThemePreference(): ThemePreference {
  try {
    // eslint-disable-next-line no-restricted-globals -- sanctioned module (contract §9.B1)
    const raw = localStorage.getItem(STORAGE_KEY);
    return isThemePreference(raw) ? raw : "system";
  } catch {
    return "system"; // storage unavailable (private mode etc.) — never fatal
  }
}

export function writeThemePreference(pref: ThemePreference): void {
  try {
    if (pref === "system") {
      // eslint-disable-next-line no-restricted-globals -- sanctioned module (contract §9.B1)
      localStorage.removeItem(STORAGE_KEY);
    } else {
      // eslint-disable-next-line no-restricted-globals -- sanctioned module (contract §9.B1)
      localStorage.setItem(STORAGE_KEY, pref);
    }
  } catch {
    /* storage unavailable — theme still applies for the session */
  }
}

const systemDark = (): MediaQueryList =>
  window.matchMedia("(prefers-color-scheme: dark)");

export function resolveTheme(pref: ThemePreference): ResolvedTheme {
  if (pref === "system") return systemDark().matches ? "dark" : "light";
  return pref;
}

export function applyTheme(resolved: ResolvedTheme): void {
  document.documentElement.setAttribute("data-theme", resolved);
}

// initTheme applies the stored preference synchronously (called before React
// renders, so there is no theme flash) and keeps "system" live against OS
// changes. Returns the current preference.
export function initTheme(): ThemePreference {
  const pref = readThemePreference();
  applyTheme(resolveTheme(pref));
  systemDark().addEventListener("change", () => {
    if (readThemePreference() === "system") {
      applyTheme(resolveTheme("system"));
    }
  });
  return pref;
}

export function setTheme(pref: ThemePreference): void {
  writeThemePreference(pref);
  applyTheme(resolveTheme(pref));
}
