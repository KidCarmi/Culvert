// FE-3 route intent (§14). When a session expires the browser URL keeps the
// operator's place (memory + address bar only — NEVER persistent storage,
// never an external URL). After re-authentication the intent is honored ONLY
// if it names a known internal v2 route the new role is authorized for;
// anything else lands on Overview. Route data (API responses, forms, drafts,
// secrets) is never part of the intent — only the path.
import type { Role } from "../api/auth";
import { hasRole } from "./rbac";

export interface KnownRoute {
  path: string;
  minRole: Role;
}

// The REAL v2 route set (router.tsx). FE-3's routes are all viewer-readable;
// future rounds add entries here as real routes (never faked ahead of time).
export const KNOWN_ROUTES: readonly KnownRoute[] = [
  { path: "/", minRole: "viewer" },
  { path: "/monitor/traffic", minRole: "viewer" },
  { path: "/monitor/audit", minRole: "viewer" },
  { path: "/monitor/history", minRole: "viewer" },
  { path: "/policies/access-rules", minRole: "viewer" },
  { path: "/policies/authentication-rules", minRole: "viewer" },
  { path: "/policies/tester", minRole: "viewer" },
  { path: "/policies/learning", minRole: "viewer" },
  { path: "/objects/category-groups", minRole: "viewer" },
  { path: "/objects/decryption-profiles", minRole: "viewer" },
  { path: "/security/content-security", minRole: "viewer" },
  { path: "/security/decryption", minRole: "viewer" },
  { path: "/security/cdr", minRole: "viewer" },
  { path: "/network/pac", minRole: "viewer" },
  { path: "/diagnostics", minRole: "viewer" },
  { path: "/governance", minRole: "admin" }, // uiRoutes: /api/governance/control-plane GET=admin
  { path: "/design-system", minRole: "viewer" },
];

/** resolveRouteIntent: validate a candidate internal path against a route
 * table + the authenticated role. Pure — the table is a parameter so the
 * role-authorization arm is testable without faking production routes. */
export function resolveRouteIntent(
  path: string,
  role: Role,
  routes: readonly KnownRoute[] = KNOWN_ROUTES,
): string {
  const known = routes.find((r) => r.path === path);
  if (known === undefined) return "/"; // unknown or external — Overview
  if (!hasRole(role, known.minRole)) return "/"; // not authorized — Overview
  return known.path;
}
