// FE-3 RBAC helper (§15): ONE role ordering matching server doctrine
// (store.go roleLevels: viewer=1, operator=2, admin=3; UIRole.HasRole).
// Frontend role handling is UX only — the backend (requireRole + the C2
// metadata middleware) remains the authorization boundary. Components
// consume capability/minRole metadata through hasRole; scattered
// `role === "admin"` comparisons are not the pattern.
import type { Role } from "../api/auth";

const roleRank: Record<Role, number> = {
  viewer: 1,
  operator: 2,
  admin: 3,
};

/** hasRole mirrors the server's UIRole.HasRole: role satisfies minRole. */
export function hasRole(role: Role, minRole: Role): boolean {
  return roleRank[role] >= roleRank[minRole];
}
