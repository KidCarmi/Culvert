// FE-3 setup credential validation — a UX MIRROR of the server's rules
// (store.go validatePasswordComplexity + apiSetupComplete's username check).
// The server remains authoritative; these exist so the operator learns of a
// problem before the credential travels.

/** Mirrors apiSetupComplete: trimmed username must be 1–64 characters. */
export function usernameProblem(user: string): string | undefined {
  const trimmed = user.trim();
  if (trimmed.length < 1 || trimmed.length > 64) {
    return "Username must be 1–64 characters.";
  }
  return undefined;
}

/** Mirrors validatePasswordComplexity (≥8 chars; upper+lower+digit; ≤72
 * BYTES — bcrypt's hard limit, measured in UTF-8 bytes, not characters). */
export function passwordProblem(pass: string): string | undefined {
  if (pass.length < 8) return "Password must be at least 8 characters.";
  if (new TextEncoder().encode(pass).length > 72) {
    return "Password must be at most 72 bytes (bcrypt limit).";
  }
  if (!/[A-Z]/.test(pass) || !/[a-z]/.test(pass) || !/[0-9]/.test(pass)) {
    return "Password must contain at least one uppercase letter, one lowercase letter, and one digit.";
  }
  return undefined;
}
