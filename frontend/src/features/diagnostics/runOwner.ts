// FE-4 active-diagnostic request ownership (hardening §10). The
// implementation moved verbatim to src/shared/runOwner.ts when the 2A Policy
// Tester became its second real consumer; this module keeps the diagnostics
// import path and names stable so the FE-4 cancellation contract (and its
// tests) are untouched.
export type { RequestRunOwner as DiagnoseRunOwner } from "../../shared/runOwner";
export { createRequestRunOwner as createDiagnoseRunOwner } from "../../shared/runOwner";
