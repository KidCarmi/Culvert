// FE-3 first-run Setup (§8). Credential path only — the API's open/unauth
// mode is deliberately NOT exposed (see postSetupComplete in api/auth.ts:
// after {unauth:true} no in-band admin authentication path exists).
//
// Success is never claimed from the POST alone: the machine re-reads
// setup/status AND auth/status before the app renders authenticated state.
// A persistence-failure 500 rolls the server back and stays retryable — the
// form is NOT wiped. The password exists only in component memory.
import { useRef, useState } from "react";
import type { FormEvent, JSX } from "react";
import { useNavigate } from "react-router";
import { ApiError } from "../../api/client";
import { postSetupComplete } from "../../api/auth";
import { useAuth } from "../../auth/AuthProvider";
import { Button, Callout } from "../../design-system/primitives";
import { InputField } from "../../design-system/forms";
import { AuthScreen } from "./AuthScreen";
import { passwordProblem, usernameProblem } from "./validation";
import styles from "./auth.module.css";

interface FieldErrors {
  user?: string;
  pass?: string;
  pass2?: string;
}

type FormNotice =
  | { kind: "persistence"; text: string }
  | { kind: "lockout"; text: string }
  | { kind: "error"; text: string }
  | null;

export function SetupPage(): JSX.Element {
  const { state, machine } = useAuth();
  const navigate = useNavigate();
  const [user, setUser] = useState("admin");
  const [pass, setPass] = useState("");
  const [pass2, setPass2] = useState("");
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [notice, setNotice] = useState<FormNotice>(null);
  const [busy, setBusy] = useState(false);
  const userRef = useRef<HTMLInputElement>(null);
  const passRef = useRef<HTMLInputElement>(null);
  const pass2Ref = useRef<HTMLInputElement>(null);

  const submit = async (ev: FormEvent): Promise<void> => {
    ev.preventDefault();
    if (busy) return;
    const trimmed = user.trim();
    const errs: FieldErrors = {};
    const up = usernameProblem(user);
    if (up !== undefined) errs.user = up;
    const pp = passwordProblem(pass);
    if (pp !== undefined) errs.pass = pp;
    if (pass2 !== pass) errs.pass2 = "Passwords do not match.";
    setFieldErrors(errs);
    setNotice(null);
    if (errs.user !== undefined) return userRef.current?.focus();
    if (errs.pass !== undefined) return passRef.current?.focus();
    if (errs.pass2 !== undefined) return pass2Ref.current?.focus();

    setBusy(true);
    try {
      await postSetupComplete(trimmed, pass);
      // §8: POST success alone is not "setup succeeded" — confirm with fresh
      // setup/status + auth/status through the authoritative machine.
      const after = await machine.refresh();
      if (after.phase === "authenticated") {
        setPass("");
        setPass2("");
        void navigate("/", { replace: true });
        return;
      }
      if (after.phase === "setup_required") {
        setNotice({
          kind: "error",
          text: "The appliance still reports setup as incomplete. Nothing was saved — please retry.",
        });
      }
      // unauthenticated: credentials saved but the auto-login cookie did not
      // land — the gate renders the login screen; secrets are cleared by
      // unmount and the state below.
      setPass("");
      setPass2("");
    } catch (err) {
      if (err instanceof ApiError && err.kind === "http") {
        if (err.status === 500) {
          setNotice({
            kind: "persistence",
            text:
              err.bodyText !== undefined && err.bodyText !== ""
                ? err.bodyText
                : "The appliance could not save the credential to disk.",
          });
        } else if (err.status === 429) {
          setNotice({
            kind: "lockout",
            text: err.bodyText ?? "Too many attempts — wait before retrying.",
          });
        } else if (err.status === 403) {
          setNotice({
            kind: "error",
            text: "Setup was already completed elsewhere. Redirecting to sign-in…",
          });
          void machine.refresh();
        } else {
          setNotice({
            kind: "error",
            text:
              err.bodyText !== undefined && err.bodyText !== ""
                ? err.bodyText
                : "Setup failed.",
          });
        }
      } else if (
        err instanceof ApiError &&
        (err.kind === "network" || err.kind === "timeout")
      ) {
        setNotice({
          kind: "error",
          text: "Could not reach the appliance — setup was NOT confirmed. Check the connection and retry; retrying is safe.",
        });
      } else {
        setNotice({
          kind: "error",
          text: "The appliance returned an unexpected response — setup was not confirmed.",
        });
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthScreen
      title="First-time setup"
      subtitle="Create the administrator account that secures this management interface. These credentials are required every time the dashboard opens."
      tlsFallback={state.tlsFallback}
      tlsFallbackReason={state.tlsFallbackReason}
    >
      {notice !== null && notice.kind === "persistence" && (
        <Callout variant="critical" title="Setup did NOT complete" role="alert">
          {notice.text} Your entries are preserved — fix the disk condition and
          submit again; retrying is safe.
        </Callout>
      )}
      {notice !== null && notice.kind === "lockout" && (
        <Callout variant="warning" title="Too many attempts" role="alert">
          {notice.text}
        </Callout>
      )}
      {notice !== null && notice.kind === "error" && (
        <Callout variant="critical" role="alert">
          {notice.text}
        </Callout>
      )}
      <form
        className={styles.form}
        onSubmit={(ev) => {
          void submit(ev);
        }}
        noValidate
      >
        <InputField
          label="Administrator username"
          required
          autoComplete="username"
          value={user}
          maxLength={64}
          inputRef={userRef}
          onChange={(e) => setUser(e.target.value)}
          {...(fieldErrors.user !== undefined
            ? { error: fieldErrors.user }
            : {})}
        />
        <InputField
          label="Password"
          required
          type="password"
          autoComplete="new-password"
          value={pass}
          help="At least 8 characters with an uppercase letter, a lowercase letter, and a digit (at most 72 bytes)."
          inputRef={passRef}
          onChange={(e) => setPass(e.target.value)}
          {...(fieldErrors.pass !== undefined
            ? { error: fieldErrors.pass }
            : {})}
        />
        <InputField
          label="Confirm password"
          required
          type="password"
          autoComplete="new-password"
          value={pass2}
          inputRef={pass2Ref}
          onChange={(e) => setPass2(e.target.value)}
          {...(fieldErrors.pass2 !== undefined
            ? { error: fieldErrors.pass2 }
            : {})}
        />
        <div className={styles.formActions}>
          <Button type="submit" variant="primary" disabled={busy}>
            {busy ? "Saving…" : "Create administrator account"}
          </Button>
        </div>
      </form>
    </AuthScreen>
  );
}
