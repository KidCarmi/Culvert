// FE-3 sign-in (§10/§11). Two-step: credentials, then — only when the
// server answers {totp_required:true} — an IN-BAND TOTP/backup-code step
// that re-POSTs the SAME credentials plus the code. A 401 here is EXPECTED
// application behavior (expected-policy call): it renders as a form error
// and NEVER triggers the global session-expiry boundary. 429 lockout is
// shown with the server's bounded message and is never auto-retried.
// Success is confirmed by a FRESH /api/auth/status read before the app
// renders; password and code state are cleared immediately on success.
import { useEffect, useRef, useState } from "react";
import type { FormEvent, JSX } from "react";
import { useLocation, useNavigate } from "react-router";
import { ApiError } from "../../api/client";
import { postLogin } from "../../api/auth";
import { useAuth } from "../../auth/AuthProvider";
import { resolveRouteIntent } from "../../auth/routeIntent";
import { Button, Callout } from "../../design-system/primitives";
import { InputField } from "../../design-system/forms";
import { AuthScreen } from "./AuthScreen";
import styles from "./auth.module.css";

type Step = "credentials" | "totp";

type Notice =
  | { kind: "invalid"; text: string }
  | { kind: "lockout"; text: string }
  | { kind: "connection"; text: string }
  | { kind: "malformed"; text: string }
  | null;

export function LoginPage(): JSX.Element {
  const { state, machine } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [step, setStep] = useState<Step>("credentials");
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [totp, setTotp] = useState("");
  const [notice, setNotice] = useState<Notice>(null);
  const [busy, setBusy] = useState(false);
  const userRef = useRef<HTMLInputElement>(null);
  const passRef = useRef<HTMLInputElement>(null);
  const totpRef = useRef<HTMLInputElement>(null);

  // §19: after the credentials step hands over to TOTP, focus enters the
  // code input.
  useEffect(() => {
    if (step === "totp") totpRef.current?.focus();
  }, [step]);

  const finishAuthenticated = async (): Promise<void> => {
    // §2: never trust the login response alone — fresh authoritative read.
    const after = await machine.refresh();
    if (after.phase === "authenticated" && after.role !== null) {
      setPass("");
      setTotp("");
      // §14: honor the current URL only if it is a known internal route the
      // confirmed role may visit; otherwise land on Overview.
      const raw = location.pathname;
      const intent = raw.startsWith("/app") ? raw.slice(4) || "/" : raw;
      void navigate(resolveRouteIntent(intent, after.role), { replace: true });
      return;
    }
    setNotice({
      kind: "malformed",
      text: "Sign-in could not be confirmed by the appliance — no session was established.",
    });
  };

  const submit = async (ev: FormEvent): Promise<void> => {
    ev.preventDefault();
    if (busy) return;
    setNotice(null);
    if (step === "credentials" && (user === "" || pass === "")) {
      setNotice({ kind: "invalid", text: "Enter a username and password." });
      (user === "" ? userRef : passRef).current?.focus();
      return;
    }
    if (step === "totp" && totp === "") {
      setNotice({
        kind: "invalid",
        text: "Enter the code from your authenticator app, or a backup code.",
      });
      totpRef.current?.focus();
      return;
    }
    setBusy(true);
    try {
      const result = await postLogin(
        user,
        pass,
        step === "totp" ? totp : undefined,
      );
      if (result.kind === "totp_required") {
        setStep("totp"); // no cookie was issued; same credentials re-POST next
        return;
      }
      await finishAuthenticated();
    } catch (err) {
      if (
        err instanceof ApiError &&
        err.kind === "http" &&
        err.status === 401
      ) {
        // EXPECTED auth-flow failure (§4) — a form error, never the boundary.
        setNotice({
          kind: "invalid",
          text:
            err.bodyText !== undefined && err.bodyText !== ""
              ? err.bodyText.trim()
              : "Invalid credentials.",
        });
        (step === "totp" ? totpRef : passRef).current?.focus();
      } else if (
        err instanceof ApiError &&
        err.kind === "http" &&
        err.status === 429
      ) {
        setNotice({
          kind: "lockout",
          text:
            err.bodyText !== undefined && err.bodyText !== ""
              ? err.bodyText.trim()
              : "Too many attempts — the account is temporarily locked.",
        });
      } else if (
        err instanceof ApiError &&
        (err.kind === "network" || err.kind === "timeout")
      ) {
        setNotice({
          kind: "connection",
          text: "Connection failed — your credentials were NOT verified. Check the connection and try again.",
        });
      } else {
        setNotice({
          kind: "malformed",
          text: "The appliance returned an unexpected response — sign-in was not completed.",
        });
      }
    } finally {
      setBusy(false);
    }
  };

  const backToCredentials = (): void => {
    setTotp(""); // §11: leaving the TOTP step clears the code
    setNotice(null);
    setStep("credentials");
  };

  return (
    <AuthScreen
      title={step === "credentials" ? "Sign in" : "Two-factor verification"}
      subtitle={
        step === "credentials"
          ? "Authenticate to manage this CULVERT appliance."
          : `The account ${user} has two-factor authentication enrolled. Enter the 6-digit code from your authenticator app, or one of your backup codes. Nothing is stored in the browser.`
      }
      tlsFallback={state.tlsFallback}
      tlsFallbackReason={state.tlsFallbackReason}
    >
      {state.boundaryNote === "session_ended" && (
        // §8: memory-only boundary reason — never "timeout" (the 401 or
        // loggedOut answer may mean revocation, deletion, or replacement);
        // never persisted; cleared on successful authentication; absent on
        // an ordinary first visit.
        <Callout
          variant="warning"
          title="Management session ended"
          role="alert"
        >
          Your management session is no longer valid. Sign in again to continue.
        </Callout>
      )}
      {state.logoutNote === "unconfirmed" && (
        <Callout
          variant="warning"
          title="Server-side sign-out not confirmed"
          role="alert"
        >
          Local application state was cleared, but the appliance could not
          confirm the session token was revoked. If this device is shared,
          verify connectivity and sign out again.
        </Callout>
      )}
      {notice !== null && notice.kind === "invalid" && (
        <Callout variant="critical" role="alert">
          {notice.text}
        </Callout>
      )}
      {notice !== null && notice.kind === "lockout" && (
        <Callout variant="warning" title="Temporarily locked" role="alert">
          {notice.text} Sign-in is not retried automatically.
        </Callout>
      )}
      {notice !== null && notice.kind === "connection" && (
        <Callout
          variant="unknown"
          title="Connection state unknown"
          role="alert"
        >
          {notice.text}
        </Callout>
      )}
      {notice !== null && notice.kind === "malformed" && (
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
        {step === "credentials" ? (
          <>
            <InputField
              label="Username"
              required
              autoComplete="username"
              value={user}
              inputRef={userRef}
              onChange={(e) => setUser(e.target.value)}
            />
            <InputField
              label="Password"
              required
              type="password"
              autoComplete="current-password"
              value={pass}
              inputRef={passRef}
              onChange={(e) => setPass(e.target.value)}
            />
            <div className={styles.formActions}>
              <Button type="submit" variant="primary" disabled={busy}>
                {busy ? "Signing in…" : "Sign in"}
              </Button>
            </div>
          </>
        ) : (
          <>
            <InputField
              label="Authenticator or backup code"
              required
              // Backup codes may be non-numeric — the field is NOT
              // digits-constrained (§11).
              type="text"
              inputMode="text"
              autoComplete="one-time-code"
              value={totp}
              inputRef={totpRef}
              onChange={(e) => setTotp(e.target.value)}
            />
            <div className={styles.formActions}>
              <Button type="submit" variant="primary" disabled={busy}>
                {busy ? "Verifying…" : "Verify"}
              </Button>
              <Button
                type="button"
                variant="ghost"
                onClick={backToCredentials}
                disabled={busy}
              >
                Back
              </Button>
            </div>
          </>
        )}
      </form>
    </AuthScreen>
  );
}
