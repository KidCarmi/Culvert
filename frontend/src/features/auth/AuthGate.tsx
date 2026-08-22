// FE-3 authenticated route guard (§17). ONE switch on the authoritative
// machine phase decides what the v2 app may render — the AppShell (and any
// route under it, including /design-system) mounts ONLY in the
// `authenticated` phase, so privileged content can never flash while auth
// state is unknown, and pre-setup exposes ONLY the Setup UI.
import type { JSX } from "react";
import { useAuth } from "../../auth/AuthProvider";
import { CulvertMark } from "../../design-system/icons";
import { Button, ErrorState, Spinner } from "../../design-system/primitives";
import { AppShell } from "../../layouts/AppShell";
import { LoginPage } from "./LoginPage";
import { SetupPage } from "./SetupPage";
import styles from "./auth.module.css";

function BootShell(): JSX.Element {
  return (
    <div className={styles.loading} role="status" aria-live="polite">
      <CulvertMark />
      <Spinner />
      <span>Checking appliance state…</span>
    </div>
  );
}

function AuthErrorShell(): JSX.Element {
  const { state, machine } = useAuth();
  return (
    <div className={styles.loading}>
      <CulvertMark />
      <ErrorState title="Authentication state unavailable">
        The appliance did not return a usable authentication state
        {state.errorDetail !== "" ? ` (${state.errorDetail})` : ""}. Nothing was
        rendered; no session was assumed.
      </ErrorState>
      <Button
        variant="primary"
        onClick={() => {
          void machine.retry();
        }}
      >
        Retry
      </Button>
    </div>
  );
}

export function AuthGate(): JSX.Element {
  const { state } = useAuth();
  switch (state.phase) {
    case "booting":
      return <BootShell />;
    case "setup_required":
      return <SetupPage />;
    case "unauthenticated":
      return <LoginPage />;
    case "auth_error":
      return <AuthErrorShell />;
    case "authenticated":
      return <AppShell />;
  }
}
