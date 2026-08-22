// FE-3 shared auth-surface frame (§18): CULVERT identity + appliance/
// connection posture in a rail, the task (setup/login) in the pane. The
// TLS-fallback warning (§9) renders PROMINENTLY, before any credential
// field, whenever the server reports ui_tls_fallback — never a toast,
// never behind Help.
import type { JSX, ReactNode } from "react";
import { CulvertMark } from "../../design-system/icons";
import { Callout } from "../../design-system/primitives";
import { ThemeSwitcher } from "../../layouts/AppShell";
import styles from "./auth.module.css";

export function TLSFallbackWarning({
  active,
  reason,
}: {
  active: boolean;
  reason: string;
}): JSX.Element | null {
  if (!active) return null;
  return (
    <Callout
      variant="critical"
      title="This connection is NOT encrypted"
      role="alert"
    >
      Automatic TLS setup failed, so the management interface is being served
      over plain HTTP. Credentials submitted on this page may travel
      unencrypted.
      {reason !== ""
        ? ` Server detail: ${reason}.`
        : // The server deliberately withholds the cause from this
          // UNAUTHENTICATED page — the raw self-sign error can embed an
          // operator-configured SAN or the host name (see
          // preAuthTLSFallbackReason, ui_auth.go). Say where it lives rather
          // than silently rendering nothing.
          " The specific cause is not published on this unauthenticated page; it is available after signing in, under Settings → Network & TLS."}{" "}
      Complete this task over a trusted network only, then restart the appliance
      to retry TLS.
    </Callout>
  );
}

export function AuthScreen({
  title,
  subtitle,
  tlsFallback,
  tlsFallbackReason,
  children,
}: {
  title: string;
  subtitle: string;
  tlsFallback: boolean;
  tlsFallbackReason: string;
  children: ReactNode;
}): JSX.Element {
  const scheme = window.location.protocol === "https:" ? "HTTPS" : "Plain HTTP";
  return (
    <div className={styles.screen}>
      <aside className={styles.rail}>
        <div className={styles.brandRow}>
          <CulvertMark />
          <div>
            <div className={styles.brandName}>CULVERT</div>
            <div className={styles.brandTag}>Secure Web Gateway</div>
          </div>
        </div>
        <div>
          <div className={styles.railHeading}>Management plane</div>
          <dl className={styles.railList}>
            <div className={styles.railItem}>
              <dt>Appliance</dt>
              <dd>{window.location.host}</dd>
            </div>
            <div className={styles.railItem}>
              <dt>Connection</dt>
              <dd>{tlsFallback ? "Plain HTTP (TLS fallback)" : scheme}</dd>
            </div>
          </dl>
        </div>
        <div className={styles.railSpacer} />
        <ThemeSwitcher />
      </aside>
      <div className={styles.pane}>
        <section className={styles.task} aria-labelledby="auth-task-title">
          <div>
            <h1 className={styles.taskTitle} id="auth-task-title">
              {title}
            </h1>
            <p className={styles.taskSubtitle}>{subtitle}</p>
          </div>
          <TLSFallbackWarning active={tlsFallback} reason={tlsFallbackReason} />
          {children}
        </section>
      </div>
    </div>
  );
}
