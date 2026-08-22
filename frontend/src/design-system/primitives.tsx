// Core CULVERT primitives (FE-2 §7). Semantic-token styling only; dynamic
// state is expressed through data-* attributes and classes — never style
// mutation (contract §4).
import type { ButtonHTMLAttributes, JSX, ReactNode } from "react";
import { IconAlert, IconCheck, IconInfo } from "./icons";
import styles from "./primitives.module.css";

export type ButtonVariant =
  "primary" | "secondary" | "ghost" | "danger" | "danger-quiet";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: "md" | "sm";
}

export function Button({
  variant = "secondary",
  size = "md",
  type,
  ...rest
}: ButtonProps): JSX.Element {
  return (
    <button
      className={styles.button}
      data-variant={variant}
      data-size={size}
      type={type ?? "button"}
      {...rest}
    />
  );
}

interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  label: string; // icon-only controls always carry an accessible name
  variant?: ButtonVariant;
}

export function IconButton({
  label,
  variant = "ghost",
  type,
  children,
  ...rest
}: IconButtonProps): JSX.Element {
  return (
    <button
      className={styles.iconButton}
      data-variant={variant}
      type={type ?? "button"}
      aria-label={label}
      title={label}
      {...rest}
    >
      {children}
    </button>
  );
}

export type Status =
  "ok" | "warn" | "critical" | "info" | "unknown" | "neutral";

export function StatusBadge({
  status,
  children,
}: {
  status: Status;
  children: ReactNode;
}): JSX.Element {
  // Dot + text: state is never communicated by color alone.
  return (
    <span className={styles.badge} data-status={status}>
      <span className={styles.badgeDot} aria-hidden="true" />
      {children}
    </span>
  );
}

export type CalloutVariant =
  "info" | "success" | "warning" | "critical" | "unknown";

const calloutIcons: Record<CalloutVariant, JSX.Element> = {
  info: <IconInfo />,
  success: <IconCheck />,
  warning: <IconAlert />,
  critical: <IconAlert />,
  unknown: <IconInfo />,
};

export function Callout({
  variant,
  title,
  children,
  role,
}: {
  variant: CalloutVariant;
  title?: string;
  children: ReactNode;
  role?: "alert" | "status";
}): JSX.Element {
  return (
    <div className={styles.callout} data-variant={variant} role={role}>
      <span className={styles.calloutIcon}>{calloutIcons[variant]}</span>
      <div>
        {title !== undefined && (
          <div className={styles.calloutTitle}>{title}</div>
        )}
        <div>{children}</div>
      </div>
    </div>
  );
}

export function Card({
  title,
  actions,
  children,
}: {
  title?: string;
  actions?: ReactNode;
  children: ReactNode;
}): JSX.Element {
  return (
    <section className={styles.card}>
      {title !== undefined && (
        <header className={styles.cardHeader}>
          <h2 className={styles.cardTitle}>{title}</h2>
          {actions}
        </header>
      )}
      <div className={styles.cardBody}>{children}</div>
    </section>
  );
}

export function Divider(): JSX.Element {
  return <hr className={styles.divider} />;
}

// Tooltip: internal, statically CSS-positioned (above, centered). No runtime
// measurement ⇒ no style attributes ⇒ CSP-clean by construction (OQ-2).
// For text that must be readable by AT regardless of hover, prefer visible
// text; this is a supplemental affordance.
let tooltipSeq = 0;
export function Tooltip({
  text,
  children,
}: {
  text: string;
  children: ReactNode;
}): JSX.Element {
  const id = `tt-${String(++tooltipSeq)}`;
  return (
    <span className={styles.tooltipHost} aria-describedby={id}>
      {children}
      <span role="tooltip" id={id} className={styles.tooltipBubble}>
        {text}
      </span>
    </span>
  );
}

export function Spinner({
  label = "Loading",
}: {
  label?: string;
}): JSX.Element {
  return (
    <span role="status" aria-label={label}>
      <span className={styles.spinner} aria-hidden="true" />
    </span>
  );
}

export function Skeleton({ children }: { children?: ReactNode }): JSX.Element {
  return (
    <span className={styles.skeleton} aria-hidden="true">
      {children ?? "…"}
    </span>
  );
}

export function EmptyState({
  title,
  children,
  action,
}: {
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}): JSX.Element {
  return (
    <div className={styles.state} data-tone="empty">
      <span className={styles.stateIcon} aria-hidden="true">
        <IconInfo size={24} />
      </span>
      <div className={styles.stateTitle}>{title}</div>
      {children !== undefined && (
        <div className={styles.stateBody}>{children}</div>
      )}
      {action}
    </div>
  );
}

export function ErrorState({
  title,
  children,
  action,
}: {
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}): JSX.Element {
  return (
    <div className={styles.state} data-tone="error" role="alert">
      <span className={styles.stateIcon} aria-hidden="true">
        <IconAlert size={24} />
      </span>
      <div className={styles.stateTitle}>{title}</div>
      {children !== undefined && (
        <div className={styles.stateBody}>{children}</div>
      )}
      {action}
    </div>
  );
}

export function KeyValue({
  items,
}: {
  items: ReadonlyArray<readonly [string, ReactNode]>;
}): JSX.Element {
  return (
    <dl className={styles.kv}>
      {items.map(([k, v]) => (
        <ItemPair key={k} k={k} v={v} />
      ))}
    </dl>
  );
}

function ItemPair({ k, v }: { k: string; v: ReactNode }): JSX.Element {
  return (
    <>
      <dt>{k}</dt>
      <dd>{v}</dd>
    </>
  );
}

export function Mono({ children }: { children: ReactNode }): JSX.Element {
  return <code className={styles.mono}>{children}</code>;
}

// Timestamp: absolute, unambiguous, tabular. Appliance operators correlate
// logs across systems — relative-only time is banned by product doctrine.
export function Timestamp({ iso }: { iso: string }): JSX.Element {
  return (
    <time dateTime={iso} className={styles.timestamp}>
      {iso.replace("T", " ").replace(/\.\d+Z$/, "Z")}
    </time>
  );
}
