// Internal SVG icon set (FE-2 §18 decision: no icon dependency — CULVERT
// needs ~a dozen precise marks, not a 1,500-icon package). 16×16 viewBox,
// stroke inherits currentColor. Decorative by default (aria-hidden); pass
// `label` for icon-only semantics.
import type { JSX, ReactNode } from "react";

interface IconProps {
  label?: string;
  size?: number;
}

function Icon({
  label,
  size = 16,
  children,
}: IconProps & { children: ReactNode }): JSX.Element {
  return (
    <svg
      viewBox="0 0 16 16"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden={label === undefined ? true : undefined}
      role={label === undefined ? undefined : "img"}
      aria-label={label}
      focusable="false"
    >
      {children}
    </svg>
  );
}

export const IconGauge = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <path d="M2.5 9.5a5.5 5.5 0 1 1 11 0" />
    <path d="M8 9.5 10.8 6" />
    <path d="M2.5 12.5h11" />
  </Icon>
);
export const IconActivity = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <path d="M1.5 8h3l2-4.5 3 9 2-4.5h3" />
  </Icon>
);
export const IconPolicy = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <path d="M4 2.5h8v11H4z" />
    <path d="M6 5.5h4M6 8h4M6 10.5h2.5" />
  </Icon>
);
export const IconShield = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <path d="M8 1.8 13 3.6v4.2c0 3.2-2.1 5.3-5 6.4-2.9-1.1-5-3.2-5-6.4V3.6z" />
    <path d="m5.8 7.8 1.6 1.6 2.8-3" />
  </Icon>
);
export const IconServer = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <rect x="2" y="2.5" width="12" height="4.5" rx="1" />
    <rect x="2" y="9" width="12" height="4.5" rx="1" />
    <path d="M4.5 4.75h.01M4.5 11.25h.01" />
  </Icon>
);
export const IconUsers = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <circle cx="6" cy="5.5" r="2.3" />
    <path d="M2 13.5c.5-2.5 2-3.8 4-3.8s3.5 1.3 4 3.8" />
    <path d="M11 8.2c1.6.3 2.6 1.5 3 3.3" />
    <path d="M10.2 3.4a2.3 2.3 0 0 1 0 4.2" />
  </Icon>
);
export const IconSun = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <circle cx="8" cy="8" r="3" />
    <path d="M8 1.5v1.6M8 12.9v1.6M1.5 8h1.6M12.9 8h1.6M3.4 3.4l1.1 1.1M11.5 11.5l1.1 1.1M12.6 3.4l-1.1 1.1M4.5 11.5l-1.1 1.1" />
  </Icon>
);
export const IconMoon = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <path d="M13.5 9.7A5.8 5.8 0 0 1 6.3 2.5a5.8 5.8 0 1 0 7.2 7.2z" />
  </Icon>
);
export const IconMonitor = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <rect x="2" y="3" width="12" height="8" rx="1" />
    <path d="M6 13.5h4M8 11v2.5" />
  </Icon>
);
export const IconMenu = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <path d="M2.5 4.5h11M2.5 8h11M2.5 11.5h11" />
  </Icon>
);
export const IconClose = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <path d="m4 4 8 8M12 4l-8 8" />
  </Icon>
);
export const IconCheck = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <path d="m3 8.5 3.2 3.2L13 5" />
  </Icon>
);
export const IconAlert = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <path d="M8 2 14.5 13.5h-13z" />
    <path d="M8 6.5v3.2M8 11.6v.01" />
  </Icon>
);
export const IconInfo = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <circle cx="8" cy="8" r="6" />
    <path d="M8 7.2v3.6M8 5v.01" />
  </Icon>
);
export const IconChevronDown = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <path d="m4 6.5 4 4 4-4" />
  </Icon>
);
export const IconRollback = (p: IconProps): JSX.Element => (
  <Icon {...p}>
    <path d="M3 6.5h7a3.5 3.5 0 0 1 0 7H6" />
    <path d="M6 3.5 3 6.5l3 3" />
  </Icon>
);

// CulvertMark — the product mark: a culvert arch over a flow line.
export function CulvertMark({ size = 22 }: { size?: number }): JSX.Element {
  return (
    <svg
      viewBox="0 0 22 22"
      width={size}
      height={size}
      aria-hidden="true"
      focusable="false"
    >
      <rect
        x="1"
        y="1"
        width="20"
        height="20"
        rx="5"
        fill="var(--color-interactive)"
        opacity="0.16"
      />
      <path
        d="M4.5 15.5v-4a6.5 6.5 0 0 1 13 0v4"
        fill="none"
        stroke="var(--color-interactive)"
        strokeWidth="2"
        strokeLinecap="round"
      />
      <path
        d="M4.5 15.5h13"
        stroke="var(--color-interactive)"
        strokeWidth="2"
        strokeLinecap="round"
      />
    </svg>
  );
}
