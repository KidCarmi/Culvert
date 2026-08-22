// Internal SVG charts — the CHART DECISION (FE-2 §17) outcome.
//
// Chart.js 4.x was REJECTED for the new frontend: its DOM layer mutates
// element.style at runtime (canvas init + responsive resize both write
// canvas style properties — verifiable in the vendored legacy bundle:
// `grep -c '\.style\.' static/chart.umd.js` ≫ 0, e.g. initCanvas/_resize
// setting display/height/width). That violates the hard "zero runtime style
// mutation" contract (§4/§17) regardless of whether CSSOM writes escape CSP
// enforcement — the contract bans the practice, not just the enforcement
// path. CSP is not weakened to keep a library.
//
// The two legacy dashboard charts (request-rate line, verdict donut) need
// exactly these two thin primitives. Geometry is expressed through SVG
// ATTRIBUTES (points/d/dasharray), never style. Every chart carries a
// non-visual equivalent: the donut's legend is visible data; the line chart
// embeds an sr-only summary.
import type { JSX } from "react";
import styles from "./charts.module.css";
import type { Status } from "./primitives";

const W = 300;
const H = 80;

export function LineChart({
  title,
  points,
  unit,
}: {
  title: string;
  points: readonly number[];
  unit: string;
}): JSX.Element {
  const max = Math.max(...points, 1);
  const step = points.length > 1 ? W / (points.length - 1) : W;
  const xy = points.map((v, i) => {
    const x = (i * step).toFixed(1);
    const y = (H - 6 - (v / max) * (H - 14)).toFixed(1);
    return `${x},${y}`;
  });
  const last = points.at(-1) ?? 0;
  const summary = `${title}: ${String(points.length)} samples, min ${String(Math.min(...points))} ${unit}, max ${String(Math.max(...points))} ${unit}, latest ${String(last)} ${unit}.`;
  return (
    <figure className={styles.figure}>
      <figcaption className={styles.caption}>{title}</figcaption>
      <svg
        viewBox={`0 0 ${String(W)} ${String(H)}`}
        className={styles.plot}
        role="img"
        aria-label={summary}
        preserveAspectRatio="none"
      >
        {[0.25, 0.5, 0.75].map((f) => (
          <line
            key={f}
            x1="0"
            x2={W}
            y1={H * f}
            y2={H * f}
            className={styles.grid}
          />
        ))}
        <polygon
          points={`0,${String(H)} ${xy.join(" ")} ${String(W)},${String(H)}`}
          className={styles.area}
        />
        <polyline points={xy.join(" ")} className={styles.line} />
      </svg>
      <span className="sr-only">{summary}</span>
    </figure>
  );
}

export interface DonutSegment {
  label: string;
  value: number;
  status: Status;
}

export function DonutChart({
  title,
  segments,
}: {
  title: string;
  segments: readonly DonutSegment[];
}): JSX.Element {
  const total = segments.reduce((s, x) => s + x.value, 0) || 1;
  let offset = 25; // start at 12 o'clock (pathLength 100 circle starts at 3 o'clock)
  const arcs = segments.map((s) => {
    const frac = (s.value / total) * 100;
    const arc = { ...s, frac, offset };
    offset -= frac;
    return arc;
  });
  return (
    <figure className={styles.figure}>
      <figcaption className={styles.caption}>{title}</figcaption>
      <div className={styles.donutWrap}>
        <svg
          viewBox="0 0 42 42"
          width="96"
          height="96"
          role="img"
          aria-label={`${title} distribution`}
        >
          <circle
            cx="21"
            cy="21"
            r="16"
            fill="none"
            strokeWidth="6"
            pathLength={100}
            className={styles.donutTrack}
          />
          {arcs.map((a) => (
            <circle
              key={a.label}
              cx="21"
              cy="21"
              r="16"
              fill="none"
              strokeWidth="6"
              pathLength={100}
              strokeDasharray={`${a.frac.toFixed(2)} ${(100 - a.frac).toFixed(2)}`}
              strokeDashoffset={a.offset.toFixed(2)}
              className={styles.seg}
              data-status={a.status}
            />
          ))}
        </svg>
        {/* The legend IS the non-visual equivalent: visible labels + counts. */}
        <ul className={styles.legend}>
          {arcs.map((a) => (
            <li key={a.label} className={styles.legendRow}>
              <span
                className={styles.legendSwatch}
                data-status={a.status}
                aria-hidden="true"
              />
              {a.label}
              <span className={styles.legendValue}>
                {String(a.value)} ({a.frac.toFixed(0)}%)
              </span>
            </li>
          ))}
        </ul>
      </div>
    </figure>
  );
}
