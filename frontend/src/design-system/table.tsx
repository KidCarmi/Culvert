// DataTable foundation (FE-2 §7): a semantic <table> with typed columns.
// Deliberately NOT a grid framework — sorting/selection/virtualization arrive
// with the first real consumer that needs them.
import type { JSX, ReactNode } from "react";
import styles from "./table.module.css";

export interface Column<Row> {
  key: string;
  header: string;
  numeric?: boolean;
  render: (row: Row) => ReactNode;
}

export function DataTable<Row>({
  caption,
  columns,
  rows,
  rowKey,
  empty,
}: {
  caption: string; // every table names itself for AT; visually optional
  captionHidden?: boolean;
  columns: ReadonlyArray<Column<Row>>;
  rows: ReadonlyArray<Row>;
  rowKey: (row: Row) => string;
  empty?: ReactNode;
}): JSX.Element {
  return (
    <div className={styles.wrap}>
      <table className={styles.table}>
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((c) => (
              <th
                key={c.key}
                scope="col"
                className={c.numeric === true ? styles.numeric : undefined}
              >
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr>
              <td colSpan={columns.length}>{empty ?? "No entries."}</td>
            </tr>
          )}
          {rows.map((r) => (
            <tr key={rowKey(r)}>
              {columns.map((c) => (
                <td
                  key={c.key}
                  className={c.numeric === true ? styles.numeric : undefined}
                >
                  {c.render(r)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
