// Slice 2A Where Used (FE-X06): ONE reusable read-only consumer of
// GET /api/objects/references — the generic object-dependency seam future
// slices reuse. Fetches ONLY on explicit operator interest (never per-row).
//
// SECURITY/CORRECTNESS (directive §17): the server's `referencedBy[].view`
// value is a product/legacy view identifier, NEVER a client route. Navigation
// goes exclusively through the explicit reviewed mapping below; consumers
// whose surface has no real v2 route render as reference information only.
import { useEffect, useRef, useState, type JSX } from "react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { getObjectReferences } from "../../api/policy";
import type { ObjectRefConsumer, ObjectRefType } from "../../api/policy";
import { ApiError } from "../../api/client";
import {
  Button,
  ErrorState,
  Mono,
  Spinner,
} from "../../design-system/primitives";
import styles from "./policy.module.css";

const REF_TYPE_LABEL: Record<ObjectRefType, string> = {
  category: "URL category",
  "category-group": "Category group",
  "file-profile": "File profile",
  "decryption-profile": "Decryption profile",
};

// Explicit reviewed consumer → destination mapping (2A foundation, extended in
// 2D-A §19 for routes that now exist). Deep links use STABLE IDs only. The
// server `view` value stays data, never navigation authority — only these
// reviewed (consumerType, view) pairs navigate; everything else renders as
// reference information. Exported for the object-management delete dialog,
// which renders the authoritative 409 consumer list with the same mapping.
export function consumerDestination(c: ObjectRefConsumer): JSX.Element {
  if (c.consumerType === "access-rule" && c.view === "policy" && c.id !== "") {
    return (
      <Link to={`/policies/access-rules?rule=${encodeURIComponent(c.id)}`}>
        {c.name}
      </Link>
    );
  }
  if (
    c.consumerType === "auth-rule" &&
    c.view === "authpolicy" &&
    c.id !== ""
  ) {
    return (
      <Link
        to={`/policies/authentication-rules?rule=${encodeURIComponent(c.id)}`}
      >
        {c.name}
      </Link>
    );
  }
  if (
    c.consumerType === "category-group" &&
    c.view === "catgroups" &&
    c.id !== ""
  ) {
    return (
      <Link to={`/objects/category-groups?id=${encodeURIComponent(c.id)}`}>
        {c.name}
      </Link>
    );
  }
  const note =
    c.consumerType === "auth-rule"
      ? "Authentication rule"
      : c.consumerType === "category-group"
        ? "Category group"
        : c.consumerType === "access-rule"
          ? "Access rule"
          : `${c.consumerType} — not navigable here`;
  return (
    <span>
      {c.name} <span className={styles.refDetail}>({note})</span>
    </span>
  );
}

export function WhereUsed({
  type,
  name,
}: {
  type: ObjectRefType;
  name: string;
}): JSX.Element {
  // Explicit-interest fetch: the query mounts disabled and is armed by the
  // operator's action; auth-boundary cancellation rides the normal TanStack
  // signal (the fetcher consumes it).
  const [armed, setArmed] = useState(false);
  const q = useQuery({
    queryKey: ["objects", "references", type, name],
    queryFn: ({ signal }) => getObjectReferences(type, name, signal),
    enabled: armed,
    staleTime: Infinity,
    retry: false,
  });
  // Reset the armed state when the object identity changes so a previously
  // opened panel never shows another object's references.
  const key = `${type}:${name}`;
  const lastKey = useRef(key);
  useEffect(() => {
    if (lastKey.current !== key) {
      lastKey.current = key;
      setArmed(false);
    }
  }, [key]);

  if (!armed) {
    return (
      <Button
        size="sm"
        variant="secondary"
        onClick={() => {
          setArmed(true);
        }}
      >
        Where used: {REF_TYPE_LABEL[type]} “{name}”
      </Button>
    );
  }
  if (q.isPending) return <Spinner label={`Loading references for ${name}`} />;
  if (q.isError) {
    const err = q.error;
    return (
      <ErrorState title={`Could not load references for ${name}`}>
        {err instanceof ApiError && err.bodyText !== undefined
          ? err.bodyText
          : "The reference lookup failed. Try again."}
      </ErrorState>
    );
  }
  const refs = q.data.referencedBy;
  return (
    <div className={styles.whereUsedPanel}>
      <strong>
        {REF_TYPE_LABEL[type]} “{q.data.object.name}”
      </strong>{" "}
      {refs.length === 0 ? (
        <span className={styles.refDetail}>
          is not referenced by any rule or group.
        </span>
      ) : (
        <span className={styles.refDetail}>
          is referenced by {refs.length}{" "}
          {refs.length === 1 ? "consumer" : "consumers"}:
        </span>
      )}
      {refs.length > 0 && (
        <table className={styles.table}>
          <caption className="sr-only">
            Consumers referencing {q.data.object.name}
          </caption>
          <thead>
            <tr>
              <th scope="col">Consumer</th>
              <th scope="col">Type</th>
              <th scope="col">Via</th>
              <th scope="col">ID</th>
            </tr>
          </thead>
          <tbody>
            {refs.map((c, i) => (
              <tr key={`${c.consumerType}:${c.id !== "" ? c.id : String(i)}`}>
                <td>{consumerDestination(c)}</td>
                <td>{c.consumerType}</td>
                <td className={styles.refDetail}>{c.detail}</td>
                <td>{c.id === "" ? "—" : <Mono>{c.id}</Mono>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
