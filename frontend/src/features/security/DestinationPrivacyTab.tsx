// 2E-B Destination Privacy: the NODE-LOCAL posture governing what DESTINATION
// information is retained/rendered in traffic logs and observability. It is
// NOT TLS inspection, NOT a Decryption Profile, and NOT CA management; the
// pseudonym key is NOT the TLS inspection Root CA and rotating it is NOT a
// certificate rotation. Enable is a light T1 confirm (protective direction),
// disable is a T2 ceremony, key rotation is a T3 typed ceremony bound to
// fresh server truth. Rotation is NEVER blindly retried: an unknown outcome
// latches and is resolved by comparing the non-secret pseudonym generation
// (key_id) against fresh GET truth.
import { useState, type JSX } from "react";
import {
  Callout,
  Card,
  ErrorState,
  KeyValue,
  Mono,
  Skeleton,
  StatusBadge,
} from "../../design-system/primitives";
import { Button } from "../../design-system/primitives";
import { ConfirmationDialog } from "../../design-system/dialog";
import type { ConfirmResult } from "../../design-system/dialog";
import { SnapshotBar } from "../../shared/snapshot";
import { useObjectPage } from "../objects/useObjectPage";
import { asRevisionConflict } from "../../api/urlcat";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import {
  getDestinationPrivacy,
  putDestinationPrivacy,
  rotatePseudonymKey,
} from "../../api/decryption";
import styles from "../policy/policy.module.css";

type Ceremony =
  | { kind: "enable"; revision: string }
  | { kind: "disable"; revision: string }
  | { kind: "rotate"; revision: string; preKeyId: string };

export function DestinationPrivacyTab({
  isAdmin,
}: {
  isAdmin: boolean;
}): JSX.Element {
  const page = useObjectPage(
    ["security", "decryption", "privacy"],
    getDestinationPrivacy,
  );
  const p = page.q.data;
  const [ceremony, setCeremony] = useState<Ceremony | null>(null);
  const [typed, setTyped] = useState("");
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  const [notice, setNotice] = useState("");
  // Pending rotation whose response was LOST: resolved against fresh GET
  // truth by comparing key_id — never by repeating the rotation.
  const [unresolvedRotation, setUnresolvedRotation] = useState<string | null>(
    null,
  );

  page.setBoundaryCleanup(() => {
    setCeremony(null);
    setTyped("");
    setResult("idle");
    setErrorText("");
    setNotice("");
    setUnresolvedRotation(null);
  });

  const closeCeremony = (): void => {
    setCeremony(null);
    setTyped("");
    setResult("idle");
    setErrorText("");
  };

  const handleFailure = (err: unknown, action: string): void => {
    if (unknownOutcome(err)) {
      if (ceremony?.kind === "rotate") {
        setUnresolvedRotation(ceremony.preKeyId);
      }
      page.latchUnknown("edit");
      closeCeremony();
      return;
    }
    if (asRevisionConflict(err) !== null) {
      closeCeremony();
      setNotice(
        "The destination-privacy state changed on the appliance since you loaded it. Nothing was changed — review the refreshed state and retry from fresh truth.",
      );
      page.refreshToResolve();
      return;
    }
    setResult("failed");
    setErrorText(serverErrorText(err, `The ${action} failed.`));
  };

  const runPosture = (target: boolean, revision: string): void => {
    const signal = page.owner.begin();
    setResult("pending");
    putDestinationPrivacy(target, revision, signal)
      .then(() => {
        closeCeremony();
        page.refreshToResolve();
      })
      .catch((err: unknown) => {
        handleFailure(err, "posture change");
      })
      .finally(() => {
        page.owner.settle(signal);
      });
  };

  const runRotation = (c: Ceremony & { kind: "rotate" }): void => {
    const signal = page.owner.begin();
    setResult("pending");
    rotatePseudonymKey(c.revision, signal)
      .then((res) => {
        closeCeremony();
        setNotice(
          `Pseudonym key rotated. New pseudonym generation: ${res.keyId}. Records written before this rotation no longer correlate with new ones.`,
        );
        page.refreshToResolve();
      })
      .catch((err: unknown) => {
        handleFailure(err, "key rotation");
      })
      .finally(() => {
        page.owner.settle(signal);
      });
  };

  // Resolve a lost-response rotation from FRESH truth once it arrives.
  const rotationResolution =
    unresolvedRotation !== null && p !== undefined && page.unknown === null
      ? p.keyId !== unresolvedRotation
        ? "landed"
        : "not-landed"
      : null;

  return (
    <div>
      <div className={styles.toolbar}>
        <SnapshotBar
          updatedAt={page.q.dataUpdatedAt}
          fetching={page.q.isFetching}
          error={page.q.isError}
          hasData={p !== undefined}
          onRefresh={page.refreshToResolve}
        />
      </div>

      {page.unknown !== null && (
        <div className={styles.calloutSpace}>
          <Callout variant="unknown" title="Outcome unconfirmed" role="alert">
            The connection was lost before the appliance&apos;s answer arrived.
            Refresh to resolve the authoritative state — do NOT repeat a key
            rotation blindly.
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={page.refreshToResolve}>
                Refresh state
              </Button>
            </div>
          </Callout>
        </div>
      )}

      {rotationResolution === "landed" && (
        <div className={styles.calloutSpace}>
          <Callout variant="warning" title="Rotation landed" role="alert">
            The rotation&apos;s response was lost, but fresh server truth shows
            the pseudonym generation CHANGED — the rotation landed exactly once.
            Do not run it again unless you intend a second rotation.
          </Callout>
        </div>
      )}
      {rotationResolution === "not-landed" && (
        <div className={styles.calloutSpace}>
          <Callout variant="warning" title="Rotation did not land" role="alert">
            The rotation&apos;s response was lost and fresh server truth shows
            the pseudonym generation is UNCHANGED — the rotation did not happen.
            You may start it again from the current state.
          </Callout>
        </div>
      )}

      {notice !== "" && (
        <div className={styles.calloutSpace}>
          <Callout variant="warning" title="Destination privacy" role="status">
            {notice}
          </Callout>
        </div>
      )}

      {p === undefined && page.q.isPending && (
        <Skeleton>Loading destination-privacy posture…</Skeleton>
      )}
      {p === undefined && page.q.isError && (
        <ErrorState title="Destination privacy unavailable">
          The destination-privacy posture could not be loaded. Refresh to try
          again.
        </ErrorState>
      )}

      {p !== undefined && (
        <Card title="Destination privacy">
          <p className={styles.refDetail}>
            <StatusBadge status="info">Node-local</StatusBadge> This setting
            governs what DESTINATION information this appliance retains in
            traffic logs and operational views. It does not change whether
            traffic is decrypted or inspected, and it applies to this node only
            — it is not distributed to the fleet, exported, or included in
            config-version rollback.
          </p>
          <KeyValue
            items={[
              [
                "Posture",
                p.redactHosts
                  ? "ON — destinations are pseudonymized in logs"
                  : "OFF — destinations are recorded in plaintext",
              ],
              ["Scope", p.scope === "" ? "not reported" : p.scope],
              [
                "Pseudonymized fields",
                p.scopeFields.length === 0 ? (
                  "not reported"
                ) : (
                  <Mono key="f">{p.scopeFields.join(", ")}</Mono>
                ),
              ],
              [
                "Pseudonym key",
                p.keyProvisioned
                  ? "provisioned on this node"
                  : "not provisioned",
              ],
              [
                "Pseudonym generation",
                p.keyId === "" ? "—" : <Mono key="g">{p.keyId}</Mono>,
              ],
            ]}
          />
          {p.redactHosts && !p.keyProvisioned && (
            <Callout
              variant="critical"
              title="Fail-closed sentinel"
              role="alert"
            >
              The posture is on but no pseudonym key is provisioned: this node
              records a constant sentinel instead of destinations (never
              plaintext) until a key exists.
            </Callout>
          )}
          {isAdmin && (
            <div className={styles.toolbarActions}>
              {p.redactHosts ? (
                <Button
                  size="sm"
                  disabled={page.unknown !== null}
                  onClick={() => {
                    setCeremony({ kind: "disable", revision: p.revision });
                    setNotice("");
                  }}
                >
                  Disable destination privacy…
                </Button>
              ) : (
                <Button
                  size="sm"
                  disabled={page.unknown !== null}
                  onClick={() => {
                    setCeremony({ kind: "enable", revision: p.revision });
                    setNotice("");
                  }}
                >
                  Enable destination privacy…
                </Button>
              )}
              <Button
                size="sm"
                variant="ghost"
                disabled={page.unknown !== null || unresolvedRotation !== null}
                onClick={() => {
                  setCeremony({
                    kind: "rotate",
                    revision: p.revision,
                    preKeyId: p.keyId,
                  });
                  setNotice("");
                }}
              >
                Rotate pseudonym key…
              </Button>
            </div>
          )}
        </Card>
      )}

      {ceremony?.kind === "enable" && (
        <ConfirmationDialog
          open
          tier={1}
          title="Enable destination privacy"
          body={
            <>
              Traffic logs and operational views on this node will record a
              keyed pseudonym instead of the plaintext destination (host, URI,
              dec.host/dec.sni, top-hosts). A node-local pseudonym key is
              provisioned if none exists. Log search by plaintext host stops
              resolving while the posture is on.
            </>
          }
          confirmLabel="Enable destination privacy"
          result={result}
          {...(errorText !== "" ? { errorText } : {})}
          onConfirm={() => {
            if (result !== "pending") runPosture(true, ceremony.revision);
          }}
          onCancel={() => {
            if (result !== "pending") closeCeremony();
          }}
        />
      )}

      {ceremony?.kind === "disable" && (
        <ConfirmationDialog
          open
          tier={2}
          title="Disable destination privacy"
          body={
            <>
              New traffic records on this node will carry the plaintext
              destination again. This changes what is RETAINED in logs and
              operational views — it does not enable or disable TLS inspection,
              and already-written pseudonymized records stay pseudonymized.
            </>
          }
          impact="More destination detail is retained and rendered in logs, SIEM forwarding, and operational views on this node from now on."
          rollback="Re-enable destination privacy at any time; the pseudonym key is kept."
          confirmLabel="Disable destination privacy"
          destructive
          result={result}
          {...(errorText !== "" ? { errorText } : {})}
          onConfirm={() => {
            if (result !== "pending") runPosture(false, ceremony.revision);
          }}
          onCancel={() => {
            if (result !== "pending") closeCeremony();
          }}
        />
      )}

      {ceremony?.kind === "rotate" && (
        <ConfirmationDialog
          open
          tier={3}
          title="Rotate the destination-pseudonym key"
          body={
            <>
              This rotates the node-local key that pseudonymizes DESTINATIONS in
              traffic logs. Existing and future pseudonyms will no longer
              correlate across the rotation boundary — analyses that join old
              and new records by destination token break permanently. This is
              NOT the TLS inspection Root CA and NOT a certificate rotation;
              proxied traffic is unaffected. The action is bound to the state
              you just reviewed (generation{" "}
              <Mono>
                {ceremony.preKeyId === "" ? "none" : ceremony.preKeyId}
              </Mono>
              ); if it changed meanwhile, the appliance refuses.
            </>
          }
          impact="Destination-pseudonym continuity breaks at the rotation boundary, node-wide and irreversibly."
          rollback="None — a rotation cannot be undone (a further rotation only breaks continuity again)."
          confirmLabel="Rotate pseudonym key"
          confirmWord="ROTATE"
          typedValue={typed}
          onTypedChange={setTyped}
          destructive
          result={result}
          {...(errorText !== "" ? { errorText } : {})}
          onConfirm={() => {
            if (result !== "pending") runRotation(ceremony);
          }}
          onCancel={() => {
            if (result !== "pending") closeCeremony();
          }}
        />
      )}
    </div>
  );
}
