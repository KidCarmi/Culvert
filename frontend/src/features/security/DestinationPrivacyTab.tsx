// 2E-B Destination Privacy: the NODE-LOCAL posture governing what DESTINATION
// information is retained/rendered in traffic logs and observability. It is
// NOT TLS inspection, NOT a Decryption Profile, and NOT CA management; the
// pseudonym key is NOT the TLS inspection Root CA and rotating it is NOT a
// certificate rotation. Enable is a light T1 confirm (protective direction),
// disable is a T2 ceremony, key rotation is a T3 typed ceremony bound to
// fresh server truth. Rotation is NEVER blindly retried: each rotation
// carries a fresh client-minted operation id; an unknown outcome latches and
// is resolved against fresh GET truth PER OPERATION (2E-B correction) — our
// receipt present = landed exactly once; rotation sequence unchanged = did
// not land; sequence advanced without our receipt = AMBIGUOUS (stay
// latched; another admin may have rotated). A proven landed/not-landed
// resolution converts into a durable local notice and CLEARS the latch, so
// a deliberate NEW rotation (with a NEW operation id) becomes possible;
// nothing is ever re-dispatched automatically.
import { useCallback, useEffect, useRef, useState, type JSX } from "react";
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
import { useAuth } from "../../auth/AuthProvider";
import { asRevisionConflict } from "../../api/urlcat";
import { serverErrorText, unknownOutcome } from "../../shared/mutationOutcome";
import {
  getDestinationPrivacy,
  mintRotationOperationId,
  putDestinationPrivacy,
  rotatePseudonymKey,
} from "../../api/decryption";
import {
  clearRotationRecovery,
  readRotationRecovery,
  writeRotationRecovery,
} from "./rotationRecovery";
import styles from "../policy/policy.module.css";

type Ceremony =
  | { kind: "enable"; revision: string }
  | { kind: "disable"; revision: string }
  | {
      kind: "rotate";
      revision: string;
      preKeyId: string;
      /** rotation_seq at review time — the NOT-LANDED proof anchor. */
      preSeq: number;
      /** Fresh opaque identity for THIS operation (never reused). */
      operationId: string;
    }
  // The explicit AMBIGUOUS recovery: consciously give up proof of one
  // irreversible operation. Never a mutation — it only retires the durable
  // recovery marker so a NEW deliberate T3 rotation becomes possible.
  | { kind: "abandon"; operationId: string };

/** A transport-lost rotation awaiting per-operation proof from fresh truth. */
interface UnresolvedRotation {
  operationId: string;
  preSeq: number;
}

/** An authoritative per-operation resolution, kept as a durable local notice
 * after the latch clears. */
type RotationResolution =
  { kind: "landed"; keyId: string } | { kind: "not-landed" };

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
  // Subject binding for the durable recovery marker: the authenticated
  // username from the auth machine — the strongest session identity the
  // frontend holds. A marker written under a different subject is discarded
  // at read time; the auth boundary clears it globally (rotationRecovery.ts).
  const subject = useAuth().state.user;
  const [ceremony, setCeremony] = useState<Ceremony | null>(null);
  const [typed, setTyped] = useState("");
  const [result, setResult] = useState<ConfirmResult>("idle");
  const [errorText, setErrorText] = useState("");
  const [notice, setNotice] = useState("");
  // Pending rotation whose response was LOST: resolved against fresh GET
  // truth PER OPERATION (receipt / sequence) — never by repeating it.
  const [unresolvedRotation, setUnresolvedRotation] =
    useState<UnresolvedRotation | null>(null);

  // RECOVERY-HYDRATION GATE (TRUE FINAL closure, Blocker 1). The snapshot
  // model caches with staleTime:Infinity and a SPA route-away/route-back
  // keeps the QueryClient alive, so `p` can be the PRE-operation snapshot —
  // classifying a restored marker against it can falsely prove NOT-LANDED
  // and re-arm Rotate toward a second continuity-breaking rotation.
  //   "inspecting"  — the marker has not been checked yet (first render;
  //                   Rotate withheld even under a warm cache).
  //   "stale"       — a marker was restored; a FRESH authoritative GET,
  //                   initiated AFTER recovery entry, is in flight. Cached
  //                   data may render for context but must not classify,
  //                   clear the marker, or enable Rotate.
  //   "fetch-failed"— that recovery GET failed: marker + latch retained,
  //                   Rotate stays blocked, explicit retry offered.
  //   "fresh"       — no marker existed, or the post-restore GET succeeded;
  //                   classification and Rotate follow the normal rules.
  const [recoveryGate, setRecoveryGate] = useState<
    "inspecting" | "stale" | "fetch-failed" | "fresh"
  >("inspecting");

  // The pre-recovery dataUpdatedAt stamp: only a successful fetch that
  // completed STRICTLY AFTER this stamp is post-restore authoritative truth.
  const recoveryStaleStampRef = useRef(0);

  const refetchPrivacy = page.q.refetch;
  const runRecoveryFetch = useCallback((): void => {
    setRecoveryGate("stale");
    // The refetch promise is used ONLY for the failure transition. Its
    // success value must NOT open the gate: a refetch cancelled by an
    // unmount (StrictMode's simulated one included) resolves "success"
    // while ECHOING the pre-recovery cached result — exactly the stale
    // truth this gate exists to keep inert. Freshness is judged solely by
    // the dataUpdatedAt stamp effect below.
    void refetchPrivacy().then((res) => {
      if (res.status === "error") {
        setRecoveryGate((cur) => (cur === "stale" ? "fetch-failed" : cur));
      }
    });
  }, [refetchPrivacy]);

  // Freshness judge: the gate opens only when a SUCCESSFUL, settled fetch
  // carries data newer than the pre-recovery stamp — i.e. an authoritative
  // GET that completed after recovery entry (whoever initiated it).
  useEffect(() => {
    if (recoveryGate !== "stale" && recoveryGate !== "fetch-failed") return;
    if (
      page.q.isSuccess &&
      !page.q.isFetching &&
      page.q.dataUpdatedAt > recoveryStaleStampRef.current
    ) {
      setRecoveryGate("fresh");
    }
  }, [recoveryGate, page.q.isSuccess, page.q.isFetching, page.q.dataUpdatedAt]);

  // Restore the DURABLE recovery marker on mount (lifecycle closure): the
  // identity of a dispatched-but-unconfirmed T3 operation survives route
  // navigation and page reload until a terminal/recovery decision. An
  // EFFECT rather than a state initializer, deliberately: the unmount-path
  // boundary cleanup clears the transient latch state, and StrictMode's
  // simulated unmount would otherwise wipe the restored value; the effect
  // re-reads after every (re)mount pass. A foreign-subject marker is
  // discarded by the read itself, never inherited. A restored marker
  // immediately forces the fresh recovery GET.
  useEffect(() => {
    const m = readRotationRecovery(subject);
    if (m === null) {
      setRecoveryGate("fresh");
      return;
    }
    setUnresolvedRotation(m);
    // Everything the query holds RIGHT NOW is pre-recovery: stamp it stale.
    recoveryStaleStampRef.current = Math.max(
      recoveryStaleStampRef.current,
      page.q.dataUpdatedAt,
    );
    runRecoveryFetch();
    // The restore re-runs per (re)mount pass and identity change only —
    // page.q.dataUpdatedAt is read at restore time, deliberately not a dep.
  }, [subject, runRecoveryFetch]);
  // Durable local record of the last authoritative resolution (survives the
  // latch clearing; replaced only by a new ceremony or the auth boundary).
  const [resolution, setResolution] = useState<RotationResolution | null>(null);

  page.setBoundaryCleanup(() => {
    setCeremony(null);
    setTyped("");
    setResult("idle");
    setErrorText("");
    setNotice("");
    setUnresolvedRotation(null);
    setResolution(null);
  });

  // Classify the unresolved operation against the CURRENT fresh truth. This
  // is the directive's matrix, exactly: (1) our receipt exists ⇒ LANDED;
  // (2) the sequence still equals our pre-operation anchor and no receipt ⇒
  // NOT LANDED; (3) anything else ⇒ AMBIGUOUS (another admin may have
  // rotated, or our receipt aged out of the bounded window) — no claim.
  const pendingClass =
    unresolvedRotation !== null &&
    p !== undefined &&
    page.unknown === null &&
    recoveryGate === "fresh"
      ? ((): "landed" | "not-landed" | "ambiguous" => {
          const rcpt = p.receipts.find(
            (r) => r.operationId === unresolvedRotation.operationId,
          );
          if (rcpt !== undefined) return "landed";
          if (p.rotationSeq === unresolvedRotation.preSeq) return "not-landed";
          return "ambiguous";
        })()
      : null;

  // A PROVEN outcome converts into the durable notice and clears the latch
  // (2E-B correction, Minor C) — a fresh deliberate rotation becomes possible
  // again. AMBIGUOUS deliberately stays latched. Never dispatches anything.
  useEffect(() => {
    if (
      unresolvedRotation === null ||
      p === undefined ||
      page.unknown !== null ||
      recoveryGate !== "fresh" // never resolve from pre-recovery cache
    )
      return;
    const rcpt = p.receipts.find(
      (r) => r.operationId === unresolvedRotation.operationId,
    );
    if (rcpt !== undefined) {
      setResolution({ kind: "landed", keyId: rcpt.keyId });
      setUnresolvedRotation(null);
      clearRotationRecovery(); // terminal: proven landed
    } else if (p.rotationSeq === unresolvedRotation.preSeq) {
      setResolution({ kind: "not-landed" });
      setUnresolvedRotation(null);
      clearRotationRecovery(); // terminal: proven not landed
    }
  }, [unresolvedRotation, p, page.unknown, recoveryGate]);

  const closeCeremony = (): void => {
    setCeremony(null);
    setTyped("");
    setResult("idle");
    setErrorText("");
  };

  const handleFailure = (err: unknown, action: string): void => {
    if (unknownOutcome(err)) {
      if (ceremony?.kind === "rotate") {
        // The durable marker (written before dispatch) stays: only a
        // terminal outcome or the explicit abandon ceremony retires it.
        setUnresolvedRotation({
          operationId: ceremony.operationId,
          preSeq: ceremony.preSeq,
        });
      }
      page.latchUnknown("edit");
      closeCeremony();
      return;
    }
    if (asRevisionConflict(err) !== null) {
      if (ceremony?.kind === "rotate") clearRotationRecovery(); // authoritative: refused, nothing landed
      closeCeremony();
      setNotice(
        "The destination-privacy state changed on the appliance since you loaded it. Nothing was changed — review the refreshed state and retry from fresh truth.",
      );
      page.refreshToResolve();
      return;
    }
    if (ceremony?.kind === "rotate") clearRotationRecovery(); // the appliance answered: no rotation occurred
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
    // LOAD-BEARING ORDER + FAIL-CLOSED PERSISTENCE (TRUE FINAL closure,
    // Blocker 2): the recovery identity is persisted AND verified
    // recoverable BEFORE the network dispatch. No durable marker ⇒ no T3
    // rotation — there is deliberately no memory-only fallback for this one
    // irreversible operation.
    if (
      !writeRotationRecovery(subject, {
        operationId: c.operationId,
        preSeq: c.preSeq,
      })
    ) {
      setResult("failed");
      setErrorText(
        "The browser could not create the recovery record required for a safe key rotation. No rotation was sent.",
      );
      return;
    }
    const signal = page.owner.begin();
    setResult("pending");
    rotatePseudonymKey(c.operationId, c.revision, signal)
      .then((res) => {
        clearRotationRecovery(); // terminal: outcome confirmed by response
        closeCeremony();
        setNotice(
          res.alreadyApplied
            ? `This rotation had already landed exactly once (generation ${res.keyId}); nothing was rotated again.`
            : `Pseudonym key rotated. New pseudonym generation: ${res.keyId}. Records written before this rotation no longer correlate with new ones.`,
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

      {unresolvedRotation !== null &&
        (recoveryGate === "inspecting" || recoveryGate === "stale") && (
          <div className={styles.calloutSpace}>
            <Callout
              variant="unknown"
              title="Verifying an unresolved rotation"
              role="status"
            >
              An earlier rotation&apos;s outcome is unconfirmed. The appliance
              is being asked for fresh truth; cached information is NOT used to
              resolve it, and the rotate action stays unavailable until the
              appliance answers.
            </Callout>
          </div>
        )}
      {unresolvedRotation !== null && recoveryGate === "fetch-failed" && (
        <div className={styles.calloutSpace}>
          <Callout
            variant="critical"
            title="Unresolved rotation not verified"
            role="alert"
          >
            The appliance could not be reached to verify the unresolved
            rotation. Cached information may be stale and is not used to resolve
            it; the rotate action stays unavailable until fresh truth arrives.
            <div className={styles.fallbackAction}>
              <Button size="sm" onClick={runRecoveryFetch}>
                Retry verification
              </Button>
            </div>
          </Callout>
        </div>
      )}

      {pendingClass === "ambiguous" && (
        <div className={styles.calloutSpace}>
          <Callout
            variant="unknown"
            title="Rotation outcome unproven"
            role="alert"
          >
            The rotation&apos;s response was lost, and the appliance&apos;s
            state has changed since — but it holds no receipt for the specific
            rotation you started, so its outcome cannot yet be proven (another
            admin may have rotated meanwhile). No landed or not-landed claim can
            be made; do not start another rotation from here. Refresh to
            re-check.
            {isAdmin && unresolvedRotation !== null && (
              <div className={styles.fallbackAction}>
                <Button
                  size="sm"
                  onClick={() => {
                    setCeremony({
                      kind: "abandon",
                      operationId: unresolvedRotation.operationId,
                    });
                    setNotice("");
                  }}
                >
                  Resolve ambiguous rotation…
                </Button>
              </div>
            )}
          </Callout>
        </div>
      )}
      {(resolution?.kind === "landed" || pendingClass === "landed") && (
        <div className={styles.calloutSpace}>
          <Callout variant="warning" title="Rotation landed" role="alert">
            The rotation&apos;s response was lost, but the appliance holds the
            receipt for the specific rotation you started — it landed exactly
            once
            {resolution?.kind === "landed" && resolution.keyId !== "" ? (
              <>
                {" "}
                (generation <Mono>{resolution.keyId}</Mono>)
              </>
            ) : null}
            . It will not run again on its own; a further rotation is a new,
            deliberate operation.
          </Callout>
        </div>
      )}
      {(resolution?.kind === "not-landed" || pendingClass === "not-landed") && (
        <div className={styles.calloutSpace}>
          <Callout variant="warning" title="Rotation did not land" role="alert">
            The rotation&apos;s response was lost and the appliance&apos;s
            rotation sequence is unchanged — the rotation you started did not
            occur. You may deliberately start a new rotation from the current
            state.
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
                disabled={
                  page.unknown !== null ||
                  unresolvedRotation !== null ||
                  recoveryGate !== "fresh"
                }
                onClick={() => {
                  // A NEW deliberate operation: fresh identity, fresh anchors,
                  // and the previous resolution notice retires. An old
                  // operation id is never reused.
                  setCeremony({
                    kind: "rotate",
                    revision: p.revision,
                    preKeyId: p.keyId,
                    preSeq: p.rotationSeq,
                    operationId: mintRotationOperationId(),
                  });
                  setNotice("");
                  setResolution(null);
                }}
              >
                Rotate pseudonym key…
              </Button>
            </div>
          )}
        </Card>
      )}

      {ceremony?.kind === "abandon" && (
        <ConfirmationDialog
          open
          tier={3}
          title="Resolve ambiguous rotation"
          body={
            <>
              The appliance cannot prove whether your previous specific rotation
              (operation <Mono>{ceremony.operationId}</Mono>) landed: it holds
              no receipt for it while the rotation sequence has advanced.
              Confirming abandons automatic attribution for that operation
              permanently — this consciously gives up proof of an irreversible
              operation. Nothing is rotated or changed on the appliance now.
              Starting a future rotation is a NEW deliberate action with a new
              identity — and if the abandoned operation actually landed, a
              further rotation will break destination-pseudonym continuity
              again.
            </>
          }
          impact="The pending operation's recovery identity is discarded on this browser; its true outcome will never be automatically attributed."
          rollback="None — once abandoned, the operation cannot be re-latched for automatic resolution."
          confirmLabel="Abandon unresolved rotation"
          confirmWord="ABANDON"
          typedValue={typed}
          onTypedChange={setTyped}
          destructive
          result={result}
          onConfirm={() => {
            // NO mutation is dispatched as part of recovery: this only
            // retires the durable marker and re-reads authoritative state.
            clearRotationRecovery();
            setUnresolvedRotation(null);
            setResolution(null);
            closeCeremony();
            setNotice(
              "The unresolved rotation was abandoned — nothing was changed on the appliance and its outcome remains unattributed. Any future rotation is a new deliberate action.",
            );
            page.refreshToResolve();
          }}
          onCancel={() => {
            closeCeremony();
          }}
        />
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
