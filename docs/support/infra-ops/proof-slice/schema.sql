-- Proof Slice — Postgres schema (migrations/0001_init.sql)
-- Owner: services/operation. The operation DB is the durable workflow/execution
-- state and (with operation_events) the authoritative record independent of chat.
-- Design-only; not applied.
--
-- STAGE-5 REVISION (qualification closure): added tenant_id (R7-F2 tenant isolation),
-- approver_signature (R7-F3), and the separated-signing-key requirement (R7-F1: plans,
-- approvals, and audit are each signed by a DISTINCT KMS/Ed25519 key — never one key).
-- Composite scope (tenant,env,region) is the G0 target (R2-F5); staging-only shown here.

BEGIN;

-- ─────────────────────────────────────────────────────────────────────────────
-- Worker registry: the SERVER-SIDE ALLOWLIST. Claude never names a raw worker,
-- image, or registry — it passes a worker_id that must exist and be allowlisted.
CREATE TABLE worker_registry (
    worker_id            text PRIMARY KEY,                 -- e.g. "tac-analysis-worker-1"
    tenant_id            text NOT NULL,                    -- R7-F2: every resource is tenant-scoped
    environment          text NOT NULL CHECK (environment = 'staging'),  -- slice: staging only
    allowlisted          boolean NOT NULL DEFAULT false,
    approved_registry    text NOT NULL,                    -- e.g. "registry.tac.example/analysis-worker"
    current_image_digest text,                             -- sha256:...
    known_good_digest    text,                             -- rollback target; sha256:...
    config               jsonb NOT NULL DEFAULT '{}'::jsonb,
    max_replicas         int  NOT NULL DEFAULT 1,
    updated_at           timestamptz NOT NULL DEFAULT now()
);

-- Allowlist of deployable image digests per worker (approved digests only).
CREATE TABLE approved_image_digests (
    worker_id    text NOT NULL REFERENCES worker_registry(worker_id),
    image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    approved_by  text NOT NULL,
    approved_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (worker_id, image_digest)
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Operations: the durable workflow record. One row per operation.
CREATE TABLE operations (
    id               text PRIMARY KEY,                     -- "OP-2026-000042"
    kind             text NOT NULL CHECK (kind IN ('restart','deploy')),
    level            text NOT NULL CHECK (level IN ('L2','L3')),
    tenant_id        text NOT NULL,                         -- R7-F2: op is tenant-scoped; policy enforces match
    environment      text NOT NULL CHECK (environment = 'staging'),
    worker_id        text NOT NULL REFERENCES worker_registry(worker_id),
    intent           text NOT NULL,                        -- human-readable requested outcome
    state            text NOT NULL CHECK (state IN (
                        'CREATED','DISCOVERING','PLANNING','POLICY_REJECTED',
                        'REVIEW_PENDING','APPROVAL_PENDING','APPROVED',
                        'EXECUTION_QUEUED','EXECUTING','VALIDATING','SUCCEEDED','FAILED',
                        'ROLLBACK_PENDING','ROLLING_BACK','ROLLED_BACK',
                        'CANCELLED','EXPIRED','MANUAL_INTERVENTION_REQUIRED')),
    current_plan_id  text,                                 -- FK set once PLANNING succeeds
    rollback_target  jsonb,                                -- {commit_sha, image_digest, config} previous known-good
    idempotency_key  text NOT NULL,                        -- client-supplied; dedups create
    initiating_user  text NOT NULL,                        -- human operator identity
    session_meta     jsonb NOT NULL DEFAULT '{}'::jsonb,   -- model/session id, agent role (audit only)
    version          integer NOT NULL DEFAULT 0,           -- optimistic concurrency (CAS)
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,                 -- op-level expiry (e.g. now()+30m)
    CONSTRAINT uq_idem UNIQUE (idempotency_key)            -- exactly-once create
);
CREATE INDEX ix_ops_state ON operations(state);
CREATE INDEX ix_ops_worker ON operations(worker_id) WHERE state IN
    ('EXECUTION_QUEUED','EXECUTING','VALIDATING','ROLLBACK_PENDING','ROLLING_BACK');

-- ─────────────────────────────────────────────────────────────────────────────
-- Plans: immutable, signed plan artifacts. A changed commit ⇒ new plan_id.
CREATE TABLE plans (
    plan_id             text PRIMARY KEY,                  -- content-addressed: "PLAN-<sha256[:12]>"
    op_id               text NOT NULL REFERENCES operations(id),
    kind                text NOT NULL CHECK (kind IN ('restart','deploy')),
    commit_sha          text,                              -- desired-state commit (deploy)
    config_digest       text NOT NULL,                     -- sha256 of the rendered config
    provider_lock_digest text,                             -- sha256 of .terraform.lock.hcl (deploy)
    target_image_digest text,                              -- sha256:... (deploy)
    expected_changes    jsonb NOT NULL,                    -- parsed `tofu plan -json` (deploy) or {action:'restart'}
    policy_result       jsonb NOT NULL,                    -- {passed:bool, rules:[{id,pass,detail}]}
    review_results      jsonb NOT NULL DEFAULT '{}'::jsonb,-- {security:{verdict,findings}, cost:{delta_usd}}
    rollback_target     jsonb NOT NULL,                    -- previous known-good {commit_sha,image_digest,config}
    cost_delta_usd      numeric NOT NULL DEFAULT 0,
    signature           text NOT NULL,                     -- Ed25519 over the canonical plan body
    signer_key_id       text NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL               -- plan expiry (e.g. now()+15m)
);
ALTER TABLE operations
    ADD CONSTRAINT fk_current_plan FOREIGN KEY (current_plan_id) REFERENCES plans(plan_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- Reviews: advisory independent-agent findings (never the safety boundary).
CREATE TABLE reviews (
    id          bigserial PRIMARY KEY,
    plan_id     text NOT NULL REFERENCES plans(plan_id),
    reviewer    text NOT NULL CHECK (reviewer IN ('security','cost')),
    verdict     text NOT NULL CHECK (verdict IN ('OK','BLOCK')),
    findings    jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (plan_id, reviewer)
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Approvals: human authorization, cryptographically BOUND to a plan signature.
CREATE TABLE approvals (
    approval_id       text PRIMARY KEY,                    -- "APPROVAL-..."
    op_id             text NOT NULL REFERENCES operations(id),
    plan_id           text NOT NULL REFERENCES plans(plan_id),
    bound_plan_signature text NOT NULL,                    -- MUST equal plans.signature at apply time
    approver          text NOT NULL,                       -- human identity
    approver_is_author boolean NOT NULL DEFAULT false,     -- must be false to be valid
    dual_required     boolean NOT NULL DEFAULT false,
    second_approver   text,                                -- non-null when dual_required
    decision          text NOT NULL CHECK (decision IN ('APPROVED','REJECTED')),
    approver_signature text NOT NULL,                      -- R7-F3: approver's signature over {op_id,plan_id,plan_signature,decision} (distinct approval-key)
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,                -- inherits plan expiry
    single_use_consumed boolean NOT NULL DEFAULT false,
    UNIQUE (op_id, plan_id)                                -- one approval per (op,plan)
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Leases: per-worker apply serialization (concurrency guarantee).
CREATE TABLE leases (
    resource_key  text PRIMARY KEY,                        -- "staging:tac-analysis-worker-1"
    holder_op_id  text NOT NULL REFERENCES operations(id),
    holder_exec   text NOT NULL,                           -- executor instance id
    acquired_at   timestamptz NOT NULL DEFAULT now(),
    heartbeat_at  timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL                     -- TTL (e.g. now()+90s), heartbeated
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Operation events: APPEND-ONLY, SIGNED audit + state-transition log.
-- This is the record that remains understandable without the chat.
CREATE TABLE operation_events (
    id            bigserial PRIMARY KEY,
    op_id         text NOT NULL REFERENCES operations(id),
    seq           int NOT NULL,                            -- per-op monotonic
    ts            timestamptz NOT NULL DEFAULT now(),
    actor         text NOT NULL,                           -- 'claude:planner' | 'human:<id>' | 'executor:<id>' | 'policy' | 'validator' | 'reconciler'
    actor_kind    text NOT NULL CHECK (actor_kind IN ('model','human','service')),
    event_type    text NOT NULL,                           -- 'operation.created', 'policy.rejected', ...
    from_state    text,
    to_state      text,
    detail        jsonb NOT NULL DEFAULT '{}'::jsonb,      -- refs only, NEVER secrets
    prev_hash     text,                                    -- hash chain over previous event (tamper-evident)
    hash          text NOT NULL,                           -- sha256(canonical(event) || prev_hash)
    signature     text NOT NULL,                           -- audit-writer Ed25519 signature
    UNIQUE (op_id, seq)
);
CREATE INDEX ix_events_op ON operation_events(op_id, seq);

-- ─────────────────────────────────────────────────────────────────────────────
-- Execution results: provider response + validation outcome (per op attempt).
CREATE TABLE execution_results (
    id                bigserial PRIMARY KEY,
    op_id             text NOT NULL REFERENCES operations(id),
    attempt           int NOT NULL DEFAULT 1,
    phase             text NOT NULL CHECK (phase IN ('apply','restart','rollback')),
    provider_response jsonb,                                -- raw-ish provider result (redacted)
    applied_resources jsonb NOT NULL DEFAULT '[]'::jsonb,   -- per-resource outcome (partial-success detection)
    validation_result jsonb,                                -- {gates:[{name,pass,detail}], passed:bool}
    outcome           text CHECK (outcome IN ('succeeded','failed','partial','rolled_back','manual_required')),
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (op_id, attempt, phase)
);

COMMIT;

-- Notes:
-- * No table stores a secret value; identity/creds live in the broker, resolved
--   inside the executor process only. `detail`/`provider_response` are redacted.
-- * operation_events is append-only (no UPDATE/DELETE grant); hash-chained + signed.
-- * All state transitions: single txn = UPDATE operations (version CAS) + INSERT event.
