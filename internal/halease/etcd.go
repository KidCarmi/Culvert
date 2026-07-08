package halease

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// leaderKey is the single cluster-wide lease-bound key. Its value is the
// holder's candidate ID; its create_revision is the fencing epoch —
// strictly monotonic across the etcd cluster's life, survives etcd
// restarts, cannot go backwards (ADR-0005: this is what retires the
// hand-rolled-witness durability finding).
const leaderKey = "/culvert/ha/leader"

// Config configures the etcd-backed Provider.
type Config struct {
	Endpoints   []string
	TLS         *tls.Config   // nil = plaintext (operator's call; S5 wires flags)
	TTL         time.Duration // lease TTL; rounded up to whole seconds, min 1s; default 10s
	DialTimeout time.Duration // default 5s
}

// Etcd is the etcd-backed Provider (ADR-0005 S1 default implementation).
type Etcd struct {
	cli *clientv3.Client
	ttl int64 // seconds

	mu      sync.Mutex
	leaseID clientv3.LeaseID // our held lease; 0 = none
	epoch   int64            // create_revision of our grant; 0 = none
	holder  string           // candidateID we acquired with
}

// NewEtcd connects to etcd and returns the Provider. It does NOT touch the
// leader key — connection only.
func NewEtcd(cfg Config) (*Etcd, error) {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	ttlSec := int64((ttl + time.Second - 1) / time.Second) // round up; etcd minimum is 1s
	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 5 * time.Second
	}
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: dialTimeout,
		TLS:         cfg.TLS,
	})
	if err != nil {
		return nil, fmt.Errorf("halease: etcd connect: %w", err)
	}
	return &Etcd{cli: cli, ttl: ttlSec}, nil
}

// Acquire implements Provider: a single transaction that puts the
// lease-bound key iff it does not exist. etcd deletes the key when the
// old holder's lease expires, so "free or expired" is exactly
// create_revision == 0.
func (e *Etcd) Acquire(ctx context.Context, candidateID string) (bool, Status, error) {
	grant, err := e.cli.Grant(ctx, e.ttl)
	if err != nil {
		return false, Status{}, fmt.Errorf("halease: lease grant: %w", err)
	}
	txn, err := e.cli.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(leaderKey), "=", 0)).
		Then(clientv3.OpPut(leaderKey, candidateID, clientv3.WithLease(grant.ID))).
		Else(clientv3.OpGet(leaderKey)).
		Commit()
	if err != nil {
		// The grant may leak until its TTL if this revoke also fails —
		// harmless: an unattached lease pins no key.
		_, _ = e.cli.Revoke(context.WithoutCancel(ctx), grant.ID)
		return false, Status{}, fmt.Errorf("halease: acquire txn: %w", err)
	}

	if txn.Succeeded {
		// We created the key: its create_revision IS the txn's revision.
		epoch := txn.Header.Revision
		e.mu.Lock()
		e.leaseID, e.epoch, e.holder = grant.ID, epoch, candidateID
		e.mu.Unlock()
		return true, Status{Holder: candidateID, Epoch: epoch, ValidFor: time.Duration(e.ttl) * time.Second}, nil
	}

	// Denied: someone holds it. Release our unused grant and report theirs.
	_, _ = e.cli.Revoke(context.WithoutCancel(ctx), grant.ID)
	kvs := txn.Responses[0].GetResponseRange().Kvs
	if len(kvs) == 0 {
		// Holder vanished between txn evaluation and now; caller retries.
		return false, Status{}, nil
	}
	st := Status{Holder: string(kvs[0].Value), Epoch: kvs[0].CreateRevision}
	if ttl, err := e.cli.TimeToLive(ctx, clientv3.LeaseID(kvs[0].Lease)); err == nil && ttl.TTL > 0 {
		st.ValidFor = time.Duration(ttl.TTL) * time.Second
	}
	return false, st, nil
}

// Renew implements Provider: keepalive our lease, then re-verify the key
// still carries our (holder, epoch). The re-verify guards the fencing
// property even if a stray keepalive outlives the key.
func (e *Etcd) Renew(ctx context.Context, holderID string, epoch int64) (bool, time.Duration, error) {
	e.mu.Lock()
	leaseID, ourEpoch, ourHolder := e.leaseID, e.epoch, e.holder
	e.mu.Unlock()
	if leaseID == 0 || ourEpoch != epoch || ourHolder != holderID {
		return false, 0, nil // never held / stale caller state ⇒ lost
	}
	ka, err := e.cli.KeepAliveOnce(ctx, leaseID)
	if err != nil {
		// etcd reports a vanished lease as ErrLeaseNotFound: the lease
		// expired ⇒ we LOST (an outcome, nil error). Everything else is
		// transport-unknown ⇒ error (caller fails toward self-fence).
		if errors.Is(err, rpctypes.ErrLeaseNotFound) {
			e.clearHeld()
			return false, 0, nil
		}
		return false, 0, fmt.Errorf("halease: keepalive: %w", err)
	}
	// Lease is alive — verify the key is still OUR grant.
	get, err := e.cli.Get(ctx, leaderKey)
	if err != nil {
		return false, 0, fmt.Errorf("halease: renew verify: %w", err)
	}
	if len(get.Kvs) == 0 || get.Kvs[0].CreateRevision != epoch || string(get.Kvs[0].Value) != holderID {
		e.clearHeld()
		return false, 0, nil
	}
	return true, time.Duration(ka.TTL) * time.Second, nil
}

// Read implements Provider.
func (e *Etcd) Read(ctx context.Context) (Status, error) {
	get, err := e.cli.Get(ctx, leaderKey)
	if err != nil {
		return Status{}, fmt.Errorf("halease: read: %w", err)
	}
	if len(get.Kvs) == 0 {
		return Status{}, nil
	}
	st := Status{Holder: string(get.Kvs[0].Value), Epoch: get.Kvs[0].CreateRevision}
	if ttl, err := e.cli.TimeToLive(ctx, clientv3.LeaseID(get.Kvs[0].Lease)); err == nil && ttl.TTL > 0 {
		st.ValidFor = time.Duration(ttl.TTL) * time.Second
	}
	return st, nil
}

// Close implements Provider: closes the client connection WITHOUT revoking
// a held lease (release-on-shutdown is S2 policy; an unrevoked lease
// simply expires after its TTL).
func (e *Etcd) Close() error { return e.cli.Close() }

// clearHeld drops the local held-lease record after a confirmed loss.
func (e *Etcd) clearHeld() {
	e.mu.Lock()
	e.leaseID, e.epoch, e.holder = 0, 0, ""
	e.mu.Unlock()
}
