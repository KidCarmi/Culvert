package export

import (
	"context"
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
)

// Exporter is the pluggable additive sink. An implementation receives a bounded
// batch of safe events and returns an authenticated acknowledgment (how many it
// durably accepted). It is ADDITIVE: a failure here never erases local durability.
// PR-8 ships only deterministic in-memory exporters; a network SIEM/bus client is
// out of scope.
type Exporter interface {
	// Export durably delivers a bounded batch and returns the number accepted. A
	// returned error (or accepted < len(batch)) leaves the local records intact and
	// the cursor unadvanced past the accepted prefix.
	Export(ctx context.Context, batch []model.Event) (accepted int, err error)
}

// AckFunc is called after a batch is acknowledged, with the highest sequence in
// the acknowledged prefix, so the caller can advance a durable cursor and mark
// segments exported (never before the ack).
type AckFunc func(part model.Partition, throughSeq uint64)

// PumpConfig parameterises one bounded export pump.
type PumpConfig struct {
	Reader     Reader
	Exporter   Exporter
	Limits     limits.EventLimits
	Auth       Authorization
	Partition  model.Partition
	BatchSize  int
	MaxRetries int
	OnAck      AckFunc
}

// Pump drives bounded export of one partition. It is single-worker by design (the
// manager runs a bounded pool of pumps); there is no per-event goroutine and no
// unbounded in-memory backlog — it reads a batch, exports it, advances the cursor
// only on ack, and stops on context cancel.
type Pump struct {
	cfg    PumpConfig
	mu     sync.Mutex
	cursor uint64
}

// NewPump builds a pump starting at cursor.
func NewPump(cfg PumpConfig, startCursor uint64) *Pump {
	return &Pump{cfg: cfg, cursor: startCursor}
}

// Cursor returns the current acknowledged cursor.
func (p *Pump) Cursor() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cursor
}

// Step performs one bounded read→export→ack cycle. It returns the number of events
// exported this step (0 when nothing was pending) and an error. On an export
// error the cursor does NOT advance (local durability is preserved) and the error
// is returned after bounded retries. Step is what the manager's bounded worker
// loop calls; it never blocks indefinitely.
func (p *Pump) Step(ctx context.Context) (int, error) {
	p.mu.Lock()
	cur := p.cursor
	p.mu.Unlock()

	res, err := Read(p.cfg.Reader, p.cfg.Limits, p.cfg.Auth, p.cfg.Partition, cur)
	if err != nil {
		return 0, err
	}
	next := res.NextCursor
	if len(res.Events) == 0 {
		// Advance the scan cursor even when nothing matched the tenant filter, so a
		// stream of other-tenant records does not wedge this pump — but only up to
		// what was scanned, never past a pending record.
		p.advance(next)
		return 0, nil
	}
	batch := res.Events
	if p.cfg.BatchSize > 0 && len(batch) > p.cfg.BatchSize {
		batch = batch[:p.cfg.BatchSize]
	}
	accepted, xerr := p.exportWithRetry(ctx, batch)
	if xerr != nil || accepted == 0 {
		// Fail-safe: keep local durability, do not advance the cursor.
		return 0, xerr
	}
	// Advance only through the acknowledged prefix.
	throughSeq := next
	if accepted < len(batch) {
		throughSeq = cur + uint64(accepted) // conservative: advance by accepted count
	}
	p.advance(throughSeq)
	if p.cfg.OnAck != nil {
		p.cfg.OnAck(p.cfg.Partition, throughSeq)
	}
	return accepted, nil
}

func (p *Pump) advance(to uint64) {
	p.mu.Lock()
	if to > p.cursor {
		p.cursor = to
	}
	p.mu.Unlock()
}

func (p *Pump) exportWithRetry(ctx context.Context, batch []model.Event) (int, error) {
	var lastErr error
	tries := p.cfg.MaxRetries
	if tries < 1 {
		tries = 1
	}
	for i := 0; i < tries; i++ {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		accepted, err := p.cfg.Exporter.Export(ctx, batch)
		if err == nil {
			return accepted, nil
		}
		lastErr = err
	}
	return 0, lastErr
}
