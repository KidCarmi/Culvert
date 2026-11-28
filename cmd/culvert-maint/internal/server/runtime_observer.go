// Runtime health observer (ADR-0062 slice 5).
//
// One loop that watches the running proxy and records what it saw. It is an
// observer only, by construction:
//
//   - it never begins an operation, takes no lock and writes no journal record
//     or audit entry;
//   - it reaches Docker only through observerDocker, whose two methods are
//     reads (`compose ps` + inspects, and an inspect of the fixed tag). No
//     method that pulls, tags or recreates is reachable from here;
//   - it writes only <state_dir>/health (runtimehealth).
//
// Each tick:
//
//  1. skip while the maintenance lock is held or the settle window is open:
//     whatever it saw then could be a container an operation is replacing;
//  2. read identity (container id, its image, the fixed tag's image);
//  3. run the production health probe (HealthProbeFactory, the probe every
//     gate uses), bounded by its own budget;
//  4. read identity again, and look at the lock and the window again. If
//     anything changed in between, the sample is discarded: a probe result is
//     evidence only about the container it was taken against.
//
// A gate that passed with identity unchanged is `gated` and, when the image
// has a validated allow-listed reference, becomes last_good.json. Nothing else
// writes that file, so an unhealthy, unknown or stale observation never
// erases the last-known-good evidence (owner decision 5).
package server

import (
	"context"
	"log"
	"sync"
	"time"

	"culvert-maint/internal/health"
	"culvert-maint/internal/runner"
	"culvert-maint/internal/runtimehealth"
)

// observerDocker is everything the observer may ask Docker. Both are reads;
// *runner.Runner satisfies it.
type observerDocker interface {
	ReadProxyContainer(ctx context.Context) (*runner.ProxyContainer, error)
	PinnedTagImageID(ctx context.Context) (string, error)
}

// runtimeObserver is the observer's in-memory state.
type runtimeObserver struct {
	// docker overrides s.opts.Runner (tests).
	docker observerDocker
	// now overrides time.Now (tests).
	now func() time.Time
	// afterProbe, when set (tests only), runs between the probe and the
	// second identity read.
	afterProbe func()
	mu         sync.Mutex
	lastLogged string // state/reason last logged, so only changes are logged
}

// Outcomes of one tick, for tests and logs.
const (
	obsSkippedLock     = "skipped_lock_held"
	obsSkippedSettle   = "skipped_settle_open"
	obsDiscarded       = "discarded_identity_changed"
	obsDiscardedLock   = "discarded_lock_taken"
	obsWriteFailed     = "write_failed"
	obsRecorded        = "recorded"
	obsRecordedAndGood = "recorded_last_good"
)

// Reasons written into a sample.
const (
	obsReasonDockerUnreadable     = "docker_unreadable"
	obsReasonTagUnreadable        = "pinned_tag_unreadable"
	obsReasonNoContainer          = "no_proxy_container"
	obsReasonNotRunning           = "container_not_running"
	obsReasonProbeError           = "probe_error"
	obsReasonNotReady             = "not_ready"
	obsReasonGateOK               = "gate_passed"
	obsReasonGateOKNoRef          = "gate_passed_no_validated_ref"
	obsReasonGateOKGoodUnwritable = "gate_passed_last_good_unwritable"
)

// runtimeObserverEnabled reports whether the observer has what it needs.
func (s *Server) runtimeObserverEnabled() bool {
	return s.opts.Cfg.RuntimeHealthInterval > 0 && s.opts.RuntimeHealth != nil &&
		s.opts.HealthProbeFactory != nil && s.observerDocker() != nil
}

func (s *Server) observerDocker() observerDocker {
	if s.observer.docker != nil {
		return s.observer.docker
	}
	if s.opts.Runner == nil {
		return nil
	}
	return s.opts.Runner
}

func (s *Server) observerNow() time.Time {
	if s.observer.now != nil {
		return s.observer.now()
	}
	return time.Now().UTC()
}

// startRuntimeObserver starts the loop when it is configured. It runs under
// goOp like every other goroutine of the server, and ends when ctx ends.
func (s *Server) startRuntimeObserver(ctx context.Context) {
	if !s.runtimeObserverEnabled() {
		return
	}
	every := s.opts.Cfg.RuntimeHealthInterval
	s.goOp(func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.observeOnce(ctx)
			}
		}
	})
}

// observedIdentity is what has to stay the same across the probe.
type observedIdentity struct {
	present, running bool
	containerID      string
	imageID          string
	repoDigests      []string
	pinnedTagID      string
	// tagUnread: the fixed tag could not be inspected. Unknown is not a value
	// that two reads can agree on, so such a read never counts as unchanged.
	tagUnread bool
}

func (a observedIdentity) same(b observedIdentity) bool {
	return !a.tagUnread && !b.tagUnread && a.present == b.present && a.running == b.running &&
		a.containerID == b.containerID && a.imageID == b.imageID && a.pinnedTagID == b.pinnedTagID
}

// readIdentity reads the proxy container and the fixed tag. An error means
// Docker could not be read: nothing is known about the container.
func (s *Server) readIdentity(ctx context.Context) (observedIdentity, error) {
	d := s.observerDocker()
	pc, err := d.ReadProxyContainer(ctx)
	if err != nil {
		return observedIdentity{}, err
	}
	id := observedIdentity{present: pc.Present, running: pc.Running, containerID: pc.ContainerID, imageID: pc.ImageID, repoDigests: pc.RepoDigests}
	tag, terr := d.PinnedTagImageID(ctx)
	id.pinnedTagID, id.tagUnread = tag, terr != nil || tag == ""
	return id, nil
}

// observeBusy reports why the observer must not sample now, or "".
func (s *Server) observeBusy() string {
	if s.opts.Ops.Holder() != nil {
		return obsSkippedLock
	}
	if s.settleRemaining() > 0 {
		return obsSkippedSettle
	}
	return ""
}

// observeOnce takes one sample and returns what it did with it.
func (s *Server) observeOnce(ctx context.Context) string {
	if why := s.observeBusy(); why != "" {
		return why
	}
	before, err := s.readIdentity(ctx)
	switch {
	case err != nil:
		return s.keep(runtimehealth.Sample{State: runtimehealth.StateUnknown, Reason: obsReasonDockerUnreadable})
	case !before.present:
		return s.keep(runtimehealth.Sample{State: runtimehealth.StateUnhealthy, Reason: obsReasonNoContainer, PinnedTagImageID: before.pinnedTagID})
	case !before.running:
		return s.keep(before.sample(runtimehealth.StateUnhealthy, obsReasonNotRunning, ""))
	case before.tagUnread:
		// No gate without knowing what the next recreate would start: the
		// sample is unknown and last_good is left as it is.
		return s.keep(before.sample(runtimehealth.StateUnknown, obsReasonTagUnreadable, ""))
	}
	hr, perr := s.runProbe(ctx)
	if s.observer.afterProbe != nil {
		s.observer.afterProbe()
	}
	after, err := s.readIdentity(ctx)
	if err != nil || !after.same(before) {
		return obsDiscarded
	}
	if s.observeBusy() != "" {
		return obsDiscardedLock
	}
	switch {
	case perr != nil || hr == nil:
		return s.keep(before.sample(runtimehealth.StateUnknown, obsReasonProbeError, ""))
	case !hr.ReadyOK:
		return s.keep(before.sample(runtimehealth.StateUnhealthy, obsReasonNotReady, hr.ReadyDetail))
	}
	return s.keepGated(before, hr)
}

// runProbe runs the production probe, bounded by its budget plus a margin.
func (s *Server) runProbe(ctx context.Context) (*health.Result, error) {
	p := s.opts.HealthProbeFactory()
	budget := p.Budget
	if budget <= 0 {
		budget = 30 * time.Second
	}
	pctx, cancel := context.WithTimeout(ctx, budget+10*time.Second)
	defer cancel()
	return p.Run(pctx)
}

func (id observedIdentity) sample(state, reason, detail string) runtimehealth.Sample {
	return runtimehealth.Sample{State: state, Reason: reason, ContainerID: id.containerID, ImageID: id.imageID, PinnedTagImageID: id.pinnedTagID, Detail: detail}
}

// keepGated records a passed gate, and the last-known-good image when the
// image has a validated, allow-listed reference.
func (s *Server) keepGated(id observedIdentity, hr *health.Result) string {
	now := s.observerNow()
	ref, digest := s.validatedRef(id.repoDigests)
	reason := obsReasonGateOK
	wroteGood := false
	if ref == "" {
		reason = obsReasonGateOKNoRef
	} else {
		lg := runtimehealth.LastGood{ImageID: id.imageID, Ref: ref, Digest: digest, ContainerID: id.containerID,
			PassedAt: now, Gate: runtimehealth.GateRuntimeObserver, GateDetail: hr.ReadyDetail}
		if err := s.opts.RuntimeHealth.WriteLastGood(lg); err != nil {
			log.Printf("culvert-maint: WARN: the last-known-good image could not be recorded: %q", err.Error())
			reason = obsReasonGateOKGoodUnwritable
		} else {
			wroteGood = true
			// The two-entry history slice 6 restores from (ADR-0062).
			ge := runtimehealth.GatedEntry{ImageID: id.imageID, Ref: ref, Digest: digest, GatedAt: now}
			if err := s.opts.RuntimeHealth.NoteGated(ge); err != nil {
				log.Printf("culvert-maint: WARN: the gated-image history could not be updated: %q", err.Error())
			}
		}
	}
	smp := id.sample(runtimehealth.StateGated, reason, hr.ReadyDetail)
	smp.ObservedAt = now
	if out := s.keep(smp); out != obsRecorded {
		return out
	}
	if wroteGood {
		return obsRecordedAndGood
	}
	return obsRecorded
}

// validatedRef returns the image's first reference that passes the same gate
// as any pinned target (repo-bound exact digest, then the image allowlist),
// and its digest. A local-only reference is never one.
func (s *Server) validatedRef(refs []string) (ref, digest string) {
	for _, r := range refs {
		if runner.ValidatePinnedDigestRef(r, s.opts.Cfg.ProxyRepo) != nil {
			continue
		}
		if s.opts.Cfg.ImageAllowlist == nil || !s.opts.Cfg.ImageAllowlist.MatchString(r) {
			continue
		}
		if d := digestRE.FindString(r); d != "" {
			return r, d
		}
	}
	return "", ""
}

// keep writes a sample as the latest observation.
func (s *Server) keep(smp runtimehealth.Sample) string {
	if smp.ObservedAt.IsZero() {
		smp.ObservedAt = s.observerNow()
	}
	if err := s.opts.RuntimeHealth.WriteLatest(smp); err != nil {
		log.Printf("culvert-maint: WARN: the runtime health observation could not be recorded: %q", err.Error())
		return obsWriteFailed
	}
	s.logTransition(smp)
	return obsRecorded
}

// logTransition logs a sample whose state or reason differs from the last one
// logged, so a steady state is logged once.
func (s *Server) logTransition(smp runtimehealth.Sample) {
	key := smp.State + "/" + smp.Reason
	s.observer.mu.Lock()
	changed := key != s.observer.lastLogged
	s.observer.lastLogged = key
	s.observer.mu.Unlock()
	if changed {
		log.Printf("culvert-maint: runtime health: %s (image %q)", key, smp.ImageID)
	}
}
