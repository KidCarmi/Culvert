package shutdown

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRegistry_IndependentOwners(t *testing.T) {
	t.Parallel()
	for i := range 4 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			var messages []string
			options := Options{Grace: time.Duration(i+1) * time.Millisecond, MinSlice: time.Duration(i+2) * time.Millisecond,
				Logf: func(format string, args ...any) { messages = append(messages, fmt.Sprintf(format, args...)) }}
			r := New(options)
			options.Grace = time.Hour
			options.MinSlice = time.Hour
			options.Logf = nil
			grace, minimum := r.timing()
			if grace != time.Duration(i+1)*time.Millisecond || minimum != time.Duration(i+2)*time.Millisecond {
				t.Fatal("constructor retained mutable caller options")
			}
			release, finished := make(chan struct{}), make(chan struct{})
			t.Cleanup(func() {
				close(release)
				select {
				case <-finished:
				case <-time.After(time.Second):
					t.Error("abandoned hook did not finish after release")
				}
			})
			name := fmt.Sprintf("owner-%d", i)
			r.Register(name, 1, func(context.Context) error { defer close(finished); <-release; return nil })
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
			defer cancel()
			if err := r.RunAll(ctx); !errors.Is(err, ErrAbandoned) {
				t.Fatalf("expected abandonment, got %v", err)
			}
			if len(messages) != 1 || !strings.Contains(messages[0], name) {
				t.Fatalf("diagnostics crossed owner boundary: %v", messages)
			}
		})
	}
}

func TestRegistry_PartitionPreservesOwnership(t *testing.T) {
	r := New(Options{Grace: 40 * time.Millisecond, MinSlice: 10 * time.Millisecond})
	var ran []string
	for _, h := range []HookInfo{{"late", 20}, {"early", 5}, {"tie", 5}} {
		r.Register(h.Name, h.Order, func(context.Context) error { ran = append(ran, h.Name); return nil })
	}
	before, after := r.PartitionAt(5)
	for _, child := range []*Registry{before, after} {
		grace, minimum := child.timing()
		if grace != 40*time.Millisecond || minimum != 10*time.Millisecond {
			t.Fatal("partition lost constructor timing")
		}
	}
	if err := r.RunAll(context.Background()); err != nil || len(ran) != 0 {
		t.Fatal("partition did not consume source")
	}
	for _, child := range []*Registry{before, after} {
		if err := child.RunAll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(ran, []string{"early", "tie", "late"}) {
		t.Fatalf("partition changed execution: %v", ran)
	}
	defer func() {
		if recover() == nil {
			t.Error("partitioned source accepted a late registration")
		}
	}()
	r.Register("too-late", 30, func(context.Context) error { return nil })
}

func TestRegistry_PartitionPreservesDiagnosticSink(t *testing.T) {
	var messages []string
	r := New(Options{Logf: func(format string, args ...any) { messages = append(messages, fmt.Sprintf(format, args...)) }})
	release := make(chan struct{})
	finished := make(chan struct{}, 2)
	t.Cleanup(func() {
		close(release)
		for range 2 {
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Error("hook did not finish")
			}
		}
	})
	for _, h := range []HookInfo{{"before", 1}, {"after", 2}} {
		r.Register(h.Name, h.Order, func(context.Context) error { defer func() { finished <- struct{}{} }(); <-release; return nil })
	}
	before, after := r.PartitionAt(1)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer cancel()
	for _, child := range []*Registry{before, after} {
		if err := child.RunAll(ctx); !errors.Is(err, ErrAbandoned) {
			t.Fatal(err)
		}
	}
	if len(messages) != 2 || !strings.Contains(messages[0], `"before"`) || !strings.Contains(messages[1], `"after"`) {
		t.Fatalf("partition lost diagnostic sink: %v", messages)
	}
}

func TestRegistry_InventoryIsDetached(t *testing.T) {
	var r Registry
	r.Register("original", 1, func(context.Context) error { return nil })
	first := r.Hooks()
	first[0] = HookInfo{Name: "mutated", Order: -1}
	if got := r.Hooks(); len(got) != 1 || got[0].Name != "original" || got[0].Order != 1 {
		t.Fatalf("inventory aliases registry: %v", got)
	}
}

func TestRegistry_WatchdogCancelsAndReleasesHook(t *testing.T) {
	r := New(Options{Grace: 50 * time.Millisecond})
	canceled, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		close(release)
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("hook did not exit after release")
		}
	})
	r.Register("unwind", 1, func(ctx context.Context) error {
		defer close(finished)
		<-ctx.Done()
		close(canceled)
		<-release
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := r.RunAll(ctx); !errors.Is(err, ErrAbandoned) {
		t.Fatalf("got %v", err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("abandoned hook context was not canceled")
	}
}
