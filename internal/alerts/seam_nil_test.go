package alerts

// The producer-facing seam must never PANIC a producer.
//
// SetSink/SetSubscriberProbe stored &fn unconditionally, so passing a nil
// function made the atomic pointer non-nil while the function behind it was
// nil — and the guarded call `if p := probe.Load(); p != nil { return (*p)(event) }`
// then called a nil func and panicked. That lands on the REQUEST goroutine:
// HasSubscriber is called synchronously from the scan path's producers
// (internal/secscan's clamScanError and remoteScanFail, internal/yara's
// fireYARADegraded), so the crash would be taken by an in-line security
// gateway while it forwards traffic.
//
// The contract these gates pin is the one the package doc already states:
// Fire "is a no-op when no sink is installed ... so producers never need a nil
// check", and HasSubscriber "fails toward DELIVERY" when nothing is wired, so
// a missing probe can never silence a real alert. A nil install is "not
// wired", never a crash.

import (
	"sync"
	"testing"
)

// restoreSeam puts the process-global seam back the way the rest of the test
// binary expects it.
func restoreSeam(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		SetSink(nil)
		SetSubscriberProbe(nil)
	})
}

func TestSeam_NilSinkIsUninstalledNotAPanic(t *testing.T) {
	restoreSeam(t)
	SetSink(func(string, Payload) { t.Fatal("the uninstalled sink must not be called") })
	SetSink(nil)
	Fire("scan_clam_error", Payload{Detail: "connect_failed"}) // must not panic
}

func TestSeam_NilProbeFailsTowardDelivery(t *testing.T) {
	restoreSeam(t)
	SetSubscriberProbe(func(string) bool { return false })
	if HasSubscriber("yara_degraded") {
		t.Fatal("an installed probe must be consulted")
	}
	SetSubscriberProbe(nil)
	if !HasSubscriber("yara_degraded") {
		t.Fatal("a nil probe must read as NOT WIRED and answer true: a missing wire-up " +
			"may never silence a real alert")
	}
}

// TestSeam_InstalledSinkAndProbeStillWork is the CONTROL: the nil handling must
// not be bought by making a real install a no-op.
func TestSeam_InstalledSinkAndProbeStillWork(t *testing.T) {
	restoreSeam(t)
	var mu sync.Mutex
	var got []string
	SetSink(func(event string, p Payload) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, event+":"+p.Detail)
	})
	SetSubscriberProbe(func(event string) bool { return event == "wanted" })

	if !HasSubscriber("wanted") || HasSubscriber("unwanted") {
		t.Fatal("the installed probe must decide per event")
	}
	Fire("wanted", Payload{Detail: "d"})
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0] != "wanted:d" {
		t.Fatalf("installed sink did not receive the alert: %v", got)
	}
}

// TestSeam_ConcurrentInstallAndFire runs the replace path against live
// producers: a publish-once seam that is nevertheless replaced (tests, a later
// startup slice) must never hand a producer a torn or nil callable.
func TestSeam_ConcurrentInstallAndFire(t *testing.T) {
	restoreSeam(t)
	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			SetSink(func(string, Payload) {})
			SetSink(nil)
			SetSubscriberProbe(func(string) bool { return true })
			SetSubscriberProbe(nil)
		}
	}()

	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 2000 {
				if HasSubscriber("scan_clam_error") {
					Fire("scan_clam_error", Payload{Detail: "connect_failed"})
				}
			}
		}()
	}
	close(stop)
	wg.Wait()
}
