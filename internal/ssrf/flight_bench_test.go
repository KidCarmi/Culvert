package ssrf

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkPrivateHostBudget_ColdHerd measures the miss path under a herd: 64
// concurrent tunnel guards for one host whose verdict is not cached (a cold
// host, or a hot host whose 30 s entry just expired), against a resolver that
// answers in 2 ms. lookups/op is how many resolutions one herd costs.
func BenchmarkPrivateHostBudget_ColdHerd(b *testing.B) {
	const herd = 64
	var lookups atomic.Int64
	restore := SetLookupHostForTest(func(ctx context.Context, _ string) ([]string, error) {
		lookups.Add(1)
		select {
		case <-time.After(2 * time.Millisecond):
			return []string{"93.184.216.34"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	defer restore()
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		host := fmt.Sprintf("herd-%d.example.test:443", i)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for j := 0; j < herd; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if err := PrivateHostBudget(ctx, host, 10*time.Second); err != nil {
					b.Error(err)
				}
			}()
		}
		close(start)
		wg.Wait()
	}
	b.ReportMetric(float64(lookups.Load())/float64(b.N), "lookups/op")
}
