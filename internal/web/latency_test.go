package web

import (
	"sync"
	"testing"
	"time"
)

func within(t *testing.T, name string, got, sample time.Duration) {
	t.Helper()
	if got < sample || got > sample+sample/10 {
		t.Errorf("%s = %v, want within 10%% above %v", name, got, sample)
	}
}

func TestHistogramQuantiles(t *testing.T) {
	var h histogram
	for range 98 {
		h.observe(200 * time.Microsecond)
	}
	h.observe(50 * time.Millisecond)
	h.observe(50 * time.Millisecond)
	s := h.snapshot()
	if s.total != 100 {
		t.Fatalf("total = %d", s.total)
	}
	within(t, "p50", s.quantile(0.5), 200*time.Microsecond)
	within(t, "p99", s.quantile(0.99), 50*time.Millisecond)
	within(t, "p98", s.quantile(0.98), 200*time.Microsecond)
}

func TestHistogramEdges(t *testing.T) {
	var h histogram
	if s := h.snapshot(); s.quantile(0.5) != 0 || s.total != 0 {
		t.Fatal("empty histogram should report zero")
	}
	h.observe(time.Nanosecond)
	if got := h.snapshot().quantile(0.5); got != minLatency {
		t.Errorf("below range = %v, want %v", got, minLatency)
	}
	var slow histogram
	slow.observe(time.Minute)
	if got := slow.snapshot().quantile(0.5); got != maxLatency {
		t.Errorf("above range = %v, want %v", got, maxLatency)
	}
}

func TestHistogramBucketsAreMonotonic(t *testing.T) {
	for i := 1; i < buckets; i++ {
		if bounds[i] <= bounds[i-1] {
			t.Fatalf("bounds[%d] = %v <= bounds[%d] = %v", i, bounds[i], i-1, bounds[i-1])
		}
	}
	if bounds[0] != minLatency || bounds[buckets-1] != maxLatency {
		t.Errorf("bounds span %v..%v", bounds[0], bounds[buckets-1])
	}
}

func TestHistogramIsSafeConcurrently(t *testing.T) {
	var h histogram
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for range 1000 {
				h.observe(time.Duration(i+1) * time.Millisecond)
			}
		})
	}
	wg.Wait()
	s := h.snapshot()
	if s.total != 8000 {
		t.Errorf("total = %d, want 8000", s.total)
	}
	within(t, "p50", s.quantile(0.5), 4*time.Millisecond)
}
