package web

import (
	"math"
	"sort"
	"sync/atomic"
	"time"
)

// A histogram counts request durations in fixed, log-spaced buckets from
// minLatency to maxLatency, with one more for anything slower. Recording
// is a binary search and one atomic add; nothing is allocated per request
// and no lock is taken. Quantiles report a bucket's upper bound.
const (
	minLatency = 50 * time.Microsecond
	maxLatency = time.Second
	buckets    = 128
)

// bounds[i] is the upper bound of bucket i; the spacing is geometric.
var bounds = func() [buckets]time.Duration {
	var b [buckets]time.Duration
	ratio := math.Pow(float64(maxLatency)/float64(minLatency), 1/float64(buckets-1))
	for i := range b {
		b[i] = time.Duration(math.Round(float64(minLatency) * math.Pow(ratio, float64(i))))
	}
	b[0], b[buckets-1] = minLatency, maxLatency
	return b
}()

type histogram struct {
	counts [buckets + 1]atomic.Uint64
}

func (h *histogram) observe(d time.Duration) {
	i := sort.Search(buckets, func(i int) bool { return d <= bounds[i] })
	h.counts[i].Add(1)
}

// A snapshot is one read of the counts, so the total and every quantile
// taken from it describe the same requests.
type snapshot struct {
	counts [buckets + 1]uint64
	total  uint64
}

func (h *histogram) snapshot() snapshot {
	var s snapshot
	for i := range h.counts {
		s.counts[i] = h.counts[i].Load()
		s.total += s.counts[i]
	}
	return s
}

// quantile returns the upper bound of the bucket holding the q-th sample,
// 0 when nothing has been recorded, maxLatency for samples past the range.
func (s snapshot) quantile(q float64) time.Duration {
	if s.total == 0 {
		return 0
	}
	rank := max(uint64(math.Ceil(q*float64(s.total))), 1)
	var seen uint64
	for i, n := range s.counts {
		seen += n
		if seen >= rank {
			return bounds[min(i, buckets-1)]
		}
	}
	return maxLatency
}
