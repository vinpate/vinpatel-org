package resolve

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	dmarcJSON = `{"Status":0,"Answer":[{"name":"_dmarc.vinpatel.org","type":16,"TTL":300,"data":"\"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s\""}]}`
	cymruJSON = `{"Status":0,"Answer":[{"name":"AS13335.asn.cymru.com","type":16,"TTL":3600,"data":"\"13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US\""}]}`
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// upstream is a fake DoH JSON server. Names missing from answers get NXDOMAIN.
type upstream struct {
	t       *testing.T
	answers map[string]string
	status  int
	delay   time.Duration
	calls   atomic.Int64
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.calls.Add(1)
	if got := r.Header.Get("Accept"); got != "application/dns-json" {
		u.t.Errorf("Accept = %q, want application/dns-json", got)
	}
	if got := r.URL.Query().Get("type"); got != "TXT" {
		u.t.Errorf("type = %q, want TXT", got)
	}
	if u.delay > 0 {
		select {
		case <-time.After(u.delay):
		case <-r.Context().Done():
			return
		}
	}
	if u.status != 0 {
		w.WriteHeader(u.status)
		return
	}
	body, ok := u.answers[r.URL.Query().Get("name")]
	if !ok {
		body = `{"Status":3}`
	}
	w.Header().Set("Content-Type", "application/dns-json")
	fmt.Fprint(w, body)
}

func newResolver(t *testing.T, u *upstream, clk *clock, timeout time.Duration, maxEntries int) *Resolver {
	t.Helper()
	u.t = t
	srv := httptest.NewServer(u)
	t.Cleanup(srv.Close)
	return New(Options{Endpoint: srv.URL + "/dns-query", Client: srv.Client(), Now: clk.Now, Timeout: timeout, MaxEntries: maxEntries})
}

func epoch() *clock { return &clock{t: time.Unix(1_790_000_000, 0)} }

func TestDMARCPolicy(t *testing.T) {
	u := &upstream{answers: map[string]string{"_dmarc.vinpatel.org": dmarcJSON}}
	r := newResolver(t, u, epoch(), time.Second, 0)
	if got := r.DMARCPolicy(t.Context(), "vinpatel.org"); got != "reject" {
		t.Errorf("DMARCPolicy = %q, want reject", got)
	}
}

func TestASOrg(t *testing.T) {
	u := &upstream{answers: map[string]string{"as13335.asn.cymru.com": cymruJSON}}
	r := newResolver(t, u, epoch(), time.Second, 0)
	if got := r.ASOrg(t.Context(), 13335); got != "CLOUDFLARENET - Cloudflare, Inc., US" {
		t.Errorf("ASOrg = %q", got)
	}
	if got := r.ASOrg(t.Context(), 0); got != "" {
		t.Errorf("ASOrg(0) = %q, want empty", got)
	}
	if n := u.calls.Load(); n != 1 {
		t.Errorf("upstream calls = %d, want 1 (ASN 0 must not be looked up)", n)
	}
}

func TestParsers(t *testing.T) {
	dmarc := []struct {
		records []string
		want    string
	}{
		{[]string{"v=DMARC1; p=quarantine"}, "quarantine"},
		{[]string{"v=spf1 -all", "v=DMARC1;p=NONE"}, "none"},
		{[]string{"v=DMARC1; sp=reject"}, ""},
		{[]string{"p=reject"}, ""},
		{[]string{"v=DMARC1; p=bogus"}, ""},
	}
	for _, tc := range dmarc {
		if got := dmarcPolicy(tc.records); got != tc.want {
			t.Errorf("dmarcPolicy(%q) = %q, want %q", tc.records, got, tc.want)
		}
	}
	orgs := []struct {
		records []string
		want    string
	}{
		{[]string{"13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"}, "CLOUDFLARENET - Cloudflare, Inc., US"},
		{[]string{"garbage"}, ""},
		{[]string{"1 | US | arin | 2000-01-01 |   "}, ""},
	}
	for _, tc := range orgs {
		if got := asOrg(tc.records); got != tc.want {
			t.Errorf("asOrg(%q) = %q, want %q", tc.records, got, tc.want)
		}
	}
	txt := []struct{ data, want string }{
		{`"v=DMARC1; p=quar" "antine"`, "v=DMARC1; p=quarantine"},
		{`"say \"hi\""`, `say "hi"`},
		{`plain`, `plain`},
	}
	for _, tc := range txt {
		if got := unquoteTXT(tc.data); got != tc.want {
			t.Errorf("unquoteTXT(%q) = %q, want %q", tc.data, got, tc.want)
		}
	}
}

func TestCacheHonorsTTL(t *testing.T) {
	clk := epoch()
	u := &upstream{answers: map[string]string{"_dmarc.vinpatel.org": dmarcJSON}}
	r := newResolver(t, u, clk, time.Second, 0)
	ctx := t.Context()

	r.DMARCPolicy(ctx, "vinpatel.org")
	clk.Advance(DMARCTTL - time.Second)
	if got := r.DMARCPolicy(ctx, "vinpatel.org"); got != "reject" {
		t.Fatalf("cached DMARCPolicy = %q", got)
	}
	if n := u.calls.Load(); n != 1 {
		t.Fatalf("upstream calls within TTL = %d, want 1", n)
	}
	clk.Advance(2 * time.Second)
	r.DMARCPolicy(ctx, "vinpatel.org")
	if n := u.calls.Load(); n != 2 {
		t.Fatalf("upstream calls after TTL = %d, want 2", n)
	}
}

func TestFailureIsUnknownAndNegativelyCached(t *testing.T) {
	cases := map[string]*upstream{
		"http 500": {status: http.StatusInternalServerError},
		"nxdomain": {},
		"bad json": {answers: map[string]string{"_dmarc.vinpatel.org": "{"}},
	}
	for name, u := range cases {
		t.Run(name, func(t *testing.T) {
			clk := epoch()
			r := newResolver(t, u, clk, time.Second, 0)
			ctx := t.Context()
			if got := r.DMARCPolicy(ctx, "vinpatel.org"); got != "" {
				t.Fatalf("DMARCPolicy = %q, want empty", got)
			}
			clk.Advance(NegativeTTL - time.Second)
			r.DMARCPolicy(ctx, "vinpatel.org")
			if n := u.calls.Load(); n != 1 {
				t.Fatalf("upstream calls within negative TTL = %d, want 1", n)
			}
			clk.Advance(2 * time.Second)
			r.DMARCPolicy(ctx, "vinpatel.org")
			if n := u.calls.Load(); n != 2 {
				t.Fatalf("upstream calls after negative TTL = %d, want 2", n)
			}
		})
	}
}

func TestTimeoutIsUnknown(t *testing.T) {
	u := &upstream{answers: map[string]string{"_dmarc.vinpatel.org": dmarcJSON}, delay: time.Second}
	r := newResolver(t, u, epoch(), 20*time.Millisecond, 0)
	start := time.Now()
	if got := r.DMARCPolicy(t.Context(), "vinpatel.org"); got != "" {
		t.Errorf("DMARCPolicy = %q, want empty after timeout", got)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("lookup took %v, want it bounded by the 20ms timeout", elapsed)
	}
}

func TestConcurrentMissesShareOneQuery(t *testing.T) {
	u := &upstream{answers: map[string]string{"_dmarc.vinpatel.org": dmarcJSON}, delay: 50 * time.Millisecond}
	r := newResolver(t, u, epoch(), time.Second, 0)
	results := make([]string, 20)
	var wg sync.WaitGroup
	for i := range results {
		wg.Go(func() { results[i] = r.DMARCPolicy(t.Context(), "vinpatel.org") })
	}
	wg.Wait()
	for i, got := range results {
		if got != "reject" {
			t.Errorf("caller %d got %q, want reject", i, got)
		}
	}
	if n := u.calls.Load(); n != 1 {
		t.Errorf("upstream calls = %d, want 1", n)
	}
}

func TestAbandonedCallerStillFillsCache(t *testing.T) {
	u := &upstream{answers: map[string]string{"_dmarc.vinpatel.org": dmarcJSON}, delay: 20 * time.Millisecond}
	r := newResolver(t, u, epoch(), time.Second, 0)
	gone, cancel := context.WithCancel(t.Context())
	cancel()
	if got := r.DMARCPolicy(gone, "vinpatel.org"); got != "" {
		t.Fatalf("cancelled caller got %q, want empty", got)
	}
	if got := r.DMARCPolicy(t.Context(), "vinpatel.org"); got != "reject" {
		t.Fatalf("next caller got %q, want reject", got)
	}
	if n := u.calls.Load(); n != 1 {
		t.Errorf("upstream calls = %d, want 1", n)
	}
}

func TestCacheIsBounded(t *testing.T) {
	u := &upstream{}
	r := newResolver(t, u, epoch(), time.Second, 2)
	for _, name := range []string{"a.example", "b.example", "c.example"} {
		r.TXT(t.Context(), name, time.Hour)
	}
	r.mu.Lock()
	n := len(r.cache)
	r.mu.Unlock()
	if n > 2 {
		t.Errorf("cache holds %d entries, cap is 2", n)
	}
}

func TestEmptyEndpointDisablesLookups(t *testing.T) {
	r := New(Options{})
	if got := r.DMARCPolicy(t.Context(), "vinpatel.org"); got != "" {
		t.Errorf("DMARCPolicy = %q, want empty", got)
	}
	if got := r.ASOrg(t.Context(), 13335); got != "" {
		t.Errorf("ASOrg = %q, want empty", got)
	}
}
