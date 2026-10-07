// Package resolve looks up TXT records over DNS-over-HTTPS behind a small,
// bounded cache. Lookups never return errors: anything that goes wrong reads
// as unknown and is remembered briefly, so a failing upstream cannot slow
// every request.
package resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	MailTTL     = time.Hour
	ASNTTL      = 24 * time.Hour
	NegativeTTL = 5 * time.Minute

	defaultTimeout    = 500 * time.Millisecond
	defaultMaxEntries = 4096
	maxResponseBytes  = 64 << 10
	typeTXT           = 16
)

type Options struct {
	// Endpoint is a DoH JSON URL such as https://cloudflare-dns.com/dns-query.
	// Empty disables lookups, the policy fetch included.
	Endpoint   string
	Client     *http.Client
	Now        func() time.Time
	Timeout    time.Duration
	MaxEntries int
	// PolicyURL returns where a domain's MTA-STS policy is fetched from.
	// Nil means https://mta-sts.<domain>/.well-known/mta-sts.txt.
	PolicyURL func(domain string) string
}

type Resolver struct {
	endpoint   string
	client     *http.Client
	policy     *http.Client
	policyURL  func(string) string
	now        func() time.Time
	timeout    time.Duration
	maxEntries int

	mu       sync.Mutex
	cache    map[string]entry
	inflight map[string]*call
}

// entry is one cached answer. For DNS, records are the TXT strings and ad
// is the resolver's authenticated-data flag; for the policy fetch, records
// holds the body as its only element.
type entry struct {
	records []string
	ad      bool
	ok      bool
	fetched time.Time
	expires time.Time
}

type call struct {
	done  chan struct{}
	entry entry
}

// fetchFunc fills one cache entry.
type fetchFunc func(ctx context.Context) (records []string, ad bool, err error)

func New(o Options) *Resolver {
	r := &Resolver{
		endpoint:   o.Endpoint,
		client:     o.Client,
		policyURL:  o.PolicyURL,
		now:        o.Now,
		timeout:    o.Timeout,
		maxEntries: o.MaxEntries,
		cache:      make(map[string]entry),
		inflight:   make(map[string]*call),
	}
	if r.client == nil {
		r.client = &http.Client{}
	}
	// RFC 8461 §3.3: a policy fetch must not follow redirects.
	r.policy = &http.Client{
		Transport:     r.client.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if r.policyURL == nil {
		r.policyURL = func(domain string) string { return "https://mta-sts." + domain + "/.well-known/mta-sts.txt" }
	}
	if r.now == nil {
		r.now = time.Now
	}
	if r.timeout <= 0 {
		r.timeout = defaultTimeout
	}
	if r.maxEntries <= 0 {
		r.maxEntries = defaultMaxEntries
	}
	return r
}

// TXT returns the TXT records for name and whether the lookup succeeded.
func (r *Resolver) TXT(ctx context.Context, name string, ttl time.Duration) ([]string, bool) {
	e := r.txt(ctx, name, ttl)
	return e.records, e.ok
}

func (r *Resolver) txt(ctx context.Context, name string, ttl time.Duration) entry {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return r.get(ctx, "txt "+name, ttl, func(ctx context.Context) ([]string, bool, error) {
		return r.query(ctx, name)
	})
}

// ASOrg returns the organization Team Cymru lists for asn, or "" if unknown.
func (r *Resolver) ASOrg(ctx context.Context, asn uint32) string {
	if asn == 0 {
		return ""
	}
	records, ok := r.TXT(ctx, fmt.Sprintf("AS%d.asn.cymru.com", asn), ASNTTL)
	if !ok {
		return ""
	}
	return asOrg(records)
}

// get serves key from the cache or from one shared call to fetch.
// Concurrent misses for one key share that call, and it runs to completion
// even if the caller that started it gives up.
func (r *Resolver) get(ctx context.Context, key string, ttl time.Duration, fetch fetchFunc) entry {
	if r.endpoint == "" {
		return entry{}
	}

	r.mu.Lock()
	if e, hit := r.cache[key]; hit && r.now().Before(e.expires) {
		r.mu.Unlock()
		return e
	}
	c, running := r.inflight[key]
	if !running {
		c = &call{done: make(chan struct{})}
		r.inflight[key] = c
		go r.fill(key, ttl, fetch, c)
	}
	r.mu.Unlock()

	select {
	case <-c.done:
		return c.entry
	case <-ctx.Done():
		return entry{}
	}
}

func (r *Resolver) fill(key string, ttl time.Duration, fetch fetchFunc, c *call) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	records, ad, err := fetch(ctx)
	if err != nil {
		ttl = NegativeTTL
	}
	now := r.now()
	c.entry = entry{records: records, ad: ad, ok: err == nil, fetched: now, expires: now.Add(ttl)}

	r.mu.Lock()
	r.store(key, c.entry)
	delete(r.inflight, key)
	r.mu.Unlock()
	close(c.done)
}

// store must be called with r.mu held. When the cache is full it drops
// expired entries first, then arbitrary ones, until there is room.
func (r *Resolver) store(key string, e entry) {
	if _, exists := r.cache[key]; !exists && len(r.cache) >= r.maxEntries {
		now := r.now()
		for k, v := range r.cache {
			if !now.Before(v.expires) {
				delete(r.cache, k)
			}
		}
		for k := range r.cache {
			if len(r.cache) < r.maxEntries {
				break
			}
			delete(r.cache, k)
		}
	}
	r.cache[key] = e
}

// query asks the DoH endpoint for name's TXT records and whether the
// resolver validated them with DNSSEC.
func (r *Resolver) query(ctx context.Context, name string) ([]string, bool, error) {
	u, err := url.Parse(r.endpoint)
	if err != nil {
		return nil, false, err
	}
	q := u.Query()
	q.Set("name", name)
	q.Set("type", "TXT")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("%s: upstream status %d", name, resp.StatusCode)
	}

	var body struct {
		Status int
		AD     bool
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&body); err != nil {
		return nil, false, fmt.Errorf("%s: %w", name, err)
	}
	if body.Status != 0 {
		return nil, false, fmt.Errorf("%s: rcode %d", name, body.Status)
	}
	var records []string
	for _, a := range body.Answer {
		if a.Type == typeTXT {
			records = append(records, unquoteTXT(a.Data))
		}
	}
	return records, body.AD, nil
}

// unquoteTXT joins the quoted character-strings of a TXT answer, so a record
// split into 255-byte chunks reads as one string.
func unquoteTXT(data string) string {
	if !strings.HasPrefix(data, `"`) {
		return data
	}
	var b strings.Builder
	inside, escaped := false, false
	for _, r := range data {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case inside && r == '\\':
			escaped = true
		case r == '"':
			inside = !inside
		case inside:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// asOrg reads the fifth field of a Team Cymru origin record:
// "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US".
func asOrg(records []string) string {
	for _, rec := range records {
		fields := strings.SplitN(rec, "|", 5)
		if len(fields) == 5 {
			if org := strings.TrimSpace(fields[4]); org != "" {
				return org
			}
		}
	}
	return ""
}
