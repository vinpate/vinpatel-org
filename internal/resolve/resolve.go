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
	DMARCTTL    = time.Hour
	ASNTTL      = 24 * time.Hour
	NegativeTTL = 5 * time.Minute

	defaultTimeout    = 500 * time.Millisecond
	defaultMaxEntries = 4096
	maxResponseBytes  = 64 << 10
	typeTXT           = 16
)

type Options struct {
	// Endpoint is a DoH JSON URL such as https://cloudflare-dns.com/dns-query.
	// Empty disables lookups.
	Endpoint   string
	Client     *http.Client
	Now        func() time.Time
	Timeout    time.Duration
	MaxEntries int
}

type Resolver struct {
	endpoint   string
	client     *http.Client
	now        func() time.Time
	timeout    time.Duration
	maxEntries int

	mu       sync.Mutex
	cache    map[string]entry
	inflight map[string]*call
}

type entry struct {
	records []string
	ok      bool
	fetched time.Time
	expires time.Time
}

type call struct {
	done  chan struct{}
	entry entry
}

func New(o Options) *Resolver {
	r := &Resolver{
		endpoint:   o.Endpoint,
		client:     o.Client,
		now:        o.Now,
		timeout:    o.Timeout,
		maxEntries: o.MaxEntries,
		cache:      make(map[string]entry),
		inflight:   make(map[string]*call),
	}
	if r.client == nil {
		r.client = &http.Client{}
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

// txt serves name from the cache or from one shared upstream query.
// Concurrent misses for one name share that query, and it runs to
// completion even if the caller that started it gives up.
func (r *Resolver) txt(ctx context.Context, name string, ttl time.Duration) entry {
	if r.endpoint == "" {
		return entry{}
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")

	r.mu.Lock()
	if e, hit := r.cache[name]; hit && r.now().Before(e.expires) {
		r.mu.Unlock()
		return e
	}
	c, running := r.inflight[name]
	if !running {
		c = &call{done: make(chan struct{})}
		r.inflight[name] = c
		go r.fill(name, ttl, c)
	}
	r.mu.Unlock()

	select {
	case <-c.done:
		return c.entry
	case <-ctx.Done():
		return entry{}
	}
}

// DMARCPolicy returns the p= tag of domain's DMARC record and how long ago
// it was fetched. Both are zero when the record is unknown.
func (r *Resolver) DMARCPolicy(ctx context.Context, domain string) (string, time.Duration) {
	e := r.txt(ctx, "_dmarc."+domain, DMARCTTL)
	if !e.ok {
		return "", 0
	}
	return dmarcPolicy(e.records), r.now().Sub(e.fetched)
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

func (r *Resolver) fill(name string, ttl time.Duration, c *call) {
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	records, err := r.query(ctx, name)
	if err != nil {
		ttl = NegativeTTL
	}
	now := r.now()
	c.entry = entry{records: records, ok: err == nil, fetched: now, expires: now.Add(ttl)}

	r.mu.Lock()
	r.store(name, c.entry)
	delete(r.inflight, name)
	r.mu.Unlock()
	close(c.done)
}

// store must be called with r.mu held. When the cache is full it drops
// expired entries first, then arbitrary ones, until there is room.
func (r *Resolver) store(name string, e entry) {
	if _, exists := r.cache[name]; !exists && len(r.cache) >= r.maxEntries {
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
	r.cache[name] = e
}

func (r *Resolver) query(ctx context.Context, name string) ([]string, error) {
	u, err := url.Parse(r.endpoint)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("name", name)
	q.Set("type", "TXT")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: upstream status %d", name, resp.StatusCode)
	}

	var body struct {
		Status int
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		}
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&body); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if body.Status != 0 {
		return nil, fmt.Errorf("%s: rcode %d", name, body.Status)
	}
	var records []string
	for _, a := range body.Answer {
		if a.Type == typeTXT {
			records = append(records, unquoteTXT(a.Data))
		}
	}
	return records, nil
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

func dmarcPolicy(records []string) string {
	for _, rec := range records {
		tags := strings.Split(rec, ";")
		if !strings.EqualFold(strings.TrimSpace(tags[0]), "v=DMARC1") {
			continue
		}
		for _, tag := range tags[1:] {
			k, v, found := strings.Cut(tag, "=")
			if !found || strings.TrimSpace(k) != "p" {
				continue
			}
			switch p := strings.ToLower(strings.TrimSpace(v)); p {
			case "none", "quarantine", "reject":
				return p
			}
		}
	}
	return ""
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
