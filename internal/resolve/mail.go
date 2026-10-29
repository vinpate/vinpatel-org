package resolve

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"vinpatel.org/site/internal/posture"
)

// Mail is what a sending server would find out about a domain's mail
// setup. In the summary fields an empty string or false means "could not
// be confirmed". Observed tells an answer that a record is absent from a
// lookup that failed, and Lookups keeps the answers themselves.
type Mail struct {
	SPF    string        // the record's all term: "~all", "-all", "?all" or "+all"
	DKIM   string        // the selector, when its key is published
	DMARC  string        // the p= policy
	MTASTS string        // the mode of the published policy
	TLSRPT bool          // a TLS reporting record exists
	DNSSEC bool          // every answer from the domain's own zone was authenticated
	Age    time.Duration // age of the oldest answer used

	Observed posture.Observation
	Lookups  Lookups
}

// Lookups holds each query behind Mail.
type Lookups struct {
	SPF, DKIM, DMARC, MTASTS, Policy, TLSRPT Answer
}

// Answer is one query as answered: the name asked, or the URL for the
// policy; the TXT strings, or the policy body; the CNAME targets on the way;
// the resolver's authenticated-data flag; and the answer's age. A query
// that failed keeps only its name.
type Answer struct {
	Name    string
	Records []string
	CNAMEs  []string
	AD      bool
	Age     time.Duration
}

// Mail runs the six checks concurrently; each goes through the cache. With
// lookups disabled it asks nothing and returns the zero Mail.
func (r *Resolver) Mail(ctx context.Context, domain, selector string) Mail {
	if r.endpoint == "" {
		return Mail{}
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	spfName, dkimName, dmarcName := domain, selector+"._domainkey."+domain, "_dmarc."+domain
	stsName, tlsrptName := "_mta-sts."+domain, "_smtp._tls."+domain
	var spf, dkim, dmarc, sts, tlsrpt, policy *entry
	var wg sync.WaitGroup
	wg.Go(func() { spf = r.txt(ctx, spfName, MailTTL) })
	wg.Go(func() { dkim = r.txt(ctx, dkimName, MailTTL) })
	wg.Go(func() { dmarc = r.txt(ctx, dmarcName, MailTTL) })
	wg.Go(func() { sts = r.txt(ctx, stsName, MailTTL) })
	wg.Go(func() { tlsrpt = r.txt(ctx, tlsrptName, MailTTL) })
	wg.Go(func() { policy = r.fetchPolicy(ctx, domain) })
	wg.Wait()

	var m Mail
	now := r.now()
	answered, authenticated := 0, 0
	// DKIM is left out of the DNSSEC count: its selector usually points into
	// the mail provider's zone through a CNAME, and iCloud's is unsigned, so
	// its answer says nothing about this domain's DNSSEC.
	for _, e := range []*entry{spf, dmarc, sts, tlsrpt} {
		if !e.ok {
			continue
		}
		answered++
		if e.ad {
			authenticated++
		}
	}
	for _, e := range []*entry{spf, dkim, dmarc, sts, tlsrpt, policy} {
		if e.ok {
			m.Age = max(m.Age, now.Sub(e.fetched))
		}
	}
	m.DNSSEC = answered > 0 && authenticated == answered
	if spf.ok {
		m.SPF = spfAll(spf.records)
	}
	hasKey := dkimPublished(dkim.records)
	if dkim.ok && hasKey {
		m.DKIM = selector
	}
	if dmarc.ok {
		m.DMARC = dmarcPolicy(dmarc.records)
	}
	stsID := tagValue(sts.records, "v=STSv1", "id")
	mode, maxAge := stsPolicy(policy.records)
	if sts.ok && stsID != "" && policy.ok {
		m.MTASTS = mode
	}
	rua := tagValue(tlsrpt.records, "v=TLSRPTv1", "rua")
	if tlsrpt.ok {
		m.TLSRPT = rua != ""
	}

	m.Lookups = Lookups{
		SPF:    answerOf(spfName, spf, now),
		DKIM:   answerOf(dkimName, dkim, now),
		DMARC:  answerOf(dmarcName, dmarc, now),
		MTASTS: answerOf(stsName, sts, now),
		Policy: answerOf(r.policyURL(domain), policy, now),
		TLSRPT: answerOf(tlsrptName, tlsrpt, now),
	}

	spfs, dmarcs := spfRecords(spf.records), dmarcRecords(dmarc.records)
	o := posture.Observation{
		SPF:          state(spf, len(spfs) > 0),
		DKIM:         state(dkim, hasKey),
		DMARC:        state(dmarc, len(dmarcs) > 0),
		MTASTS:       state(sts, stsID != ""),
		Policy:       state(policy, true),
		TLSRPT:       state(tlsrpt, rua != ""),
		DNSSEC:       m.DNSSEC,
		SPFRecords:   len(spfs),
		SPFAll:       m.SPF,
		DMARCRecords: len(dmarcs),
		STSMode:      m.MTASTS,
		STSMaxAge:    maxAge,
		TLSRPTRUA:    rua,
	}
	if len(spfs) > 0 {
		o.SPFRecord = spfs[0]
	}
	if len(dmarcs) > 0 {
		o.DMARCP, o.DMARCSP, o.DMARCPct, o.DMARCT = dmarcTags(dmarcs[0])
	}
	m.Observed = o
	return m
}

func answerOf(name string, e *entry, now time.Time) Answer {
	a := Answer{Name: name}
	if e.ok {
		a.Records, a.CNAMEs, a.AD, a.Age = e.records, e.cnames, e.ad, now.Sub(e.fetched)
	}
	return a
}

// state reads a lookup as posture does: unknown when it failed, present
// when the answer holds the record the check looks for, absent otherwise.
// A name that does not exist and one with no such record read alike.
func state(e *entry, found bool) posture.State {
	switch {
	case !e.ok:
		return posture.Unknown
	case found:
		return posture.Present
	}
	return posture.Absent
}

// fetchPolicy reads the policy file over HTTPS, through the same cache as
// DNS. Redirects are not followed and at most maxResponseBytes are read.
func (r *Resolver) fetchPolicy(ctx context.Context, domain string) *entry {
	u := r.policyURL(domain)
	return r.get(ctx, "policy "+domain, MailTTL, func(ctx context.Context) (result, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return result{}, err
		}
		resp, err := r.policy.Do(req)
		if err != nil {
			return result{}, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return result{}, fmt.Errorf("%s: status %d", u, resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		if err != nil {
			return result{}, err
		}
		return result{records: []string{string(body)}}, nil
	})
}

// spfAll returns the all term of the SPF record, "" when there is no
// record or it ends some other way.
func spfAll(records []string) string {
	for _, rec := range spfRecords(records) {
		for _, f := range strings.Fields(rec)[1:] {
			switch f = strings.ToLower(f); f {
			case "all", "+all":
				return "+all"
			case "-all", "~all", "?all":
				return f
			}
		}
	}
	return ""
}

// spfRecords returns the SPF records among a name's TXT strings; RFC 7208
// §4.5 makes more than one an error.
func spfRecords(records []string) []string {
	var spf []string
	for _, rec := range records {
		if f := strings.Fields(rec); len(f) > 0 && strings.EqualFold(f[0], "v=spf1") {
			spf = append(spf, rec)
		}
	}
	return spf
}

// dkimPublished reports whether the selector's record carries a key. The
// v= tag is optional in RFC 6376; a non-empty p= is what matters.
func dkimPublished(records []string) bool {
	for _, rec := range records {
		for _, tag := range strings.Split(rec, ";") {
			k, v, found := strings.Cut(tag, "=")
			if found && strings.TrimSpace(k) == "p" && strings.TrimSpace(v) != "" {
				return true
			}
		}
	}
	return false
}

func dmarcPolicy(records []string) string {
	for _, rec := range dmarcRecords(records) {
		switch p, _, _, _ := dmarcTags(rec); p {
		case "none", "quarantine", "reject":
			return p
		}
	}
	return ""
}

// dmarcRecords returns the DMARC records among a name's TXT strings: those
// whose first tag is v=DMARC1. The tag name may take any case, but the
// value must match exactly or receivers ignore the record (RFC 7489 §6.3).
func dmarcRecords(records []string) []string {
	var dmarc []string
	for _, rec := range records {
		version, _, _ := strings.Cut(rec, ";")
		k, v, _ := strings.Cut(version, "=")
		if strings.EqualFold(strings.TrimSpace(k), "v") && strings.TrimSpace(v) == "DMARC1" {
			dmarc = append(dmarc, rec)
		}
	}
	return dmarc
}

// dmarcTags reads the tags that decide how fully a DMARC record applies,
// lowercased; an absent tag reads empty.
func dmarcTags(record string) (p, sp, pct, t string) {
	for _, tag := range strings.Split(record, ";")[1:] {
		k, v, found := strings.Cut(tag, "=")
		if !found {
			continue
		}
		v = strings.ToLower(strings.TrimSpace(v))
		switch strings.TrimSpace(k) {
		case "p":
			p = v
		case "sp":
			sp = v
		case "pct":
			pct = v
		case "t":
			t = v
		}
	}
	return p, sp, pct, t
}

// tagValue returns a non-empty tag from the first record that starts with
// version and carries it, the shape of both the MTA-STS and TLSRPT records.
func tagValue(records []string, version, tag string) string {
	for _, rec := range records {
		tags := strings.Split(rec, ";")
		if !strings.EqualFold(strings.TrimSpace(tags[0]), version) {
			continue
		}
		for _, t := range tags[1:] {
			k, v, found := strings.Cut(t, "=")
			if v = strings.TrimSpace(v); found && strings.TrimSpace(k) == tag && v != "" {
				return v
			}
		}
	}
	return ""
}

// stsPolicy reads the mode and max_age of a version 1 policy. Anything else
// reads as no mode, and a max_age that is not a count of seconds as zero.
func stsPolicy(records []string) (mode string, maxAge int) {
	if len(records) == 0 {
		return "", 0
	}
	var version, age string
	for line := range strings.SplitSeq(strings.ReplaceAll(records[0], "\r\n", "\n"), "\n") {
		k, v, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.TrimSpace(k) {
		case "version":
			version = strings.TrimSpace(v)
		case "mode":
			mode = strings.ToLower(strings.TrimSpace(v))
		case "max_age":
			age = strings.TrimSpace(v)
		}
	}
	if version != "STSv1" {
		return "", 0
	}
	switch mode {
	case "testing", "enforce", "none":
	default:
		mode = ""
	}
	if n, err := strconv.Atoi(age); err == nil && n >= 0 {
		maxAge = n
	}
	return mode, maxAge
}
