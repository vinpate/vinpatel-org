package resolve

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Mail is what a sending server would find out about a domain's mail
// setup. An empty string or false means "could not be confirmed", which
// the page shows by leaving that part out.
type Mail struct {
	SPF    string        // the record's all term: "~all", "-all", "?all" or "+all"
	DKIM   string        // the selector, when its key is published
	DMARC  string        // the p= policy
	MTASTS string        // the mode of the published policy
	TLSRPT bool          // a TLS reporting record exists
	DNSSEC bool          // every answer from the domain's own zone was authenticated
	Age    time.Duration // age of the oldest answer used
}

// Mail runs the six checks concurrently; each goes through the cache.
func (r *Resolver) Mail(ctx context.Context, domain, selector string) Mail {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	var spf, dkim, dmarc, sts, tlsrpt, policy entry
	var wg sync.WaitGroup
	wg.Go(func() { spf = r.txt(ctx, domain, MailTTL) })
	wg.Go(func() { dkim = r.txt(ctx, selector+"._domainkey."+domain, MailTTL) })
	wg.Go(func() { dmarc = r.txt(ctx, "_dmarc."+domain, MailTTL) })
	wg.Go(func() { sts = r.txt(ctx, "_mta-sts."+domain, MailTTL) })
	wg.Go(func() { tlsrpt = r.txt(ctx, "_smtp._tls."+domain, MailTTL) })
	wg.Go(func() { policy = r.fetchPolicy(ctx, domain) })
	wg.Wait()

	var m Mail
	now := r.now()
	answered, authenticated := 0, 0
	// DKIM is left out: its selector usually points into the mail provider's
	// zone through a CNAME, and iCloud's is unsigned, so its answer says
	// nothing about this domain's signing.
	for _, e := range []entry{spf, dmarc, sts, tlsrpt} {
		if !e.ok {
			continue
		}
		answered++
		if e.ad {
			authenticated++
		}
	}
	for _, e := range []entry{spf, dkim, dmarc, sts, tlsrpt, policy} {
		if e.ok {
			m.Age = max(m.Age, now.Sub(e.fetched))
		}
	}
	m.DNSSEC = answered > 0 && authenticated == answered
	if spf.ok {
		m.SPF = spfAll(spf.records)
	}
	if dkim.ok && dkimPublished(dkim.records) {
		m.DKIM = selector
	}
	if dmarc.ok {
		m.DMARC = dmarcPolicy(dmarc.records)
	}
	if sts.ok && tagged(sts.records, "v=STSv1", "id") && policy.ok {
		m.MTASTS = stsMode(policy.records)
	}
	if tlsrpt.ok {
		m.TLSRPT = tagged(tlsrpt.records, "v=TLSRPTv1", "rua")
	}
	return m
}

// fetchPolicy reads the policy file over HTTPS, through the same cache as
// DNS. Redirects are not followed and at most maxResponseBytes are read.
func (r *Resolver) fetchPolicy(ctx context.Context, domain string) entry {
	u := r.policyURL(domain)
	return r.get(ctx, "policy "+domain, MailTTL, func(ctx context.Context) ([]string, bool, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, false, err
		}
		resp, err := r.policy.Do(req)
		if err != nil {
			return nil, false, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, false, fmt.Errorf("%s: status %d", u, resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		if err != nil {
			return nil, false, err
		}
		return []string{string(body)}, false, nil
	})
}

// spfAll returns the all term of the SPF record, "" when there is no
// record or it ends some other way.
func spfAll(records []string) string {
	for _, rec := range records {
		fields := strings.Fields(rec)
		if len(fields) == 0 || !strings.EqualFold(fields[0], "v=spf1") {
			continue
		}
		for _, f := range fields[1:] {
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

// tagged reports whether a record starts with version and carries a
// non-empty tag, the shape of both the MTA-STS and TLSRPT records.
func tagged(records []string, version, tag string) bool {
	for _, rec := range records {
		tags := strings.Split(rec, ";")
		if !strings.EqualFold(strings.TrimSpace(tags[0]), version) {
			continue
		}
		for _, t := range tags[1:] {
			k, v, found := strings.Cut(t, "=")
			if found && strings.TrimSpace(k) == tag && strings.TrimSpace(v) != "" {
				return true
			}
		}
	}
	return false
}

// stsMode reads the mode of a version 1 policy, "" for anything else.
func stsMode(records []string) string {
	if len(records) == 0 {
		return ""
	}
	var version, mode string
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
		}
	}
	if version != "STSv1" {
		return ""
	}
	switch mode {
	case "testing", "enforce", "none":
		return mode
	}
	return ""
}
