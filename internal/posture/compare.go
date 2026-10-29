package posture

import (
	"fmt"
	"strconv"
	"strings"
)

// State is what DNS established about one record.
type State uint8

const (
	Unknown State = iota // no answer: the lookup failed or timed out, or lookups are off
	Absent               // DNS answered that there is no such record
	Present
)

func (s State) String() string {
	switch s {
	case Absent:
		return "absent"
	case Present:
		return "present"
	}
	return "unknown"
}

// Verdict is what the page may say about mail from the domain. Only the
// observed DMARC record decides it: a forgery fails both aligned SPF and
// aligned DKIM, so p=reject applied in full is what asks receivers to
// reject it, and the major providers do.
type Verdict uint8

const (
	Unconfirmed Verdict = iota // no DMARC answer: the lookup failed, or lookups are off
	Weaker                     // DNS answered, but does not ask for every forgery to be rejected
	Confirmed                  // one DMARC record asks receivers to reject, in full
)

func (v Verdict) String() string {
	switch v {
	case Weaker:
		return "weaker"
	case Confirmed:
		return "confirmed"
	}
	return "unconfirmed"
}

// Match says how an observed value compares with the declared one.
type Match uint8

const (
	NotCompared Match = iota // unknown, or no declaration for the host
	Matches
	Differs
)

// Observation is what DNS showed for a domain, filled in by the resolver.
// Present means the answer holds what the check looks for: an SPF record,
// a DKIM key, a DMARC record, an MTA-STS id, the fetched policy or a TLS
// reporting address. Any v=DMARC1 record counts, even one with a broken
// policy: receivers then act as if p=none, or skip DMARC when it names no
// report address (RFC 7489 §6.6.3), so it reads as weaker, not absent.
type Observation struct {
	SPF, DKIM, DMARC, MTASTS, Policy, TLSRPT State
	DNSSEC                                   bool // every answer from the domain's own zone was authenticated

	SPFRecords int    // v=spf1 records; RFC 7208 §4.5 makes more than one an error
	SPFRecord  string // the first of them, whole
	SPFAll     string // its all term

	// The first v=DMARC1 record's tags as published, lowercased, empty when
	// the tag is absent.
	DMARCRecords                      int
	DMARCP, DMARCSP, DMARCPct, DMARCT string

	STSMode   string // the policy's mode; empty unless the _mta-sts record and a readable policy were both found
	STSMaxAge int
	TLSRPTRUA string
}

// Check is one entry of the mail row. Observed is in the row's terms: the
// short form while it matches, the value compared once it differs.
type Check struct {
	Name     string
	State    State
	Observed string
	Declared string // empty when no declaration applies
	Match    Match
}

// Report is the comparison the page and /trace render.
type Report struct {
	Verdict                          Verdict
	Declared                         bool // a declaration describes this host
	SPF, DKIM, DMARC, MTASTS, TLSRPT Check
	DNSSEC                           State // present once any answer came from the domain's own zone
	Authenticated                    bool  // the resolver authenticated every such answer
}

// Checks returns the five checks in row order.
func (r Report) Checks() []Check { return []Check{r.SPF, r.DKIM, r.DMARC, r.MTASTS, r.TLSRPT} }

// Compare judges what DNS showed for host against the declaration. selector
// is the DKIM selector the observation was made with, so one that differs
// from the declared selector reads as a DKIM mismatch.
func Compare(d Declaration, o Observation, host, selector string) Report {
	r := Report{
		Verdict:       verdict(o),
		Declared:      d.Domain != "" && host == d.Domain,
		Authenticated: o.DNSSEC,
	}
	if o.SPF != Unknown || o.DMARC != Unknown || o.MTASTS != Unknown || o.TLSRPT != Unknown {
		r.DNSSEC = Present
	}

	spfShort, spfFull := o.SPFAll, o.SPFRecord
	if o.SPFRecords > 1 {
		spfShort = fmt.Sprintf("%d records", o.SPFRecords)
		spfFull = spfShort
	}
	r.SPF = r.check("spf", o.SPF, d.SPF,
		o.SPFRecords == 1 && normalize(o.SPFRecord) == normalize(d.SPF), spfShort, spfFull)
	r.DKIM = r.check("dkim", o.DKIM, d.DKIM.Selector, selector == d.DKIM.Selector, selector, selector)
	dmarc := dmarcText(o)
	r.DMARC = r.check("dmarc", o.DMARC, d.DMARC.P, enforced(o) && o.DMARCP == d.DMARC.P, dmarc, dmarc)
	r.MTASTS = r.check("mta-sts", stsState(o), stsText(d.MTASTS.Mode, d.MTASTS.MaxAge),
		o.STSMode == d.MTASTS.Mode && o.STSMaxAge == d.MTASTS.MaxAge, o.STSMode, stsText(o.STSMode, o.STSMaxAge))
	r.TLSRPT = r.check("tls-rpt", o.TLSRPT, d.TLSRPT.RUA, o.TLSRPTRUA == d.TLSRPT.RUA, "", o.TLSRPTRUA)
	return r
}

// check builds one entry. short is how a present value reads when it
// matches or is not compared; full is how it reads when it differs.
func (r Report) check(name string, s State, declared string, equal bool, short, full string) Check {
	c := Check{Name: name, State: s}
	if s == Present {
		c.Observed = short
	}
	if !r.Declared {
		return c
	}
	c.Declared = declared
	switch {
	case s == Unknown:
	case s == Present && equal:
		c.Match = Matches
	default:
		c.Match = Differs
		if s == Present {
			c.Observed = full
		}
	}
	return c
}

func verdict(o Observation) Verdict {
	switch {
	case o.DMARC == Unknown:
		return Unconfirmed
	case o.DMARC == Present && enforced(o) && o.DMARCP == "reject":
		return Confirmed
	}
	return Weaker
}

// enforced reports whether the DMARC record's policy applies to every
// message, as Terraform publishes it: RFC 7489 applies none when there are
// several records (§6.6.3) or sp is invalid (step 6), and only pct percent
// of messages otherwise (§6.6.4). Any t= other than n also withdraws it:
// DMARCbis reads t=y as a request not to enforce, and an unknown value is
// treated alike so that the page errs toward claiming less.
func enforced(o Observation) bool {
	return o.DMARCRecords == 1 && validSP(o.DMARCSP) && fullPct(o.DMARCPct) && !testMode(o.DMARCT)
}

func validSP(sp string) bool {
	switch sp {
	case "", "none", "quarantine", "reject":
		return true
	}
	return false
}

func fullPct(pct string) bool {
	n, err := strconv.Atoi(pct)
	return pct == "" || err == nil && n == 100
}

func testMode(t string) bool { return t != "" && t != "n" }

// stsState joins the _mta-sts record and the policy it points to. A record
// whose policy could not be fetched or read is unknown, not absent.
func stsState(o Observation) State {
	if o.MTASTS != Present {
		return o.MTASTS
	}
	if o.Policy != Present || o.STSMode == "" {
		return Unknown
	}
	return Present
}

func stsText(mode string, maxAge int) string { return fmt.Sprintf("%s max_age %d", mode, maxAge) }

// dmarcText shows the policy and every tag that keeps it from applying in
// full, as published.
func dmarcText(o Observation) string {
	if o.DMARCRecords > 1 {
		return fmt.Sprintf("%d records", o.DMARCRecords)
	}
	if o.DMARCP == "" {
		return "p missing"
	}
	s := "p=" + o.DMARCP
	if !validSP(o.DMARCSP) {
		s += " sp=" + o.DMARCSP
	}
	if !fullPct(o.DMARCPct) {
		s += " pct=" + o.DMARCPct
	}
	if testMode(o.DMARCT) {
		s += " t=" + o.DMARCT
	}
	return s
}

func normalize(record string) string {
	return strings.ToLower(strings.Join(strings.Fields(record), " "))
}
